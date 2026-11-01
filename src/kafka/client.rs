use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{mpsc, Arc};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

use rdkafka::admin::{AdminClient, AdminOptions, ConfigEntry, ResourceSpecifier};
use rdkafka::client::ClientContext;
use rdkafka::config::RDKafkaLogLevel;
use rdkafka::consumer::{BaseConsumer, Consumer, ConsumerContext};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{DeliveryResult, Headers, Message};
use rdkafka::producer::{BaseProducer, BaseRecord, ProducerContext};
use rdkafka::{ClientConfig, Offset, TopicPartitionList};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::explorer::{
    validate_send, HeaderData, PartitionDetail, RecordData, SearchFailure, SearchQuery,
    SearchWarning, SendRequest, TimestampOrder, TopicConfiguration, TopicDetail, TopicSummary,
    MAX_RECORDS_PER_PARTITION,
};
use crate::models::{
    ConnectionProfile, ProfileValidationError, SaslMechanism, SaslTransport, SecurityMode,
    TlsSettings,
};

#[derive(Debug, Error)]
pub enum KafkaConfigError {
    #[error("connection profile is invalid: {0:?}")]
    InvalidProfile(Vec<ProfileValidationError>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionFailureKind {
    Network,
    Tls,
    Authentication,
    Authorization,
    Protocol,
    Unknown,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{diagnostic}")]
pub struct ConnectionProbeError {
    pub kind: ConnectionFailureKind,
    pub diagnostic: String,
}

impl ConnectionProbeError {
    pub fn from_diagnostic(diagnostic: String) -> Self {
        let normalized = diagnostic.to_ascii_lowercase();
        let contains_any =
            |phrases: &[&str]| phrases.iter().any(|phrase| normalized.contains(phrase));
        let kind = if contains_any(&["authorization", "not authorized", "access denied"]) {
            ConnectionFailureKind::Authorization
        } else if contains_any(&[
            "tls",
            "ssl error",
            "ssl handshake",
            "ssl.ca.location",
            "ssl.key",
            "ssl.certificate",
            "certificate",
        ]) {
            ConnectionFailureKind::Tls
        } else if contains_any(&[
            "unsupported sasl mechanism",
            "unsupportedsaslmechanism",
            "unsupportedversion",
            "api version not supported",
            "protocol",
        ]) {
            ConnectionFailureKind::Protocol
        } else if contains_any(&[
            "authentication",
            "invalid username",
            "invalid password",
            "invalid credentials",
        ]) {
            ConnectionFailureKind::Authentication
        } else if contains_any(&[
            "connection refused",
            "connection timed out",
            "timed out",
            "timeout",
            "resolve",
            "transport failure",
            "brokertransportfailure",
            "all brokers down",
            "allbrokersdown",
            "network",
            "disconnected",
        ]) {
            ConnectionFailureKind::Network
        } else {
            ConnectionFailureKind::Unknown
        };
        Self { kind, diagnostic }
    }
}

pub fn build_client_config(profile: &ConnectionProfile) -> Result<ClientConfig, KafkaConfigError> {
    profile
        .validate()
        .map_err(KafkaConfigError::InvalidProfile)?;

    let mut config = ClientConfig::new();
    config.set("bootstrap.servers", &profile.bootstrap_servers);

    match &profile.security {
        SecurityMode::Plaintext => {
            config.set("security.protocol", "PLAINTEXT");
        }
        SecurityMode::Ssl { .. } => {
            config.set("security.protocol", "SSL");
        }
        SecurityMode::SaslPlain {
            transport,
            username,
            password,
        }
        | SecurityMode::SaslScramSha256 {
            transport,
            username,
            password,
        }
        | SecurityMode::SaslScramSha512 {
            transport,
            username,
            password,
        } => {
            let mechanism = match &profile.security {
                SecurityMode::SaslPlain { .. } => SaslMechanism::Plain,
                SecurityMode::SaslScramSha256 { .. } => SaslMechanism::ScramSha256,
                _ => SaslMechanism::ScramSha512,
            };
            set_sasl(
                &mut config,
                *transport,
                mechanism.as_str(),
                username,
                password.expose(),
            );
        }
    }

    if let Some(tls) = profile.tls() {
        set_tls(&mut config, &tls);
    }

    Ok(config)
}

pub fn probe_connection(profile: &ConnectionProfile) -> Result<usize, ConnectionProbeError> {
    let consumer: BaseConsumer = build_client_config(profile)
        .map_err(|error| ConnectionProbeError::from_diagnostic(error.to_string()))?
        .create()
        .map_err(|error| ConnectionProbeError::from_diagnostic(error.to_string()))?;
    let metadata = consumer
        .fetch_metadata(None, std::time::Duration::from_secs(5))
        .map_err(|error| ConnectionProbeError::from_diagnostic(error.to_string()))?;
    Ok(metadata.topics().len())
}

const KAFKA_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const PARTITION_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExplorerKafkaError {
    #[error("Operation cancelled")]
    Cancelled,
    #[error("{0}")]
    InvalidInput(&'static str),
    #[error("{operation}: {diagnostic}")]
    Kafka {
        operation: &'static str,
        diagnostic: String,
    },
    #[error("{0}: timed out")]
    Timeout(&'static str),
}

impl ExplorerKafkaError {
    fn from_kafka(operation: &'static str, error: KafkaError) -> Self {
        let code = match &error {
            KafkaError::AdminOp(code) => Some(*code),
            _ => error.rdkafka_error_code(),
        };
        match code {
            Some(
                RDKafkaErrorCode::OperationTimedOut
                | RDKafkaErrorCode::RequestTimedOut
                | RDKafkaErrorCode::MessageTimedOut
                | RDKafkaErrorCode::TimedOutQueue,
            ) => Self::Timeout(operation),
            Some(code) => Self::Kafka {
                operation,
                diagnostic: code.to_string(),
            },
            None => Self::Kafka {
                operation,
                // Raw client errors can include the supplied configuration value.
                diagnostic: match error {
                    KafkaError::ClientConfig(..) => "Invalid Kafka client configuration",
                    KafkaError::ClientCreation(_) => {
                        "Could not initialize Kafka client; check connection and TLS settings"
                    }
                    KafkaError::Canceled => "Kafka client closed before completion",
                    KafkaError::Nul(_) => "Input contains an unsupported null character",
                    _ => "Kafka operation failed without an error code",
                }
                .into(),
            },
        }
    }
}

#[derive(Default)]
pub struct SearchKafkaResult {
    pub records: Vec<RecordData>,
    pub warnings: Vec<SearchWarning>,
    pub failed_partitions: Vec<SearchFailure>,
    pub cancelled: bool,
}

impl SearchKafkaResult {
    fn append_partition(
        &mut self,
        partition: i32,
        records: Vec<RecordData>,
        status: Result<(), ExplorerKafkaError>,
    ) {
        if records.len() == MAX_RECORDS_PER_PARTITION {
            self.warnings.push(SearchWarning {
                partition,
                scanned_records: records.len(),
            });
        }
        self.records.extend(records);
        match status {
            Err(ExplorerKafkaError::Cancelled) => self.cancelled = true,
            Err(error) => self.failed_partitions.push(SearchFailure {
                partition,
                diagnostic: error.to_string(),
            }),
            Ok(()) => {}
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendDelivery {
    pub topic: String,
    pub partition: i32,
}

struct QuietContext;

impl ClientContext for QuietContext {
    fn log(&self, _: RDKafkaLogLevel, _: &str, _: &str) {}
    fn error(&self, _: KafkaError, _: &str) {}
}

impl ConsumerContext for QuietContext {}

fn check_cancel(cancel: &CancellationToken) -> Result<(), ExplorerKafkaError> {
    if cancel.is_cancelled() {
        Err(ExplorerKafkaError::Cancelled)
    } else {
        Ok(())
    }
}

fn explorer_config(profile: &ConnectionProfile) -> Result<ClientConfig, ExplorerKafkaError> {
    let mut config = build_client_config(profile)
        .map_err(|_| ExplorerKafkaError::InvalidInput("Connection profile is invalid"))?;
    config
        .set("socket.timeout.ms", "5000")
        .set("socket.connection.setup.timeout.ms", "5000")
        .set("allow.auto.create.topics", "false");
    Ok(config)
}

fn explorer_consumer(
    profile: &ConnectionProfile,
    cancel: &CancellationToken,
) -> Result<BaseConsumer<QuietContext>, ExplorerKafkaError> {
    check_cancel(cancel)?;
    let mut config = explorer_config(profile)?;
    config
        .set(
            "group.id",
            format!("kafa-explorer-{}", uuid::Uuid::new_v4()),
        )
        .set("enable.auto.commit", "false")
        .set("enable.auto.offset.store", "false")
        .set("enable.partition.eof", "true")
        .set("auto.offset.reset", "error");
    let consumer = config
        .create_with_context(QuietContext)
        .map_err(|error| ExplorerKafkaError::from_kafka("Create consumer", error))?;
    check_cancel(cancel)?;
    Ok(consumer)
}

/// Blocking adapter; callers must run this outside the Slint event loop.
pub fn load_topics(
    profile: &ConnectionProfile,
    cancel: &CancellationToken,
) -> Result<Vec<TopicSummary>, ExplorerKafkaError> {
    let consumer = explorer_consumer(profile, cancel)?;
    let metadata = consumer.fetch_metadata(None, KAFKA_TIMEOUT);
    check_cancel(cancel)?;
    let metadata =
        metadata.map_err(|error| ExplorerKafkaError::from_kafka("Load topics", error))?;
    let mut topics: Vec<_> = metadata
        .topics()
        .iter()
        .map(|topic| TopicSummary {
            name: topic.name().into(),
            partition_count: topic.partitions().len(),
        })
        .collect();
    topics.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(topics)
}

pub fn load_topic_detail(
    profile: &ConnectionProfile,
    topic: &str,
    cancel: &CancellationToken,
) -> Result<TopicDetail, ExplorerKafkaError> {
    check_cancel(cancel)?;
    validate_topic(topic)?;
    let consumer = explorer_consumer(profile, cancel)?;
    let metadata = consumer.fetch_metadata(Some(topic), KAFKA_TIMEOUT);
    check_cancel(cancel)?;
    let metadata =
        metadata.map_err(|error| ExplorerKafkaError::from_kafka("Load topic details", error))?;
    let topic_metadata = metadata
        .topics()
        .iter()
        .find(|entry| entry.name() == topic)
        .ok_or(ExplorerKafkaError::InvalidInput("Topic is unavailable"))?;
    if let Some(error) = topic_metadata.error() {
        return Err(ExplorerKafkaError::from_kafka(
            "Load topic details",
            KafkaError::MetadataFetch(error.into()),
        ));
    }
    let mut partitions = Vec::new();
    for partition in topic_metadata.partitions() {
        check_cancel(cancel)?;
        let offsets = consumer.fetch_watermarks(topic, partition.id(), KAFKA_TIMEOUT);
        check_cancel(cancel)?;
        let (low_offset, high_offset) = match offsets {
            Ok((low, high)) => (Some(low), Some(high)),
            Err(_) => (None, None),
        };
        partitions.push(PartitionDetail {
            id: partition.id(),
            leader: partition.leader(),
            replicas: partition.replicas().to_vec(),
            isr: partition.isr().to_vec(),
            low_offset,
            high_offset,
        });
    }
    partitions.sort_by_key(|partition| partition.id);
    drop(consumer);
    let (configuration, configuration_error) = match load_configuration(profile, topic, cancel) {
        Ok(configuration) => (Some(configuration), None),
        Err(ExplorerKafkaError::Cancelled) => return Err(ExplorerKafkaError::Cancelled),
        Err(error) => (None, Some(format!("Configuration unavailable: {error}"))),
    };
    check_cancel(cancel)?;
    Ok(TopicDetail {
        name: topic.into(),
        partitions,
        configuration,
        configuration_error,
    })
}

fn validate_topic(topic: &str) -> Result<(), ExplorerKafkaError> {
    if topic.is_empty() || topic.contains('\0') {
        Err(ExplorerKafkaError::InvalidInput(
            "A valid topic is required",
        ))
    } else {
        Ok(())
    }
}

fn load_configuration(
    profile: &ConnectionProfile,
    topic: &str,
    cancel: &CancellationToken,
) -> Result<TopicConfiguration, ExplorerKafkaError> {
    check_cancel(cancel)?;
    let admin: AdminClient<QuietContext> = explorer_config(profile)?
        .create_with_context(QuietContext)
        .map_err(|error| ExplorerKafkaError::from_kafka("Create admin client", error))?;
    check_cancel(cancel)?;
    let resources = [ResourceSpecifier::Topic(topic)];
    let options = AdminOptions::new().request_timeout(Some(KAFKA_TIMEOUT));
    let response = wait_for_admin(admin.describe_configs(&resources, &options), cancel)?
        .map_err(|error| ExplorerKafkaError::from_kafka("Describe configuration", error))?;
    check_cancel(cancel)?;
    let resource = response
        .into_iter()
        .next()
        .ok_or(ExplorerKafkaError::InvalidInput(
            "No configuration returned",
        ))?
        .map_err(|code| {
            ExplorerKafkaError::from_kafka("Describe configuration", KafkaError::AdminOp(code))
        })?;
    Ok(configuration_entries(resource.entries))
}

fn configuration_entries(entries: Vec<ConfigEntry>) -> TopicConfiguration {
    let mut entries: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            let value = if entry.is_sensitive {
                "[redacted]".into()
            } else {
                entry.value.unwrap_or_else(|| "(unset)".into())
            };
            (entry.name, value)
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    TopicConfiguration { entries }
}

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

fn wait_for_admin<F: Future>(
    future: F,
    cancel: &CancellationToken,
) -> Result<F::Output, ExplorerKafkaError> {
    // AdminClient owns its polling thread; no Tokio runtime is required here.
    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let deadline = Instant::now() + KAFKA_TIMEOUT;
    loop {
        check_cancel(cancel)?;
        if Instant::now() >= deadline {
            return Err(ExplorerKafkaError::Timeout("Describe configuration"));
        }
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            check_cancel(cancel)?;
            return Ok(value);
        }
        thread::park_timeout(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

pub fn search_records(
    profile: &ConnectionProfile,
    topic: &str,
    partitions: &[PartitionDetail],
    query: &SearchQuery,
    cancel: &CancellationToken,
) -> SearchKafkaResult {
    let mut result = SearchKafkaResult::default();
    let mut selected: Vec<_> = partitions
        .iter()
        .filter(|partition| {
            query
                .partition
                .is_none_or(|selected| partition.id == selected)
        })
        .cloned()
        .collect();
    selected.sort_unstable_by_key(|partition| partition.id);
    selected.dedup_by_key(|partition| partition.id);
    let prepared = (|| {
        check_cancel(cancel)?;
        validate_topic(topic)?;
        query.clone().normalize().map_err(|_| {
            ExplorerKafkaError::InvalidInput("Timestamp from must not exceed timestamp to")
        })?;
        if selected.iter().any(|partition| partition.id < 0) {
            return Err(ExplorerKafkaError::InvalidInput(
                "Partition IDs must be non-negative",
            ));
        }
        explorer_consumer(profile, cancel)
    })();
    let consumer = match prepared {
        Ok(consumer) => consumer,
        Err(ExplorerKafkaError::Cancelled) => {
            result.cancelled = true;
            return result;
        }
        Err(error) => {
            for partition in selected {
                result.failed_partitions.push(SearchFailure {
                    partition: partition.id,
                    diagnostic: error.to_string(),
                });
            }
            return result;
        }
    };
    let mut windows = BTreeMap::new();
    for partition in selected {
        if cancel.is_cancelled() {
            result.cancelled = true;
            return result;
        }
        let window = (|| {
            let Some((cached_start, end)) =
                cached_read_window(partition.low_offset, partition.high_offset, query)?
            else {
                return Ok(None);
            };
            let start = match query.timestamp_from {
                Some(timestamp) => {
                    let low = partition.low_offset.expect("validated cached offsets");
                    offset_for_timestamp(&consumer, topic, partition.id, timestamp, end, cancel)?
                        .clamp(low, end)
                        .max(cached_start)
                }
                None => cached_start,
            };
            Ok::<_, ExplorerKafkaError>((start < end).then_some((start, end)))
        })();
        match window {
            Ok(Some(window)) => {
                windows.insert(partition.id, window);
            }
            Ok(None) => {}
            Err(ExplorerKafkaError::Cancelled) => {
                result.cancelled = true;
                return result;
            }
            Err(error) => result.failed_partitions.push(SearchFailure {
                partition: partition.id,
                diagnostic: error.to_string(),
            }),
        }
    }
    if windows.is_empty() {
        result.cancelled |= cancel.is_cancelled();
        return result;
    }
    let mut assignment = TopicPartitionList::new();
    let mut assigned_windows = BTreeMap::new();
    for (&partition, &(start, _)) in &windows {
        if let Err(error) = assignment.add_partition_offset(topic, partition, Offset::Offset(start))
        {
            result.failed_partitions.push(SearchFailure {
                partition,
                diagnostic: ExplorerKafkaError::from_kafka("Set search offset", error).to_string(),
            });
        } else {
            assigned_windows.insert(partition, windows[&partition]);
        }
    }
    if assigned_windows.is_empty() {
        return result;
    }
    if let Err(error) = check_cancel(cancel).and_then(|()| {
        let assigned = consumer.assign(&assignment);
        check_cancel(cancel)?;
        assigned.map_err(|error| ExplorerKafkaError::from_kafka("Assign partitions", error))
    }) {
        if matches!(error, ExplorerKafkaError::Cancelled) {
            result.cancelled = true;
        } else {
            for &partition in assigned_windows.keys() {
                result.failed_partitions.push(SearchFailure {
                    partition,
                    diagnostic: error.to_string(),
                });
            }
        }
        return result;
    }
    let scanned =
        scan_assigned_partitions(&assigned_windows, cancel, PARTITION_READ_TIMEOUT, || {
            match consumer.poll(POLL_INTERVAL) {
                Some(Ok(message)) if message.topic() == topic => {
                    AssignedScanEvent::Record(record_data(&message))
                }
                Some(Err(KafkaError::PartitionEOF(id))) => AssignedScanEvent::Eof(id),
                Some(Err(KafkaError::MessageConsumption(code))) => message_consumption_event(code),
                Some(Err(error)) => AssignedScanEvent::Failure(ExplorerKafkaError::from_kafka(
                    "Read records",
                    error,
                )),
                _ => AssignedScanEvent::Idle,
            }
        });
    result.records.extend(scanned.records);
    result.warnings.extend(scanned.warnings);
    result.failed_partitions.extend(scanned.failed_partitions);
    result.cancelled |= scanned.cancelled;
    result
}

fn offset_for_timestamp(
    consumer: &BaseConsumer<QuietContext>,
    topic: &str,
    partition: i32,
    timestamp: i64,
    high: i64,
    cancel: &CancellationToken,
) -> Result<i64, ExplorerKafkaError> {
    check_cancel(cancel)?;
    let mut timestamps = TopicPartitionList::new();
    timestamps
        .add_partition_offset(topic, partition, Offset::Offset(timestamp.max(0)))
        .map_err(|error| ExplorerKafkaError::from_kafka("Set search timestamp", error))?;
    let offsets = consumer.offsets_for_times(timestamps, KAFKA_TIMEOUT);
    check_cancel(cancel)?;
    let offsets = offsets
        .map_err(|error| ExplorerKafkaError::from_kafka("Resolve timestamp offsets", error))?;
    let entry =
        offsets
            .find_partition(topic, partition)
            .ok_or(ExplorerKafkaError::InvalidInput(
                "Partition timestamp offset is unavailable",
            ))?;
    entry
        .error()
        .map_err(|error| ExplorerKafkaError::from_kafka("Resolve timestamp offset", error))?;
    match entry.offset() {
        Offset::Offset(offset) if offset >= 0 => Ok(offset),
        Offset::End => Ok(high),
        _ => Err(ExplorerKafkaError::InvalidInput(
            "Broker returned an invalid timestamp offset",
        )),
    }
}

fn read_window_start(low: i64, high: i64, order: TimestampOrder) -> i64 {
    match order {
        TimestampOrder::EarliestFirst => low,
        TimestampOrder::LatestFirst => {
            low.max(high.saturating_sub(MAX_RECORDS_PER_PARTITION as i64))
        }
    }
}

fn cached_read_window(
    low: Option<i64>,
    high: Option<i64>,
    query: &SearchQuery,
) -> Result<Option<(i64, i64)>, ExplorerKafkaError> {
    let low = low.ok_or(ExplorerKafkaError::InvalidInput(
        "Cached partition offsets are unavailable; refresh the topic and try again",
    ))?;
    let high = high.ok_or(ExplorerKafkaError::InvalidInput(
        "Cached partition offsets are unavailable; refresh the topic and try again",
    ))?;
    if low < 0 || high < low {
        return Err(ExplorerKafkaError::InvalidInput(
            "Cached partition offsets are invalid; refresh the topic and try again",
        ));
    }
    let start = read_window_start(low, high, query.order);
    Ok((start < high).then_some((start, high)))
}

#[cfg(test)]
fn resolve_read_window(
    low: i64,
    high: i64,
    query: &SearchQuery,
    mut timestamp_offset: impl FnMut(i64) -> Result<i64, ExplorerKafkaError>,
) -> Result<(i64, i64), ExplorerKafkaError> {
    let low = match query.timestamp_from {
        Some(timestamp) => timestamp_offset(timestamp)?.clamp(low, high),
        None => low,
    };
    // CreateTime timestamps can decrease as offsets increase. Only the high
    // watermark is a safe upper bound; the snapshot applies timestamp_to locally.
    Ok((read_window_start(low, high, query.order), high))
}

#[cfg(test)]
enum ScanEvent {
    Record(RecordData),
    End,
}

enum AssignedScanEvent {
    Record(RecordData),
    Eof(i32),
    Idle,
    RecoverableError,
    TerminalError(ExplorerKafkaError),
    Failure(ExplorerKafkaError),
}

fn message_consumption_event(code: RDKafkaErrorCode) -> AssignedScanEvent {
    match code {
        RDKafkaErrorCode::AllBrokersDown
        | RDKafkaErrorCode::BrokerTransportFailure
        | RDKafkaErrorCode::OperationTimedOut
        | RDKafkaErrorCode::RequestTimedOut => AssignedScanEvent::RecoverableError,
        _ => AssignedScanEvent::TerminalError(ExplorerKafkaError::from_kafka(
            "Read records",
            KafkaError::MessageConsumption(code),
        )),
    }
}

fn scan_assigned_partitions(
    windows: &BTreeMap<i32, (i64, i64)>,
    cancel: &CancellationToken,
    timeout: Duration,
    mut poll: impl FnMut() -> AssignedScanEvent,
) -> SearchKafkaResult {
    struct PartitionScan {
        records: Vec<RecordData>,
        finished: bool,
        failure: Option<ExplorerKafkaError>,
        deadline: Option<Instant>,
    }
    let mut scans: BTreeMap<_, _> = windows
        .keys()
        .map(|&partition| {
            (
                partition,
                PartitionScan {
                    records: Vec::new(),
                    finished: false,
                    failure: None,
                    deadline: None,
                },
            )
        })
        .collect();
    let mut result = SearchKafkaResult::default();
    let unseen_deadline = Instant::now() + timeout;
    // Consumption errors lose their partition ID in rdkafka. Retain a terminal
    // error until healthy partitions finish and attribution becomes unambiguous.
    let mut pending_terminal_error = None;
    while scans.values().any(|scan| !scan.finished) {
        if cancel.is_cancelled() {
            result.cancelled = true;
            break;
        }
        let now = Instant::now();
        for scan in scans.values_mut().filter(|scan| !scan.finished) {
            if now >= scan.deadline.unwrap_or(unseen_deadline) {
                scan.failure = Some(
                    pending_terminal_error
                        .clone()
                        .unwrap_or(ExplorerKafkaError::Timeout("Read records")),
                );
                scan.finished = true;
            }
        }
        if scans.values().all(|scan| scan.finished) {
            break;
        }
        let event = poll();
        if cancel.is_cancelled() {
            result.cancelled = true;
            break;
        }
        match event {
            AssignedScanEvent::Record(record) => {
                if let (Some(&(start, end)), Some(scan)) = (
                    windows.get(&record.partition),
                    scans.get_mut(&record.partition),
                ) {
                    if !scan.finished {
                        scan.deadline
                            .get_or_insert_with(|| Instant::now() + timeout);
                        if record.offset >= end {
                            scan.finished = true;
                        } else if record.offset >= start {
                            let reached_end = record.offset >= end - 1;
                            scan.records.push(record);
                            scan.finished =
                                reached_end || scan.records.len() >= MAX_RECORDS_PER_PARTITION;
                        }
                    }
                }
            }
            AssignedScanEvent::Eof(partition) => {
                if let Some(scan) = scans.get_mut(&partition) {
                    scan.finished = true;
                }
            }
            AssignedScanEvent::TerminalError(error) => {
                if scans.values().filter(|scan| !scan.finished).count() == 1 {
                    if let Some(scan) = scans.values_mut().find(|scan| !scan.finished) {
                        scan.failure = Some(error);
                        scan.finished = true;
                    }
                } else {
                    pending_terminal_error = Some(error);
                }
            }
            AssignedScanEvent::Failure(error) => {
                for scan in scans.values_mut().filter(|scan| !scan.finished) {
                    scan.failure = Some(error.clone());
                    scan.finished = true;
                }
            }
            AssignedScanEvent::Idle | AssignedScanEvent::RecoverableError => {}
        }
        if pending_terminal_error.is_some()
            && scans.values().filter(|scan| !scan.finished).count() == 1
        {
            let error = pending_terminal_error.take().expect("checked above");
            if let Some(scan) = scans.values_mut().find(|scan| !scan.finished) {
                scan.failure = Some(error);
                scan.finished = true;
            }
        }
    }
    for (partition, scan) in scans {
        result.append_partition(partition, scan.records, scan.failure.map_or(Ok(()), Err));
    }
    result
}

#[cfg(test)]
fn scan_partition(
    records: &mut Vec<RecordData>,
    cancel: &CancellationToken,
    timeout: Duration,
    mut poll: impl FnMut() -> Result<ScanEvent, ExplorerKafkaError>,
) -> Result<(), ExplorerKafkaError> {
    let deadline = Instant::now() + timeout;
    while records.len() < MAX_RECORDS_PER_PARTITION {
        check_cancel(cancel)?;
        if Instant::now() >= deadline {
            return Err(ExplorerKafkaError::Timeout("Read records"));
        }
        let event = poll();
        check_cancel(cancel)?;
        match event? {
            ScanEvent::Record(record) => records.push(record),
            ScanEvent::End => return Ok(()),
        }
    }
    Ok(())
}

fn record_data(message: &impl Message) -> RecordData {
    RecordData {
        partition: message.partition(),
        offset: message.offset(),
        timestamp: message.timestamp().to_millis(),
        key: message
            .key()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
        value: String::from_utf8_lossy(message.payload().unwrap_or_default()).into_owned(),
        headers: message
            .headers()
            .map(|headers| {
                headers
                    .iter()
                    .map(|header| HeaderData {
                        name: header.key.into(),
                        value: header
                            .value
                            .map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn producer_record_for(request: &SendRequest) -> BaseRecord<'_, [u8], [u8]> {
    let mut record = BaseRecord::to(&request.topic).payload(request.value.as_bytes());
    if let Some(key) = request.key.as_deref() {
        record = record.key(key.as_bytes());
    }
    if let Some(partition) = request.partition {
        record = record.partition(partition);
    }
    record
}

struct DeliveryContext(mpsc::Sender<Result<i32, ExplorerKafkaError>>);

impl ClientContext for DeliveryContext {
    fn log(&self, _: RDKafkaLogLevel, _: &str, _: &str) {}
    fn error(&self, _: KafkaError, _: &str) {}
}

impl ProducerContext for DeliveryContext {
    type DeliveryOpaque = ();

    fn delivery(&self, result: &DeliveryResult<'_>, _: ()) {
        let status = match result {
            Ok(message) => Ok(message.partition()),
            Err((error, _)) => Err(ExplorerKafkaError::from_kafka(
                "Deliver record",
                error.clone(),
            )),
        };
        let _ = self.0.send(status);
    }
}

pub fn send_record(
    profile: &ConnectionProfile,
    request: &SendRequest,
    cancel: &CancellationToken,
) -> Result<SendDelivery, ExplorerKafkaError> {
    check_cancel(cancel)?;
    validate_topic(&request.topic)?;
    validate_send(request)
        .map_err(|_| ExplorerKafkaError::InvalidInput("Message value is required"))?;
    if request.partition.is_some_and(|partition| partition < 0) {
        return Err(ExplorerKafkaError::InvalidInput(
            "Partition IDs must be non-negative",
        ));
    }
    let (sender, receiver) = mpsc::channel();
    let mut config = explorer_config(profile)?;
    config.set("message.timeout.ms", "10000");
    let producer: BaseProducer<DeliveryContext> = config
        .create_with_context(DeliveryContext(sender))
        .map_err(|error| ExplorerKafkaError::from_kafka("Create producer", error))?;
    check_cancel(cancel)?;
    producer
        .send(producer_record_for(request))
        .map_err(|(error, _)| ExplorerKafkaError::from_kafka("Queue record", error))?;
    check_cancel(cancel)?;
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        check_cancel(cancel)?;
        if let Ok(status) = receiver.try_recv() {
            return status.map(|partition| SendDelivery {
                topic: request.topic.clone(),
                partition,
            });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ExplorerKafkaError::Timeout("Deliver record"));
        }
        producer.poll(POLL_INTERVAL.min(remaining));
        check_cancel(cancel)?;
    }
}

fn set_tls(config: &mut ClientConfig, tls: &TlsSettings) {
    config.set("ssl.ca.location", &tls.ca_path);
    if let Some(path) = tls
        .certificate_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    {
        config.set("ssl.certificate.location", path);
    }
    if let Some(path) = tls
        .private_key_path
        .as_deref()
        .filter(|path| !path.trim().is_empty())
    {
        config.set("ssl.key.location", path);
    }
    if !tls.private_key_password.expose().is_empty() {
        config.set("ssl.key.password", tls.private_key_password.expose());
    }
}

fn set_sasl(
    config: &mut ClientConfig,
    transport: SaslTransport,
    mechanism: &str,
    username: &str,
    password: &str,
) {
    config.set(
        "security.protocol",
        match transport {
            SaslTransport::Plaintext => "SASL_PLAINTEXT",
            SaslTransport::Ssl => "SASL_SSL",
        },
    );
    config.set("sasl.mechanisms", mechanism);
    config.set("sasl.username", username);
    config.set("sasl.password", password);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdkafka::error::KafkaError;
    use rdkafka::message::{Header, OwnedHeaders, OwnedMessage, Timestamp};
    use tokio_util::sync::CancellationToken;

    use crate::explorer::{PartitionDetail, RecordData, SearchQuery, SendRequest, TimestampOrder};
    use crate::models::{ConnectionProfile, SaslMechanism, SaslTransport, Secret, TlsSettings};

    use super::{
        build_client_config, cached_read_window, load_topic_detail, load_topics, probe_connection,
        producer_record_for, read_window_start, record_data, scan_partition, search_records,
        send_record, ConnectionFailureKind, ConnectionProbeError, ExplorerKafkaError, ScanEvent,
    };

    fn send_request(partition: Option<i32>) -> SendRequest {
        SendRequest {
            topic: "orders".into(),
            partition,
            key: Some("key\u{00e9}".into()),
            value: " value\u{00e9} ".into(),
        }
    }

    fn partition(id: i32, low_offset: Option<i64>, high_offset: Option<i64>) -> PartitionDetail {
        PartitionDetail {
            id,
            leader: 0,
            replicas: vec![],
            isr: vec![],
            low_offset,
            high_offset,
        }
    }

    #[test]
    fn cached_window_skips_empty_partitions_without_a_watermark_request() {
        assert_eq!(
            cached_read_window(Some(7), Some(7), &SearchQuery::default()).unwrap(),
            None
        );
    }

    #[test]
    fn automatic_send_does_not_set_a_partition() {
        let request = send_request(None);
        let record = producer_record_for(&request);
        assert_eq!(record.partition, None);
        assert_eq!(record.topic, "orders");
        assert_eq!(record.key, Some(&b"key\xc3\xa9"[..]));
        assert_eq!(record.payload, Some(&b" value\xc3\xa9 "[..]));
        assert_eq!(request.value, " value\u{00e9} ");
    }

    #[test]
    fn fixed_send_uses_the_selected_partition() {
        let request = send_request(Some(3));
        assert_eq!(producer_record_for(&request).partition, Some(3));
    }

    #[test]
    fn absent_and_empty_keys_remain_distinct() {
        let mut request = send_request(None);
        request.key = None;
        assert_eq!(producer_record_for(&request).key, None);
        request.key = Some(String::new());
        assert_eq!(producer_record_for(&request).key, Some(&b""[..]));
    }

    #[test]
    fn cancelled_operations_do_not_create_clients() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let profile = ConnectionProfile::plaintext("");
        assert!(matches!(
            load_topics(&profile, &cancel),
            Err(ExplorerKafkaError::Cancelled)
        ));
        assert!(matches!(
            load_topic_detail(&profile, "orders", &cancel),
            Err(ExplorerKafkaError::Cancelled)
        ));
        assert!(matches!(
            send_record(&profile, &send_request(None), &cancel),
            Err(ExplorerKafkaError::Cancelled)
        ));
        let result = search_records(
            &profile,
            "orders",
            &[
                partition(0, Some(0), Some(1)),
                partition(1, Some(0), Some(1)),
            ],
            &SearchQuery::default(),
            &cancel,
        );
        assert!(result.cancelled);
        assert!(result.records.is_empty());
        assert!(result.failed_partitions.is_empty());
    }

    #[test]
    fn invalid_search_fails_each_selected_partition_without_kafka_io() {
        let query = SearchQuery {
            timestamp_from: Some(20),
            timestamp_to: Some(10),
            ..SearchQuery::default()
        };
        let result = search_records(
            &ConnectionProfile::plaintext(""),
            "orders",
            &[
                partition(2, Some(0), Some(1)),
                partition(0, Some(0), Some(1)),
                partition(2, Some(0), Some(1)),
            ],
            &query,
            &CancellationToken::new(),
        );
        let failed: Vec<_> = result
            .failed_partitions
            .iter()
            .map(|failure| failure.partition)
            .collect();
        assert_eq!(failed, [0, 2]);
        assert!(result.records.is_empty());
        assert!(!result.cancelled);
    }

    #[test]
    fn invalid_send_is_rejected_before_creating_a_client() {
        let mut request = send_request(None);
        request.value = " \r\n ".into();
        assert!(matches!(
            send_record(
                &ConnectionProfile::plaintext(""),
                &request,
                &CancellationToken::new(),
            ),
            Err(ExplorerKafkaError::InvalidInput(_))
        ));
    }

    #[test]
    fn diagnostic_does_not_copy_arbitrary_client_error_text() {
        let error = ExplorerKafkaError::from_kafka(
            "create consumer",
            KafkaError::ClientCreation("sensitive fixture text".into()),
        );
        assert!(!error.to_string().contains("sensitive fixture text"));
        assert!(error.to_string().contains("create consumer"));
    }

    #[test]
    fn latest_reads_start_from_the_newest_bounded_offset_window() {
        assert_eq!(
            read_window_start(2, 30_000, TimestampOrder::LatestFirst),
            20_000
        );
        assert_eq!(
            read_window_start(25_000, 30_000, TimestampOrder::LatestFirst),
            25_000
        );
        assert_eq!(
            read_window_start(2, 30_000, TimestampOrder::EarliestFirst),
            2
        );
    }

    #[test]
    fn upper_timestamp_bound_keeps_later_out_of_order_matches_reachable() {
        let broker_records = [
            RecordData {
                timestamp: Some(300),
                ..scan_record(0)
            },
            RecordData {
                timestamp: Some(200),
                ..scan_record(1)
            },
        ];
        for order in [TimestampOrder::EarliestFirst, TimestampOrder::LatestFirst] {
            let query = SearchQuery {
                timestamp_from: Some(100),
                timestamp_to: Some(250),
                order,
                ..SearchQuery::default()
            };
            let (start, end) = super::resolve_read_window(0, 2, &query, |timestamp| {
                Ok(broker_records
                    .iter()
                    .find(|record| record.timestamp.is_some_and(|value| value >= timestamp))
                    .map_or(2, |record| record.offset))
            })
            .unwrap();
            let mut source = broker_records
                .iter()
                .filter(|record| record.offset >= start && record.offset < end)
                .cloned();
            let mut records = Vec::new();
            scan_partition(
                &mut records,
                &CancellationToken::new(),
                Duration::from_secs(60),
                || Ok(source.next().map_or(ScanEvent::End, ScanEvent::Record)),
            )
            .unwrap();
            assert_eq!(records.len(), 2);
            let snapshot = crate::explorer::filter_and_page(records, query).unwrap();
            let offsets: Vec<_> = snapshot
                .records
                .iter()
                .map(|record| record.offset)
                .collect();
            assert_eq!(offsets, [1]);
        }
    }

    fn scan_record(offset: i64) -> RecordData {
        RecordData {
            partition: 4,
            offset,
            timestamp: None,
            key: None,
            value: "value".into(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn assigned_scan_collects_interleaved_partitions_in_one_poll_stream() {
        use std::collections::BTreeMap;

        let windows = BTreeMap::from([(0, (0, 1)), (1, (0, 2))]);
        let events = [
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 0,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(1)
            }),
        ];
        let mut events = events.into_iter();
        let result = super::scan_assigned_partitions(
            &windows,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || events.next().unwrap_or(super::AssignedScanEvent::Idle),
        );
        let found: Vec<_> = result
            .records
            .iter()
            .map(|record| (record.partition, record.offset))
            .collect();
        assert_eq!(found, [(0, 0), (1, 0), (1, 1)]);
        assert!(result.failed_partitions.is_empty());
    }

    #[test]
    fn assigned_scan_keeps_other_partitions_after_one_reaches_eof() {
        use std::collections::BTreeMap;

        let windows = BTreeMap::from([(0, (0, 2)), (1, (0, 2))]);
        let events = [
            super::AssignedScanEvent::Record(RecordData {
                partition: 0,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Eof(0),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(1)
            }),
        ];
        let mut events = events.into_iter();
        let result = super::scan_assigned_partitions(
            &windows,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || events.next().unwrap_or(super::AssignedScanEvent::Idle),
        );
        let found: Vec<_> = result
            .records
            .iter()
            .map(|record| (record.partition, record.offset))
            .collect();
        assert_eq!(found, [(0, 0), (1, 0), (1, 1)]);
        assert!(result.failed_partitions.is_empty());
    }

    #[test]
    fn assigned_scan_gives_later_partition_a_fresh_timeout() {
        use std::collections::BTreeMap;

        let mut polls: i32 = 0;
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 1)), (1, (0, 2))]),
            &CancellationToken::new(),
            Duration::from_millis(100),
            || {
                polls += 1;
                if polls == 1 {
                    std::thread::sleep(Duration::from_millis(50));
                } else if polls == 3 {
                    std::thread::sleep(Duration::from_millis(70));
                }
                super::AssignedScanEvent::Record(RecordData {
                    partition: i32::from(polls > 1),
                    ..scan_record(i64::from((polls - 2).max(0)))
                })
            },
        );
        let found: Vec<_> = result
            .records
            .iter()
            .map(|record| (record.partition, record.offset))
            .collect();
        assert_eq!(found, [(0, 0), (1, 0), (1, 1)]);
        assert!(result.failed_partitions.is_empty());
    }

    #[test]
    fn assigned_scan_times_out_all_silent_partitions_on_one_shared_deadline() {
        use std::collections::BTreeMap;

        let mut polls = 0;
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 1)), (1, (0, 1)), (2, (0, 1))]),
            &CancellationToken::new(),
            Duration::from_millis(20),
            || {
                polls += 1;
                std::thread::sleep(Duration::from_millis(30));
                super::AssignedScanEvent::Idle
            },
        );

        assert_eq!(polls, 1);
        assert_eq!(result.failed_partitions.len(), 3);
        assert!(result
            .failed_partitions
            .iter()
            .all(|failure| failure.diagnostic.contains("timed out")));
    }

    #[test]
    fn assigned_scan_respects_each_fixed_window_and_record_cap() {
        use std::collections::BTreeMap;

        let windows = BTreeMap::from([(0, (3, 20_000)), (1, (0, 1))]);
        let mut polled = 0;
        let result = super::scan_assigned_partitions(
            &windows,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || {
                let offset = polled;
                polled += 1;
                if offset == 0 {
                    super::AssignedScanEvent::Record(RecordData {
                        partition: 1,
                        ..scan_record(0)
                    })
                } else {
                    super::AssignedScanEvent::Record(RecordData {
                        partition: 0,
                        ..scan_record(offset - 1)
                    })
                }
            },
        );
        assert_eq!(polled, 10_004);
        assert_eq!(result.records.len(), 10_001);
        assert_eq!(result.records[0].offset, 3);
        assert_eq!(result.records[9_999].offset, 10_002);
        assert_eq!(result.records[10_000].partition, 1);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].partition, 0);
    }

    #[test]
    fn assigned_scan_drops_a_poll_result_when_cancelled() {
        use std::collections::BTreeMap;

        let cancel = CancellationToken::new();
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 2))]),
            &cancel,
            Duration::from_secs(60),
            || {
                cancel.cancel();
                super::AssignedScanEvent::Record(RecordData {
                    partition: 0,
                    ..scan_record(0)
                })
            },
        );
        assert!(result.cancelled);
        assert!(result.records.is_empty());
    }

    #[test]
    fn assigned_scan_keeps_completed_partition_when_poll_fails() {
        use std::collections::BTreeMap;

        let events = [
            super::AssignedScanEvent::Record(RecordData {
                partition: 0,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Failure(ExplorerKafkaError::Timeout("Read records")),
        ];
        let mut events = events.into_iter();
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 1)), (1, (0, 2))]),
            &CancellationToken::new(),
            Duration::from_secs(60),
            || events.next().unwrap_or(super::AssignedScanEvent::Idle),
        );
        let found: Vec<_> = result
            .records
            .iter()
            .map(|record| (record.partition, record.offset))
            .collect();
        assert_eq!(found, [(0, 0), (1, 0)]);
        assert_eq!(result.failed_partitions.len(), 1);
        assert_eq!(result.failed_partitions[0].partition, 1);
    }

    #[test]
    fn recoverable_poll_error_does_not_stop_healthy_partitions() {
        use std::collections::BTreeMap;

        let events = [
            super::message_consumption_event(rdkafka::error::RDKafkaErrorCode::OperationTimedOut),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 0,
                ..scan_record(0)
            }),
            super::AssignedScanEvent::Record(RecordData {
                partition: 1,
                ..scan_record(1)
            }),
        ];
        let mut events = events.into_iter();
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 1)), (1, (0, 2))]),
            &CancellationToken::new(),
            Duration::from_secs(60),
            || events.next().unwrap_or(super::AssignedScanEvent::Idle),
        );
        let found: Vec<_> = result
            .records
            .iter()
            .map(|record| (record.partition, record.offset))
            .collect();
        assert_eq!(found, [(0, 0), (1, 0), (1, 1)]);
        assert!(result.failed_partitions.is_empty());
    }

    #[test]
    fn recoverable_poll_error_times_out_only_the_unfinished_partition() {
        use std::collections::BTreeMap;

        let mut polls = 0;
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 2)), (1, (0, 1))]),
            &CancellationToken::new(),
            Duration::from_millis(100),
            || {
                polls += 1;
                match polls {
                    1 => super::AssignedScanEvent::RecoverableError,
                    2 => super::AssignedScanEvent::Record(RecordData {
                        partition: 1,
                        ..scan_record(0)
                    }),
                    _ => {
                        std::thread::sleep(Duration::from_millis(120));
                        super::AssignedScanEvent::Idle
                    }
                }
            },
        );
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].partition, 1);
        assert_eq!(result.failed_partitions.len(), 1);
        assert_eq!(result.failed_partitions[0].partition, 0);
        assert!(result.failed_partitions[0].diagnostic.contains("timed out"));
    }

    #[test]
    fn terminal_consumption_error_is_attributed_to_the_only_unfinished_partition() {
        use std::collections::BTreeMap;

        let events = [
            super::message_consumption_event(rdkafka::error::RDKafkaErrorCode::OffsetOutOfRange),
            super::AssignedScanEvent::Eof(1),
        ];
        let mut events = events.into_iter();
        let result = super::scan_assigned_partitions(
            &BTreeMap::from([(0, (0, 1)), (1, (0, 1))]),
            &CancellationToken::new(),
            Duration::from_secs(60),
            || events.next().unwrap_or(super::AssignedScanEvent::Idle),
        );

        assert_eq!(result.failed_partitions.len(), 1);
        assert_eq!(result.failed_partitions[0].partition, 0);
        assert!(result.failed_partitions[0]
            .diagnostic
            .contains("Offset out of range"));
        assert!(!result.failed_partitions[0].diagnostic.contains("timed out"));
    }

    #[test]
    fn partition_scan_stops_at_exactly_ten_thousand_records() {
        let mut polled = 0;
        let mut records = Vec::new();
        let result = scan_partition(
            &mut records,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || {
                let event = ScanEvent::Record(scan_record(polled));
                polled += 1;
                Ok(event)
            },
        );
        assert!(result.is_ok());
        assert_eq!(polled, 10_000);
        assert_eq!(records.len(), 10_000);
        assert_eq!(records.last().unwrap().offset, 9_999);
    }

    #[test]
    fn partition_scan_preserves_records_before_a_failure() {
        let mut polled = 0;
        let mut records = Vec::new();
        let result = scan_partition(
            &mut records,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || {
                polled += 1;
                if polled == 1 {
                    Ok(ScanEvent::Record(scan_record(7)))
                } else {
                    Err(ExplorerKafkaError::Timeout("read records"))
                }
            },
        );
        assert!(matches!(result, Err(ExplorerKafkaError::Timeout(_))));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 7);
    }

    #[test]
    fn cancellation_after_poll_drops_that_poll_result() {
        let cancel = CancellationToken::new();
        let mut records = Vec::new();
        let result = scan_partition(&mut records, &cancel, Duration::from_secs(60), || {
            cancel.cancel();
            Ok(ScanEvent::Record(scan_record(7)))
        });
        assert!(matches!(result, Err(ExplorerKafkaError::Cancelled)));
        assert!(records.is_empty());
    }

    #[test]
    fn partition_scan_has_a_finite_deadline() {
        let mut records = Vec::new();
        let result = scan_partition(
            &mut records,
            &CancellationToken::new(),
            Duration::ZERO,
            || panic!("expired scan must not poll"),
        );
        assert!(matches!(result, Err(ExplorerKafkaError::Timeout(_))));
    }

    #[test]
    fn completed_partition_does_not_poll_again() {
        let mut polls = 0;
        let mut records = Vec::new();
        let result = scan_partition(
            &mut records,
            &CancellationToken::new(),
            Duration::from_secs(60),
            || {
                polls += 1;
                Ok(ScanEvent::End)
            },
        );
        assert!(result.is_ok());
        assert_eq!(polls, 1);
        assert!(records.is_empty());
    }

    #[test]
    fn warnings_identify_only_partitions_that_reach_the_scan_cap() {
        let mut result = super::SearchKafkaResult::default();
        result.append_partition(0, (0..10_000).map(scan_record).collect(), Ok(()));
        result.append_partition(
            1,
            vec![scan_record(5)],
            Err(ExplorerKafkaError::Timeout("read records")),
        );
        result.append_partition(2, Vec::new(), Ok(()));
        assert_eq!(result.records.len(), 10_001);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].partition, 0);
        assert_eq!(result.warnings[0].scanned_records, 10_000);
        assert_eq!(result.failed_partitions.len(), 1);
        assert_eq!(result.failed_partitions[0].partition, 1);
    }

    #[test]
    fn admin_future_can_complete_without_a_tokio_runtime() {
        assert_eq!(
            super::wait_for_admin(std::future::ready(17), &CancellationToken::new()).unwrap(),
            17
        );
    }

    #[test]
    fn admin_wait_observes_cancellation_before_polling() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = super::wait_for_admin(std::future::pending::<()>(), &cancel);
        assert!(matches!(result, Err(ExplorerKafkaError::Cancelled)));
    }

    #[test]
    fn topic_configuration_hides_sensitive_values_and_sorts_keys() {
        use rdkafka::admin::{ConfigEntry, ConfigSource};
        let entry = |name: &str, value: &str, sensitive| ConfigEntry {
            name: name.into(),
            value: Some(value.into()),
            source: ConfigSource::DynamicTopic,
            is_read_only: false,
            is_default: false,
            is_sensitive: sensitive,
        };
        let configuration = super::configuration_entries(vec![
            entry("z", "sensitive fixture", true),
            entry("a", "visible", false),
        ]);
        assert_eq!(
            configuration.entries,
            [
                ("a".to_owned(), "visible".to_owned()),
                ("z".to_owned(), "[redacted]".to_owned()),
            ]
        );
    }

    #[test]
    fn kafka_timeout_codes_remain_distinct_from_other_errors() {
        use rdkafka::error::RDKafkaErrorCode;
        let error = ExplorerKafkaError::from_kafka(
            "deliver record",
            KafkaError::MessageProduction(RDKafkaErrorCode::MessageTimedOut),
        );
        assert!(matches!(
            error,
            ExplorerKafkaError::Timeout("deliver record")
        ));
    }

    #[test]
    fn admin_errors_retain_authorization_and_unsupported_diagnostics() {
        use rdkafka::error::RDKafkaErrorCode;
        for (code, expected) in [
            (
                RDKafkaErrorCode::TopicAuthorizationFailed,
                "TopicAuthorizationFailed (Broker: Topic authorization failed)",
            ),
            (
                RDKafkaErrorCode::UnsupportedVersion,
                "UnsupportedVersion (Broker: API version not supported)",
            ),
        ] {
            let error =
                ExplorerKafkaError::from_kafka("Describe configuration", KafkaError::AdminOp(code));
            assert_eq!(
                error,
                ExplorerKafkaError::Kafka {
                    operation: "Describe configuration",
                    diagnostic: expected.into(),
                }
            );
        }
    }

    #[test]
    fn admin_timeout_codes_remain_typed_timeouts() {
        use rdkafka::error::RDKafkaErrorCode;
        for code in [
            RDKafkaErrorCode::OperationTimedOut,
            RDKafkaErrorCode::RequestTimedOut,
        ] {
            let error =
                ExplorerKafkaError::from_kafka("Describe configuration", KafkaError::AdminOp(code));
            assert!(matches!(
                error,
                ExplorerKafkaError::Timeout("Describe configuration")
            ));
        }
    }

    #[test]
    fn record_conversion_retains_headers_metadata_and_missing_key() {
        let headers = OwnedHeaders::new()
            .insert(Header {
                key: "trace",
                value: Some("abc"),
            })
            .insert(Header::<&str> {
                key: "empty",
                value: None,
            });
        let message = OwnedMessage::new(
            Some(b"payload".to_vec()),
            None,
            "orders".into(),
            Timestamp::CreateTime(123),
            4,
            42,
            Some(headers),
        );
        let record = record_data(&message);
        assert_eq!(record.partition, 4);
        assert_eq!(record.offset, 42);
        assert_eq!(record.timestamp, Some(123));
        assert_eq!(record.key, None);
        assert_eq!(record.value, "payload");
        assert_eq!(record.headers.len(), 2);
        assert_eq!(record.headers[0].name, "trace");
        assert_eq!(record.headers[0].value.as_deref(), Some("abc"));
        assert_eq!(record.headers[1].value, None);
    }

    #[test]
    fn classifies_probe_diagnostics_without_changing_copyable_text() {
        for (diagnostic, expected) in [
            (
                "Connect to broker failed: Connection refused",
                ConnectionFailureKind::Network,
            ),
            (
                "Failed to resolve broker: Name or service not known",
                ConnectionFailureKind::Network,
            ),
            (
                "BrokerTransportFailure (Local: Broker transport failure)",
                ConnectionFailureKind::Network,
            ),
            (
                "SASL_SSL broker: connection timed out",
                ConnectionFailureKind::Network,
            ),
            (
                "SSL handshake failed: certificate verify failed",
                ConnectionFailureKind::Tls,
            ),
            (
                "ssl.ca.location failed: cannot load CA",
                ConnectionFailureKind::Tls,
            ),
            ("SSL (Local: SSL error)", ConnectionFailureKind::Tls),
            (
                "SaslAuthenticationFailed (Broker: SASL Authentication failed)",
                ConnectionFailureKind::Authentication,
            ),
            (
                "Invalid username or password",
                ConnectionFailureKind::Authentication,
            ),
            (
                "TopicAuthorizationFailed (Broker: Topic authorization failed)",
                ConnectionFailureKind::Authorization,
            ),
            (
                "Cluster authorization failed",
                ConnectionFailureKind::Authorization,
            ),
            (
                "UnsupportedSaslMechanism (Broker: Unsupported SASL mechanism)",
                ConnectionFailureKind::Protocol,
            ),
            (
                "UnsupportedVersion (Broker: API version not supported)",
                ConnectionFailureKind::Protocol,
            ),
            (
                "Unexpected response while negotiating protocol",
                ConnectionFailureKind::Protocol,
            ),
            (
                "  Unrecognized broker failure\r\nDiagnostic: Ω  ",
                ConnectionFailureKind::Unknown,
            ),
        ] {
            let error = ConnectionProbeError::from_diagnostic(diagnostic.to_owned());

            assert_eq!(error.kind, expected, "{diagnostic}");
            assert_eq!(error.diagnostic, diagnostic);
            assert_eq!(error.to_string(), diagnostic);
            assert_eq!(error.clone().diagnostic, diagnostic);
        }
    }

    #[test]
    fn probe_classification_is_case_insensitive() {
        let error = ConnectionProbeError::from_diagnostic("cErTiFiCaTe VeRiFy FaIlEd".into());

        assert_eq!(error.kind, ConnectionFailureKind::Tls);
        assert_eq!(error.diagnostic, "cErTiFiCaTe VeRiFy FaIlEd");
    }

    #[test]
    fn invalid_profile_probe_returns_typed_error_before_kafka_io() {
        let profile = ConnectionProfile::plaintext("");
        let error: ConnectionProbeError = probe_connection(&profile).expect_err("invalid profile");

        assert_eq!(error.kind, ConnectionFailureKind::Unknown);
        assert_eq!(
            error.diagnostic,
            "connection profile is invalid: [MissingBootstrapServers]"
        );
    }

    #[test]
    fn maps_scram_to_sasl_ssl_client_options() {
        let mut profile = ConnectionProfile::scram_sha256("broker:9093", "alice", "secret");
        profile.tls = Some(TlsSettings::with_ca("ca.pem"));
        let config = build_client_config(&profile).expect("valid SCRAM profile");

        assert_eq!(config.get("security.protocol"), Some("SASL_SSL"));
        assert_eq!(config.get("sasl.mechanisms"), Some("SCRAM-SHA-256"));
        assert_eq!(config.get("ssl.ca.location"), Some("ca.pem"));
    }

    #[test]
    fn maps_sasl_plain_ssl_with_client_tls_options() {
        assert_sasl_ssl_tls_mapping(SaslMechanism::Plain, "PLAIN");
    }

    #[test]
    fn maps_scram_sha256_ssl_with_client_tls_options() {
        assert_sasl_ssl_tls_mapping(SaslMechanism::ScramSha256, "SCRAM-SHA-256");
    }

    #[test]
    fn maps_scram_sha512_ssl_with_client_tls_options() {
        assert_sasl_ssl_tls_mapping(SaslMechanism::ScramSha512, "SCRAM-SHA-512");
    }

    fn assert_sasl_ssl_tls_mapping(mechanism: SaslMechanism, expected: &str) {
        let profile = ConnectionProfile::sasl(
            "broker:9093",
            SaslTransport::Ssl,
            mechanism,
            "alice",
            "fixture-password",
            TlsSettings {
                ca_path: "ca.pem".into(),
                certificate_path: Some("client.pem".into()),
                private_key_path: Some("client.key".into()),
                private_key_password: Secret::new("fixture-key-password"),
            },
        );
        let config = build_client_config(&profile).expect("valid SASL SSL profile");

        assert_eq!(config.get("bootstrap.servers"), Some("broker:9093"));
        assert_eq!(config.get("security.protocol"), Some("SASL_SSL"));
        assert_eq!(config.get("sasl.mechanisms"), Some(expected));
        assert_eq!(config.get("sasl.username"), Some("alice"));
        assert_eq!(config.get("sasl.password"), Some("fixture-password"));
        assert_eq!(config.get("ssl.ca.location"), Some("ca.pem"), "{expected}");
        assert_eq!(config.get("ssl.certificate.location"), Some("client.pem"));
        assert_eq!(config.get("ssl.key.location"), Some("client.key"));
        assert_eq!(config.get("ssl.key.password"), Some("fixture-key-password"));
    }

    #[test]
    fn sasl_ssl_omits_empty_optional_tls_options() {
        let profile = ConnectionProfile::sasl(
            "broker:9093",
            SaslTransport::Ssl,
            SaslMechanism::Plain,
            "alice",
            "fixture-password",
            TlsSettings {
                ca_path: "ca.pem".into(),
                certificate_path: Some("  ".into()),
                private_key_path: Some("".into()),
                private_key_password: Secret::default(),
            },
        );
        let config = build_client_config(&profile).expect("valid CA-only profile");

        assert_eq!(config.get("ssl.ca.location"), Some("ca.pem"));
        assert_eq!(config.get("ssl.certificate.location"), None);
        assert_eq!(config.get("ssl.key.location"), None);
        assert_eq!(config.get("ssl.key.password"), None);
    }

    #[test]
    fn ssl_maps_legacy_tls_fields_instead_of_sasl_tls_settings() {
        let mut profile = ConnectionProfile::ssl(
            "broker:9093",
            TlsSettings {
                ca_path: "ca.pem".into(),
                certificate_path: Some("client.pem".into()),
                private_key_path: Some("client.key".into()),
                private_key_password: Secret::new("fixture-key-password"),
            },
        );
        profile.tls = Some(TlsSettings::with_ca("unused.pem"));
        let config = build_client_config(&profile).expect("valid SSL profile");

        assert_eq!(config.get("security.protocol"), Some("SSL"));
        assert_eq!(config.get("ssl.ca.location"), Some("ca.pem"));
        assert_eq!(config.get("ssl.certificate.location"), Some("client.pem"));
        assert_eq!(config.get("ssl.key.location"), Some("client.key"));
        assert_eq!(config.get("ssl.key.password"), Some("fixture-key-password"));
        assert_eq!(config.get("sasl.mechanisms"), None);
    }

    #[test]
    fn all_sasl_plaintext_mechanisms_ignore_tls_settings() {
        for (mechanism, expected) in [
            (SaslMechanism::Plain, "PLAIN"),
            (SaslMechanism::ScramSha256, "SCRAM-SHA-256"),
            (SaslMechanism::ScramSha512, "SCRAM-SHA-512"),
        ] {
            let profile = ConnectionProfile::sasl(
                "broker:9092",
                SaslTransport::Plaintext,
                mechanism,
                "alice",
                "fixture-password",
                TlsSettings::with_ca("unused.pem"),
            );
            let config = build_client_config(&profile).expect("valid SASL plaintext profile");

            assert_eq!(config.get("security.protocol"), Some("SASL_PLAINTEXT"));
            assert_eq!(config.get("sasl.mechanisms"), Some(expected));
            assert_eq!(config.get("sasl.username"), Some("alice"));
            assert_eq!(config.get("sasl.password"), Some("fixture-password"));
            assert_eq!(config.get("ssl.ca.location"), None);
            assert_eq!(config.get("ssl.certificate.location"), None);
            assert_eq!(config.get("ssl.key.location"), None);
            assert_eq!(config.get("ssl.key.password"), None);
        }
    }

    #[test]
    fn maps_scram_sha512_to_selected_plaintext_transport() {
        let profile =
            ConnectionProfile::scram_sha512_plaintext("localhost:9093", "admin", "secret");
        let config = build_client_config(&profile).expect("valid SCRAM profile");

        assert_eq!(config.get("security.protocol"), Some("SASL_PLAINTEXT"));
        assert_eq!(config.get("sasl.mechanisms"), Some("SCRAM-SHA-512"));
    }
}
