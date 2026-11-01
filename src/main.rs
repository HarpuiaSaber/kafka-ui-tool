#![cfg_attr(windows, windows_subsystem = "windows")]

slint::include_modules!();

#[cfg(windows)]
mod connection_controller;
mod explorer;
mod kafka;
mod models;
#[cfg(windows)]
mod profile_bundle;
#[cfg(windows)]
mod profile_store;

use std::sync::Arc;

#[cfg(windows)]
use slint::ComponentHandle;

use models::{ConnectionProfile, SaslMechanism, SaslTransport, Secret, SecurityMode, TlsSettings};

struct ConnectionForm {
    id: String,
    name: String,
    bootstrap_servers: String,
    security_mode: String,
    sasl_transport: String,
    sasl_mechanism: String,
    username: String,
    password: Secret,
    tls: TlsSettings,
}

impl Default for ConnectionForm {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            bootstrap_servers: "localhost:9092".into(),
            security_mode: "PLAINTEXT".into(),
            sasl_transport: "SASL_PLAINTEXT".into(),
            sasl_mechanism: "SCRAM-SHA-512".into(),
            username: String::new(),
            password: Secret::default(),
            tls: TlsSettings::default(),
        }
    }
}

impl ConnectionForm {
    fn from_profile(profile: &ConnectionProfile) -> Self {
        let mut form = Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            bootstrap_servers: profile.bootstrap_servers.clone(),
            tls: profile.tls().unwrap_or_default(),
            ..Self::default()
        };
        match &profile.security {
            SecurityMode::Plaintext => {}
            SecurityMode::Ssl { .. } => form.security_mode = "SSL".into(),
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
                form.security_mode = "SASL".into();
                form.sasl_transport = match transport {
                    SaslTransport::Plaintext => "SASL_PLAINTEXT",
                    SaslTransport::Ssl => "SASL_SSL",
                }
                .into();
                form.sasl_mechanism = match &profile.security {
                    SecurityMode::SaslPlain { .. } => "PLAIN",
                    SecurityMode::SaslScramSha256 { .. } => "SCRAM-SHA-256",
                    _ => "SCRAM-SHA-512",
                }
                .into();
                form.username = username.clone();
                form.password = password.clone();
            }
        }
        form
    }

    fn into_profile(self) -> ConnectionProfile {
        let mut profile = match self.security_mode.as_str() {
            "SSL" => ConnectionProfile::ssl(self.bootstrap_servers, self.tls),
            "SASL" => {
                let transport = if self.sasl_transport == "SASL_SSL" {
                    SaslTransport::Ssl
                } else {
                    SaslTransport::Plaintext
                };
                let mechanism = match self.sasl_mechanism.as_str() {
                    "PLAIN" => SaslMechanism::Plain,
                    "SCRAM-SHA-256" => SaslMechanism::ScramSha256,
                    _ => SaslMechanism::ScramSha512,
                };
                ConnectionProfile::sasl(
                    self.bootstrap_servers,
                    transport,
                    mechanism,
                    self.username,
                    self.password.expose(),
                    if transport == SaslTransport::Ssl {
                        self.tls
                    } else {
                        TlsSettings::default()
                    },
                )
            }
            _ => ConnectionProfile::plaintext(self.bootstrap_servers),
        };
        if !self.id.is_empty() {
            profile.id = self.id;
        }
        profile.name = self.name;
        profile
    }

    fn read(window: &MainWindow) -> Self {
        let optional_path =
            |path: slint::SharedString| (!path.trim().is_empty()).then(|| path.to_string());
        Self {
            id: window.get_draft_profile_id().to_string(),
            name: window.get_connection_name().to_string(),
            bootstrap_servers: window.get_bootstrap_servers().to_string(),
            security_mode: window.get_security_mode().to_string(),
            sasl_transport: window.get_sasl_transport().to_string(),
            sasl_mechanism: window.get_sasl_mechanism().to_string(),
            username: window.get_username().to_string(),
            password: Secret::new(window.get_password().to_string()),
            tls: TlsSettings {
                ca_path: window.get_ca_path().to_string(),
                certificate_path: optional_path(window.get_certificate_path()),
                private_key_path: optional_path(window.get_key_path()),
                private_key_password: Secret::new(window.get_key_password().to_string()),
            },
        }
    }

    fn write(self, window: &MainWindow) {
        window.set_draft_profile_id(self.id.into());
        window.set_connection_name(self.name.into());
        window.set_bootstrap_servers(self.bootstrap_servers.into());
        window.set_security_mode(self.security_mode.into());
        window.set_sasl_transport(self.sasl_transport.into());
        window.set_sasl_mechanism(self.sasl_mechanism.into());
        window.set_username(self.username.into());
        window.set_password(self.password.expose().into());
        window.set_ca_path(self.tls.ca_path.into());
        window.set_certificate_path(self.tls.certificate_path.unwrap_or_default().into());
        window.set_key_path(self.tls.private_key_path.unwrap_or_default().into());
        window.set_key_password(self.tls.private_key_password.expose().into());
    }
}

struct SearchForm {
    partition: String,
    page_size: String,
    key_contains: String,
    value_contains: String,
    case_sensitive: bool,
    timestamp_from: String,
    timestamp_to: String,
    order: String,
    timestamp_presence: String,
}

impl Default for SearchForm {
    fn default() -> Self {
        Self::from_query(&explorer::SearchQuery::default())
    }
}

#[derive(Default)]
struct SearchFormErrors {
    partition: String,
    page_size: String,
    timestamp_from: String,
    timestamp_to: String,
}

impl SearchFormErrors {
    fn is_empty(&self) -> bool {
        self.partition.is_empty()
            && self.page_size.is_empty()
            && self.timestamp_from.is_empty()
            && self.timestamp_to.is_empty()
    }

    fn write(self, window: &MainWindow) {
        window.set_search_partition_error(self.partition.into());
        window.set_search_page_size_error(self.page_size.into());
        window.set_search_timestamp_from_error(self.timestamp_from.into());
        window.set_search_timestamp_to_error(self.timestamp_to.into());
    }
}

struct SearchInput {
    query: explorer::SearchQuery,
    errors: SearchFormErrors,
}

impl SearchForm {
    fn from_query(query: &explorer::SearchQuery) -> Self {
        Self {
            partition: query
                .partition
                .map(|id| id.to_string())
                .unwrap_or_else(|| "All partitions".into()),
            page_size: query.page_size.to_string(),
            key_contains: query.key_contains.clone(),
            value_contains: query.value_contains.clone(),
            case_sensitive: query.case_sensitive,
            timestamp_from: query
                .timestamp_from
                .map(|value| value.to_string())
                .unwrap_or_default(),
            timestamp_to: query
                .timestamp_to
                .map(|value| value.to_string())
                .unwrap_or_default(),
            order: match query.order {
                explorer::TimestampOrder::LatestFirst => "Latest first",
                explorer::TimestampOrder::EarliestFirst => "Earliest first",
            }
            .into(),
            timestamp_presence: match query.timestamp_presence {
                explorer::TimestampPresence::All => "All",
                explorer::TimestampPresence::HasTimestamp => "Has timestamp",
                explorer::TimestampPresence::NoTimestamp => "No timestamp",
            }
            .into(),
        }
    }

    fn read(window: &MainWindow) -> Self {
        Self {
            partition: window.get_search_partition().to_string(),
            page_size: window.get_search_page_size().to_string(),
            key_contains: window.get_search_key_contains().to_string(),
            value_contains: window.get_search_value_contains().to_string(),
            case_sensitive: window.get_search_case_sensitive(),
            timestamp_from: window.get_search_timestamp_from().to_string(),
            timestamp_to: window.get_search_timestamp_to().to_string(),
            order: window.get_search_order().to_string(),
            timestamp_presence: window.get_search_timestamp_presence().to_string(),
        }
    }

    fn write(self, window: &MainWindow) {
        window.set_search_partition(self.partition.into());
        window.set_search_page_size(self.page_size.into());
        window.set_search_key_contains(self.key_contains.into());
        window.set_search_value_contains(self.value_contains.into());
        window.set_search_case_sensitive(self.case_sensitive);
        window.set_search_timestamp_from(self.timestamp_from.into());
        window.set_search_timestamp_to(self.timestamp_to.into());
        window.set_search_order(self.order.into());
        window.set_search_timestamp_presence(self.timestamp_presence.into());
    }

    fn parse(self, partitions: &[i32]) -> SearchInput {
        let mut errors = SearchFormErrors::default();
        let partition = parse_partition(&self.partition, "All partitions", partitions)
            .unwrap_or_else(|error| {
                errors.partition = error;
                None
            });
        let page_size = match self.page_size.trim().parse::<usize>() {
            Ok(value) if (1..=1_000).contains(&value) => value,
            _ => {
                errors.page_size = "Enter a whole number from 1 to 1000.".into();
                20
            }
        };
        let timestamp_from = parse_timestamp(&self.timestamp_from, &mut errors.timestamp_from);
        let timestamp_to = parse_timestamp(&self.timestamp_to, &mut errors.timestamp_to);
        if matches!((timestamp_from, timestamp_to), (Some(from), Some(to)) if from > to) {
            errors.timestamp_from = "From must be at or before To.".into();
            errors.timestamp_to = "To must be at or after From.".into();
        }
        SearchInput {
            query: explorer::SearchQuery {
                partition,
                page_size,
                key_contains: self.key_contains,
                value_contains: self.value_contains,
                case_sensitive: self.case_sensitive,
                timestamp_from,
                timestamp_to,
                order: if self.order == "Earliest first" {
                    explorer::TimestampOrder::EarliestFirst
                } else {
                    explorer::TimestampOrder::LatestFirst
                },
                timestamp_presence: match self.timestamp_presence.as_str() {
                    "Has timestamp" => explorer::TimestampPresence::HasTimestamp,
                    "No timestamp" => explorer::TimestampPresence::NoTimestamp,
                    _ => explorer::TimestampPresence::All,
                },
            },
            errors,
        }
    }
}

fn parse_partition(text: &str, automatic: &str, partitions: &[i32]) -> Result<Option<i32>, String> {
    let text = text.trim();
    if text == automatic {
        return Ok(None);
    }
    match text.parse::<i32>() {
        Ok(partition) if partition >= 0 && partitions.contains(&partition) => Ok(Some(partition)),
        _ => Err("Choose an available partition.".into()),
    }
}

fn parse_timestamp(text: &str, error: &mut String) -> Option<i64> {
    if text.trim().is_empty() {
        return None;
    }
    let text = text.trim();
    if let Ok(value) = text.parse() {
        return Some(value);
    }
    if let Some(value) = parse_iso_8601_timestamp(text) {
        return Some(value);
    }

    *error = "Enter Unix milliseconds or ISO 8601 with an offset, or leave blank.".into();
    None
}

fn parse_iso_8601_timestamp(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }

    let year = parse_decimal(&bytes[0..4])?;
    let month = parse_decimal(&bytes[5..7])?;
    let day = parse_decimal(&bytes[8..10])?;
    let hour = parse_decimal(&bytes[11..13])?;
    let minute = parse_decimal(&bytes[14..16])?;
    let second = parse_decimal(&bytes[17..19])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let mut position = 19;
    let mut milliseconds = 0_i64;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let fraction_start = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        let fraction = &bytes[fraction_start..position];
        if fraction.is_empty() {
            return None;
        }
        milliseconds = parse_decimal(&fraction[..fraction.len().min(3)])?;
        for _ in fraction.len().min(3)..3 {
            milliseconds *= 10;
        }
    }

    let offset_minutes = match bytes.get(position) {
        Some(b'Z') if position + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-'))
            if position + 6 == bytes.len() && bytes.get(position + 3) == Some(&b':') =>
        {
            let offset_hour = parse_decimal(&bytes[position + 1..position + 3])?;
            let offset_minute = parse_decimal(&bytes[position + 4..position + 6])?;
            if offset_hour > 23 || offset_minute > 59 {
                return None;
            }
            let offset = offset_hour.checked_mul(60)?.checked_add(offset_minute)?;
            if *sign == b'-' {
                -offset
            } else {
                offset
            }
        }
        _ => return None,
    };

    civil_days_since_epoch(year, month, day)?
        .checked_mul(86_400_000)?
        .checked_add(hour.checked_mul(3_600_000)?)?
        .checked_add(minute.checked_mul(60_000)?)?
        .checked_add(second.checked_mul(1_000)?)?
        .checked_add(milliseconds)?
        .checked_sub(offset_minutes.checked_mul(60_000)?)
}

fn parse_decimal(text: &[u8]) -> Option<i64> {
    text.iter().try_fold(0_i64, |value, digit| {
        digit
            .is_ascii_digit()
            .then(|| value.checked_mul(10)?.checked_add(i64::from(digit - b'0')))?
    })
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn civil_days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    let adjusted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year.checked_sub(era.checked_mul(400)?)?;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn topic_rows(topics: &[explorer::TopicSummary], filter: &str) -> Vec<TopicRow> {
    explorer::topic_filter(topics, filter)
        .into_iter()
        .map(|topic| TopicRow {
            preview_wide: topic.name.chars().count() > 27,
            name: topic.name.into(),
            partition_count: topic.partition_count.to_string().into(),
        })
        .collect()
}

fn message_preview_limit() -> usize {
    60
}

fn table_preview(text: &str, limit: usize) -> String {
    let preview = explorer::preview_text(text, limit);
    let mut single_line = String::with_capacity(preview.len());

    for character in preview.chars() {
        match character {
            '\r' => single_line.push_str("\\r"),
            '\n' => single_line.push_str("\\n"),
            '\t' => single_line.push_str("\\t"),
            _ => single_line.push(character),
        }
    }

    single_line
}

fn locked_window_size(work_width: u32, work_height: u32) -> (u32, u32) {
    (
        work_width.saturating_sub(48).clamp(880, 1_100),
        work_height.saturating_sub(56).clamp(620, 1_040),
    )
}

#[derive(Clone, Copy)]
enum TimestampDisplay {
    UnixMilliseconds,
    Iso8601,
}

fn message_row(
    record: &explorer::RecordData,
    preview_limit: usize,
    timestamp_display: TimestampDisplay,
) -> MessageRow {
    MessageRow {
        partition: record.partition.to_string().into(),
        offset: record.offset.to_string().into(),
        timestamp: timestamp_text(record.timestamp, timestamp_display).into(),
        key_preview: record
            .key
            .as_deref()
            .map(|key| table_preview(key, 20))
            .unwrap_or_else(|| "(no key)".into())
            .into(),
        value_preview: table_preview(&record.value, preview_limit).into(),
    }
}

fn timestamp_text(timestamp: Option<i64>, display: TimestampDisplay) -> String {
    timestamp
        .map(|value| match display {
            TimestampDisplay::UnixMilliseconds => value.to_string(),
            TimestampDisplay::Iso8601 => iso_8601_timestamp(value),
        })
        .unwrap_or_else(|| "No timestamp".into())
}

fn iso_8601_timestamp(timestamp_ms: i64) -> String {
    let days = timestamp_ms.div_euclid(86_400_000);
    let time = timestamp_ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_date_from_days(days);
    let hour = time / 3_600_000;
    let minute = (time % 3_600_000) / 60_000;
    let second = (time % 60_000) / 1_000;
    let milliseconds = time % 1_000;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z")
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[derive(Default)]
struct RecordDetailView {
    partition: String,
    offset: String,
    timestamp: String,
    key: String,
    value: String,
    key_line_numbers: String,
    value_line_numbers: String,
    headers: Vec<HeaderRow>,
}

fn record_detail(
    record: &explorer::RecordData,
    timestamp_display: TimestampDisplay,
) -> RecordDetailView {
    let key = record.key.clone().unwrap_or_else(|| "(no key)".into());
    let value = record.value.clone();
    RecordDetailView {
        partition: record.partition.to_string(),
        offset: record.offset.to_string(),
        timestamp: timestamp_text(record.timestamp, timestamp_display),
        key_line_numbers: line_numbers(&key),
        value_line_numbers: line_numbers(&value),
        key,
        value,
        headers: record
            .headers
            .iter()
            .map(|header| HeaderRow {
                name: header.name.clone().into(),
                value: header.value.as_deref().unwrap_or("(null)").into(),
                line_numbers: line_numbers(header.value.as_deref().unwrap_or("(null)")).into(),
            })
            .collect(),
    }
}

fn line_numbers(value: &str) -> String {
    (1..=value.matches('\n').count() + 1)
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(windows)]
fn update_send_line_numbers(window: &MainWindow) {
    window.set_send_key_line_numbers(line_numbers(window.get_send_key().as_str()).into());
    window.set_send_value_line_numbers(line_numbers(window.get_send_value().as_str()).into());
}

fn json_beauty(value: &str) -> String {
    serde_json::from_str::<serde_json::Value>(value)
        .and_then(|json| serde_json::to_string_pretty(&json))
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(windows)]
fn ui_model<T: Clone + 'static>(rows: Vec<T>) -> slint::ModelRc<T> {
    std::rc::Rc::new(slint::VecModel::from(rows)).into()
}

#[cfg(windows)]
fn ui_count(count: usize) -> i32 {
    count.min(i32::MAX as usize) as i32
}

#[cfg(windows)]
fn elapsed_text(elapsed_ms: u64) -> slint::SharedString {
    format!("{}.{:01}s", elapsed_ms / 1_000, (elapsed_ms % 1_000) / 100).into()
}

#[cfg(windows)]
fn delivery_notice_text(notice: &connection_controller::DeliveryNotice) -> String {
    let requested = notice
        .requested_partition
        .map(|id| format!("partition {id}"))
        .unwrap_or_else(|| "Automatic".into());
    if notice.success {
        let actual = notice
            .delivered_partition
            .map(|id| format!(", delivered to partition {id}"))
            .unwrap_or_default();
        format!("Sent to {} ({requested}{actual}).", notice.topic)
    } else {
        format!(
            "Send failed for {} ({requested}): {}",
            notice.topic,
            notice.diagnostic.as_deref().unwrap_or("Delivery failed")
        )
    }
}

#[cfg(windows)]
fn update_explorer_snapshot(window: &MainWindow, state: &connection_controller::ExplorerSnapshot) {
    let session_id = state
        .session_id
        .map(|id| id.to_string())
        .unwrap_or_default();
    let selected_topic = state.selected_topic.as_deref().unwrap_or_default();
    let session_changed = window.get_explorer_session_id() != session_id.as_str();
    let topic_changed = window.get_selected_topic() != selected_topic;
    // Elapsed notifications must not replace partially typed form fields.
    if session_changed || topic_changed {
        SearchForm::from_query(&state.search_query).write(window);
        SearchFormErrors::default().write(window);
    }
    if session_changed {
        window.set_topic_filter(state.topic_filter.clone().into());
    }
    window.set_explorer_session_id(session_id.into());
    window.set_selected_topic(selected_topic.into());
    window.set_topic_unavailable(state.topic_unavailable);
    let topics = topic_rows(&state.topics, &state.topic_filter);
    window.set_topic_total_count(ui_count(state.topics.len()));
    window.set_topic_filtered_count(ui_count(topics.len()));
    window.set_topics(ui_model(topics));
    window.set_topics_refreshing(state.refreshing);
    window.set_topics_elapsed(elapsed_text(state.refresh_elapsed_ms));
    window.set_topics_error(state.topic_error.as_deref().unwrap_or_default().into());
    window.set_metadata_pending(state.metadata_pending);
    window.set_metadata_elapsed(elapsed_text(state.metadata_elapsed_ms));
    window.set_detail_error(state.detail_error.as_deref().unwrap_or_default().into());

    let partitions = state
        .detail
        .as_ref()
        .map(|detail| detail.partitions.as_slice())
        .unwrap_or_default();
    window.set_detail_ready(
        !partitions.is_empty() && !state.metadata_pending && !state.topic_unavailable,
    );
    window.set_topic_partition_count(ui_count(partitions.len()));
    let ids = |values: &[i32]| {
        values
            .iter()
            .map(i32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    window.set_partitions(ui_model(
        partitions
            .iter()
            .map(|partition| PartitionRow {
                id: partition.id.to_string().into(),
                leader: if partition.leader < 0 {
                    "Unavailable".into()
                } else {
                    partition.leader.to_string().into()
                },
                replicas: ids(&partition.replicas).into(),
                isr: ids(&partition.isr).into(),
                low_offset: partition
                    .low_offset
                    .map(|offset| offset.to_string())
                    .unwrap_or_else(|| "Unavailable".into())
                    .into(),
                high_offset: partition
                    .high_offset
                    .map(|offset| offset.to_string())
                    .unwrap_or_else(|| "Unavailable".into())
                    .into(),
            })
            .collect(),
    ));
    let info_partition_choices = partitions
        .iter()
        .map(|partition| slint::SharedString::from(partition.id.to_string()))
        .collect::<Vec<_>>();
    let info_partition_count = i32::try_from(info_partition_choices.len()).unwrap_or(i32::MAX);
    let info_partition_index = window.get_info_partition_index();
    if topic_changed || info_partition_index < 0 || info_partition_index >= info_partition_count {
        window.set_info_partition_index(if info_partition_choices.is_empty() {
            -1
        } else {
            0
        });
    }
    window.set_info_partition_choices(ui_model(info_partition_choices));
    let choices = |first: &str| {
        std::iter::once(slint::SharedString::from(first))
            .chain(
                partitions
                    .iter()
                    .map(|partition| partition.id.to_string().into()),
            )
            .collect()
    };
    window.set_search_partition_choices(ui_model(choices("All partitions")));
    window.set_send_partition_choices(ui_model(choices("Automatic")));
    let configuration = state
        .detail
        .as_ref()
        .and_then(|detail| detail.configuration.as_ref());
    window.set_configuration_available(configuration.is_some());
    window.set_configuration(ui_model(
        configuration
            .map(|configuration| {
                configuration
                    .entries
                    .iter()
                    .map(|(name, value)| ConfigurationRow {
                        name: name.as_str().into(),
                        value: value.as_str().into(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    ));
    window.set_configuration_error(
        state
            .detail
            .as_ref()
            .and_then(|detail| detail.configuration_error.as_deref())
            .unwrap_or_default()
            .into(),
    );

    window.set_search_pending(state.search_pending);
    window.set_search_elapsed(elapsed_text(state.search_elapsed_ms));
    window.set_search_error(state.search_error.as_deref().unwrap_or_default().into());
    window.set_search_has_results(state.search.is_some());
    let preview_limit = message_preview_limit();
    let timestamp_display = if window.get_message_timestamps_as_iso() {
        TimestampDisplay::Iso8601
    } else {
        TimestampDisplay::UnixMilliseconds
    };
    window.set_messages(ui_model(
        state
            .page()
            .iter()
            .map(|record| message_row(record, preview_limit, timestamp_display))
            .collect(),
    ));
    window.set_search_result_count(ui_count(
        state
            .search
            .as_ref()
            .map_or(0, |search| search.records.len()),
    ));
    let warnings = state
        .search
        .as_ref()
        .map(|search| {
            search
                .warnings
                .iter()
                .map(|warning| {
                    format!(
                        "Partition {}: scanned {} records; scan limit reached, results may be incomplete.",
                        warning.partition, warning.scanned_records
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    let failures = state
        .search
        .as_ref()
        .map(|search| {
            search
                .failures
                .iter()
                .map(|failure| format!("Partition {}: {}", failure.partition, failure.diagnostic))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    window.set_search_warnings(warnings.into());
    window.set_search_failures(failures.into());
    let page_count = state.page_count();
    window.set_page_number(if page_count == 0 {
        0
    } else {
        ui_count(state.page_index + 1)
    });
    window.set_page_count(ui_count(page_count));
    window.set_previous_page_enabled(state.page_index > 0 && !state.search_pending);
    window.set_next_page_enabled(
        state.page_index.saturating_add(1) < page_count && !state.search_pending,
    );
    let selected_row = state
        .search
        .as_ref()
        .and_then(|search| {
            state.selected_record_index?.checked_sub(
                state
                    .page_index
                    .saturating_mul(search.query.page_size.clamp(1, 1_000)),
            )
        })
        .filter(|row| *row < state.page().len());
    window.set_selected_message_row(selected_row.map(ui_count).unwrap_or(-1));
    window.set_record_selected(state.selected_record().is_some());
    let record = state
        .selected_record()
        .map(|record| record_detail(record, timestamp_display))
        .unwrap_or_default();
    window.set_record_partition(record.partition.into());
    window.set_record_offset(record.offset.into());
    window.set_record_timestamp(record.timestamp.into());
    window.set_record_key(record.key.into());
    window.set_record_value(record.value.into());
    window.set_record_key_line_numbers(record.key_line_numbers.into());
    window.set_record_value_line_numbers(record.value_line_numbers.into());
    window.set_record_header_count(ui_count(record.headers.len()));
    window.set_record_headers(ui_model(record.headers));

    let opening_dialog = state.send_draft.is_some() && !window.get_send_dialog_open();
    if opening_dialog || session_changed || topic_changed || state.send_draft.is_none() {
        window.set_send_topic(
            state
                .send_draft
                .as_ref()
                .map(|draft| draft.topic.as_str())
                .unwrap_or_default()
                .into(),
        );
        window.set_send_partition(
            state
                .send_draft
                .as_ref()
                .and_then(|draft| draft.partition)
                .map(|id| id.to_string())
                .unwrap_or_else(|| "Automatic".into())
                .into(),
        );
        window.set_send_key(
            state
                .send_draft
                .as_ref()
                .and_then(|draft| draft.key.as_deref())
                .unwrap_or_default()
                .into(),
        );
        window.set_send_value(
            state
                .send_draft
                .as_ref()
                .map(|draft| draft.value.as_str())
                .unwrap_or_default()
                .into(),
        );
        window.set_send_partition_error("".into());
    }
    update_send_line_numbers(window);
    window.set_send_dialog_open(state.send_draft.is_some());
    window.set_send_value_error(
        state
            .send_validation_error
            .as_deref()
            .unwrap_or_default()
            .into(),
    );
    window.set_delivery_pending(state.delivery_pending);
    window.set_delivery_elapsed(elapsed_text(state.delivery_elapsed_ms));
    window.set_delivery_notice(
        state
            .delivery_notice
            .as_ref()
            .map(delivery_notice_text)
            .unwrap_or_default()
            .into(),
    );
    window.set_delivery_success(
        state
            .delivery_notice
            .as_ref()
            .is_some_and(|notice| notice.success),
    );
}

#[cfg(windows)]
fn apply_search_form(
    window: &MainWindow,
    controller: &connection_controller::ConnectionController,
    submit: bool,
) {
    let state = controller.snapshot();
    let partitions: Vec<_> = state
        .explorer
        .detail
        .as_ref()
        .map(|detail| {
            detail
                .partitions
                .iter()
                .map(|partition| partition.id)
                .collect()
        })
        .unwrap_or_default();
    let input = SearchForm::read(window).parse(&partitions);
    if submit && input.errors.is_empty() {
        controller.search_messages(input.query);
    } else {
        // Even malformed edits must cancel old work and discard its result snapshot.
        controller.search_form_changed(input.query);
    }
    input.errors.write(window);
}

#[cfg(windows)]
fn apply_send_form(
    window: &MainWindow,
    controller: &connection_controller::ConnectionController,
) -> bool {
    update_send_line_numbers(window);
    let state = controller.snapshot();
    let partitions: Vec<_> = state
        .explorer
        .detail
        .as_ref()
        .map(|detail| {
            detail
                .partitions
                .iter()
                .map(|partition| partition.id)
                .collect()
        })
        .unwrap_or_default();
    match parse_partition(
        window.get_send_partition().as_str(),
        "Automatic",
        &partitions,
    ) {
        Ok(partition) => {
            let key = window.get_send_key().to_string();
            controller.update_send_form(
                partition,
                (!key.is_empty()).then_some(key),
                window.get_send_value().to_string(),
            );
            window.set_send_partition_error("".into());
            true
        }
        Err(error) => {
            window.set_send_partition_error(error.into());
            false
        }
    }
}

fn main() -> Result<(), slint::PlatformError> {
    let window = MainWindow::new()?;
    let runtime = Arc::new(tokio::runtime::Runtime::new().expect("Tokio runtime"));
    #[cfg(windows)]
    let _controller = bind_controller(&window, runtime.handle().clone());
    #[cfg(windows)]
    schedule_window_lock(&window);
    #[cfg(not(windows))]
    {
        window.set_operation_pending(true);
        window.set_status_text("Connection management requires Windows.".into());
    }

    window.run()
}

#[cfg(windows)]
fn schedule_window_lock(window: &MainWindow) {
    use std::time::Duration;
    use windows_sys::Win32::{
        Foundation::RECT,
        UI::WindowsAndMessaging::{SystemParametersInfoW, SPI_GETWORKAREA},
    };

    let weak = window.as_weak();
    slint::Timer::single_shot(Duration::from_millis(1), move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        let current_size = window.window().size();
        let mut work_area = RECT::default();
        let work_area_loaded = unsafe {
            SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut work_area as *mut RECT).cast(), 0) != 0
        };
        let (work_width, work_height) = if work_area_loaded {
            (
                (work_area.right - work_area.left).max(0) as u32,
                (work_area.bottom - work_area.top).max(0) as u32,
            )
        } else {
            (current_size.width, current_size.height)
        };
        let (width, height) = locked_window_size(work_width, work_height);
        let scale_factor = window.window().scale_factor();
        let logical_width = width as f32 / scale_factor;
        let logical_height = height as f32 / scale_factor;
        window.set_locked_window_width(logical_width);
        window.set_locked_window_height(logical_height);
        window
            .window()
            .set_size(slint::PhysicalSize::new(width, height));
    });
}

#[cfg(windows)]
fn update_snapshot(window: &MainWindow, state: &connection_controller::ControllerSnapshot) {
    use connection_controller::{OperationStatus, Route};
    use models::ProfileValidationError as Validation;

    let route = match state.operation.route {
        Route::Manager => "manager",
        Route::Workspace => "workspace",
    };
    window.set_route(route.into());
    window.set_operation_pending(
        state.operation.status != OperationStatus::Idle || state.pending_storage != 0,
    );
    window.set_operation_state(
        match state.operation.status {
            OperationStatus::Idle => "idle",
            OperationStatus::Testing => "testing",
            OperationStatus::Connecting => "connecting",
        }
        .into(),
    );
    window.set_selected_profile_id(
        state
            .operation
            .selected_profile_id
            .as_deref()
            .unwrap_or_default()
            .into(),
    );
    window.set_editing_saved_profile(
        state
            .operation
            .selected_profile_id
            .as_ref()
            .is_some_and(|id| state.profiles.iter().any(|profile| profile.id == *id)),
    );
    window.set_active_profile_name(
        state
            .active_profile
            .as_ref()
            .map(|profile| profile.name.as_str())
            .unwrap_or_default()
            .into(),
    );
    let profiles: Vec<SavedConnection> = state
        .profiles
        .iter()
        .map(|profile| {
            let summary = profile.summary();
            SavedConnection {
                id: summary.id.into(),
                name: summary.name.into(),
                servers: summary.bootstrap_servers.into(),
                security: summary.security.into(),
            }
        })
        .collect();
    window.set_saved_profiles(std::rc::Rc::new(slint::VecModel::from(profiles)).into());

    let error = |kind: Validation, message: &str| -> slint::SharedString {
        if state.validation_errors.contains(&kind) {
            message.into()
        } else {
            "".into()
        }
    };
    window.set_name_error(error(Validation::MissingName, "Enter a connection name."));
    window.set_servers_error(error(
        Validation::MissingBootstrapServers,
        "Enter at least one broker.",
    ));
    window.set_ca_error(error(
        Validation::MissingCaCertificate,
        "Choose a CA certificate path.",
    ));
    window.set_certificate_error(error(
        Validation::MissingClientCertificate,
        "The private key needs a certificate.",
    ));
    window.set_key_error(error(
        Validation::MissingPrivateKey,
        "The certificate needs a private key.",
    ));
    window.set_username_error(error(Validation::MissingSaslUsername, "Enter a username."));
    window.set_password_error(error(Validation::MissingSaslPassword, "Enter a password."));

    let (title, summary, diagnostic) = diagnostic_panel(state);
    window.set_error_title(title.into());
    window.set_error_summary(summary.into());
    window.set_error_diagnostic(diagnostic.into());
    window.set_storage_notice(
        if state.probe_error.is_some() {
            state
                .storage_error
                .as_ref()
                .map(|error| format!("Profile storage failed: {error}"))
                .unwrap_or_default()
        } else {
            String::new()
        }
        .into(),
    );
    let status = match state.operation.status {
        OperationStatus::Testing => "Testing connection...".to_owned(),
        OperationStatus::Connecting => "Connecting...".to_owned(),
        OperationStatus::Idle if state.pending_storage != 0 => {
            "Loading or saving profiles...".to_owned()
        }
        OperationStatus::Idle if !state.validation_errors.is_empty() => {
            "Correct the highlighted fields.".to_owned()
        }
        OperationStatus::Idle => match state.topic_count {
            Some(count) if state.operation.route == Route::Workspace => {
                format!("Connected: {count} topics found.")
            }
            Some(count) => format!("Test successful: {count} topics found."),
            None => format!(
                "{} saved connection(s). Choose a profile or add one.",
                state.profiles.len()
            ),
        },
    };
    window.set_status_text(status.into());
    let conflict_name = state
        .import_conflict
        .as_ref()
        .map(|(name, _)| name.as_str())
        .unwrap_or_default();
    if window.get_import_conflict_name() != conflict_name {
        window.set_import_rename(format!("{conflict_name} (imported)").into());
    }
    window.set_import_conflict_name(conflict_name.into());
    update_explorer_snapshot(window, &state.explorer);
    // Draft fields change only on Add/Select. Asynchronous notifications must
    // never overwrite unsaved edits or clear an in-memory password.
}

#[cfg(windows)]
fn diagnostic_panel(state: &connection_controller::ControllerSnapshot) -> (String, String, String) {
    use kafka::client::ConnectionFailureKind;
    let (mut title, mut summary, mut diagnostic) = state
        .probe_error
        .as_ref()
        .map(|error| {
            let (title, summary) = match error.kind {
                ConnectionFailureKind::Network => (
                    "Network connection failed",
                    "Check broker addresses, VPN, firewall, and Kafka listener port.",
                ),
                ConnectionFailureKind::Tls => (
                    "TLS connection failed",
                    "Check the CA certificate, hostname, and client certificate/key pairing.",
                ),
                ConnectionFailureKind::Authentication => (
                    "Authentication failed",
                    "Check SASL mechanism, username, and password.",
                ),
                ConnectionFailureKind::Authorization => (
                    "Authorization failed",
                    "Kafka accepted authentication but denied access.",
                ),
                ConnectionFailureKind::Protocol => (
                    "Kafka protocol failed",
                    "Check broker compatibility and security protocol.",
                ),
                ConnectionFailureKind::Unknown => (
                    "Connection failed",
                    "Review the technical diagnostic before retrying.",
                ),
            };
            (
                title.to_owned(),
                summary.to_owned(),
                error.diagnostic.clone(),
            )
        })
        .unwrap_or_default();
    if let Some(storage_error) = &state.storage_error {
        if state.probe_error.is_none() {
            title = "Profile storage failed".into();
            summary = "The connection could not be saved locally.".into();
            diagnostic = storage_error.clone();
        }
    }
    (title, summary, diagnostic)
}

#[cfg(windows)]
fn bind_controller(
    window: &MainWindow,
    runtime: tokio::runtime::Handle,
) -> connection_controller::ConnectionController {
    use connection_controller::{ConnectionController, OperationStatus};
    let controller = ConnectionController::install(window, runtime, update_snapshot);
    let busy = |controller: &ConnectionController| {
        let state = controller.snapshot();
        state.pending_storage != 0
            || state.operation.status != OperationStatus::Idle
            || state.import_conflict.is_some()
    };
    let operation_busy = |controller: &ConnectionController| {
        let state = controller.snapshot();
        state.pending_storage != 0 || state.operation.status != OperationStatus::Idle
    };

    let selected = controller.clone();
    let weak = window.as_weak();
    window.on_profile_selected(move |id| {
        if busy(&selected) {
            return;
        }
        selected.select_profile(Some(id.to_string()));
        if let (Some(window), Some(profile)) = (weak.upgrade(), selected.snapshot().draft_profile) {
            ConnectionForm::from_profile(&profile).write(&window);
        }
    });
    let connected_profile = controller.clone();
    let weak = window.as_weak();
    window.on_profile_connect_requested(move |id| {
        if busy(&connected_profile) {
            return;
        }
        let id = id.to_string();
        let profile = connected_profile
            .snapshot()
            .profiles
            .into_iter()
            .find(|profile| profile.id == id);
        if let Some(profile) = profile {
            connected_profile.select_profile(Some(profile.id.clone()));
            if let Some(window) = weak.upgrade() {
                ConnectionForm::from_profile(&profile).write(&window);
            }
            connected_profile.connect(profile);
        }
    });
    let deleting = controller.clone();
    let weak = window.as_weak();
    window.on_delete_requested(move |id| {
        if busy(&deleting) {
            return;
        }
        let id = id.to_string();
        if let Some(profile) = deleting
            .snapshot()
            .profiles
            .into_iter()
            .find(|profile| profile.id == id)
        {
            if let Some(window) = weak.upgrade() {
                window.set_delete_profile_id(id.into());
                window.set_delete_profile_name(profile.name.into());
                window.set_delete_confirmation_visible(true);
            }
        }
    });
    let confirmed_delete = controller.clone();
    let weak = window.as_weak();
    window.on_delete_confirmed(move || {
        if busy(&confirmed_delete) {
            return;
        }
        if let Some(window) = weak.upgrade() {
            let id = window.get_delete_profile_id().to_string();
            window.set_delete_confirmation_visible(false);
            window.set_delete_profile_id("".into());
            window.set_delete_profile_name("".into());
            if !id.is_empty() {
                confirmed_delete.delete_profile(id);
            }
        }
    });
    let weak = window.as_weak();
    window.on_delete_cancelled(move || {
        if let Some(window) = weak.upgrade() {
            window.set_delete_confirmation_visible(false);
            window.set_delete_profile_id("".into());
            window.set_delete_profile_name("".into());
        }
    });
    let added = controller.clone();
    let weak = window.as_weak();
    window.on_add_requested(move || {
        if busy(&added) {
            return;
        }
        added.add_profile();
        if let Some(window) = weak.upgrade() {
            ConnectionForm::default().write(&window);
        }
    });
    let tested = controller.clone();
    let weak = window.as_weak();
    window.on_test_requested(move || {
        if busy(&tested) {
            return;
        }
        if let Some(window) = weak.upgrade() {
            let profile = ConnectionForm::read(&window).into_profile();
            tested.test_connection(profile);
        }
    });
    let connected = controller.clone();
    let weak = window.as_weak();
    window.on_connect_requested(move || {
        if busy(&connected) {
            return;
        }
        if let Some(window) = weak.upgrade() {
            let profile = ConnectionForm::read(&window).into_profile();
            connected.connect(profile);
        }
    });
    let manager = controller.clone();
    window.on_connections_requested(move || {
        if !busy(&manager) {
            manager.show_manager();
        }
    });
    let imported = controller.clone();
    window.on_import_requested(move || {
        if !busy(&imported) {
            imported.import_file();
        }
    });
    let exported = controller.clone();
    let weak = window.as_weak();
    window.on_export_requested(move || {
        if !busy(&exported) {
            if let Some(window) = weak.upgrade() {
                window.set_export_warning_visible(true);
            }
        }
    });
    let confirmed = controller.clone();
    let weak = window.as_weak();
    window.on_export_confirmed(move || {
        if !busy(&confirmed) {
            if let Some(window) = weak.upgrade() {
                if window.get_export_warning_visible() {
                    window.set_export_warning_visible(false);
                    confirmed.export_file();
                }
            }
        }
    });
    let renamed = controller.clone();
    window.on_import_renamed(move |name| {
        if !operation_busy(&renamed) {
            renamed.resolve_import(connection_controller::ImportResolution::Rename(
                name.to_string(),
            ));
        }
    });
    let replaced = controller.clone();
    window.on_import_replaced(move || {
        if !operation_busy(&replaced) {
            replaced.resolve_import(connection_controller::ImportResolution::Replace);
        }
    });
    let cancelled = controller.clone();
    window.on_import_cancelled(move || {
        if !operation_busy(&cancelled) {
            cancelled.cancel_import();
        }
    });
    bind_explorer_controller(window, &controller);
    window.set_portable_files_available(true);
    controller
}

#[cfg(windows)]
fn bind_explorer_controller(
    window: &MainWindow,
    controller: &connection_controller::ConnectionController,
) {
    SearchForm::default().write(window);
    let refresh = controller.clone();
    window.on_refresh_requested(move || refresh.refresh_topics());

    let filter = controller.clone();
    let filter_timer = slint::Timer::default();
    window.on_topic_filter_changed(move |text| {
        let session_id = filter.snapshot().explorer.session_id;
        let filter = filter.clone();
        filter_timer.start(
            slint::TimerMode::SingleShot,
            std::time::Duration::from_millis(200),
            move || {
                let state = filter.snapshot();
                if state.operation.route == connection_controller::Route::Workspace
                    && state.explorer.session_id == session_id
                {
                    filter.filter_topics(text.to_string());
                }
            },
        );
    });

    let selected = controller.clone();
    let weak = window.as_weak();
    window.on_topic_selected(move |topic| {
        selected.select_topic(topic.to_string());
        if let Some(window) = weak.upgrade() {
            SearchForm::from_query(&selected.snapshot().explorer.search_query).write(&window);
            SearchFormErrors::default().write(&window);
        }
    });
    let search = controller.clone();
    let weak = window.as_weak();
    window.on_search_requested(move || {
        if let Some(window) = weak.upgrade() {
            apply_search_form(&window, &search, true);
        }
    });
    let edited = controller.clone();
    let weak = window.as_weak();
    window.on_search_form_changed(move || {
        if let Some(window) = weak.upgrade() {
            apply_search_form(&window, &edited, false);
        }
    });
    let cancel = controller.clone();
    window.on_search_cancelled(move || cancel.cancel_search());
    let page = controller.clone();
    window.on_page_requested(move |delta| page.change_page(delta));
    let record = controller.clone();
    window.on_message_selected(move |row| {
        if let Ok(row) = usize::try_from(row) {
            record.select_record(row);
        }
    });
    let timestamp_format = controller.clone();
    let weak = window.as_weak();
    window.on_message_timestamp_format_toggled(move || {
        if let Some(window) = weak.upgrade() {
            window.set_message_timestamps_as_iso(!window.get_message_timestamps_as_iso());
            update_snapshot(&window, &timestamp_format.snapshot());
        }
    });
    let weak = window.as_weak();
    window.on_record_value_json_beauty_requested(move || {
        if let Some(window) = weak.upgrade() {
            let value = json_beauty(window.get_record_value().as_str());
            window.set_record_value_line_numbers(line_numbers(&value).into());
            window.set_record_value(value.into());
        }
    });
    let opening = controller.clone();
    window.on_send_dialog_requested(move || opening.open_send_dialog());
    let edited = controller.clone();
    let weak = window.as_weak();
    window.on_send_form_changed(move || {
        if let Some(window) = weak.upgrade() {
            apply_send_form(&window, &edited);
        }
    });
    let formatted = controller.clone();
    let weak = window.as_weak();
    window.on_send_value_json_beauty_requested(move || {
        if let Some(window) = weak.upgrade() {
            window.set_send_value(json_beauty(window.get_send_value().as_str()).into());
            apply_send_form(&window, &formatted);
        }
    });
    let sending = controller.clone();
    let weak = window.as_weak();
    window.on_send_requested(move || {
        if let Some(window) = weak.upgrade() {
            if apply_send_form(&window, &sending) {
                sending.send_message();
            }
        }
    });
    let closing = controller.clone();
    window.on_send_dialog_closed(move || closing.close_send_dialog());
    let notice = controller.clone();
    window.on_delivery_notice_dismissed(move || notice.dismiss_delivery_notice());
}

#[cfg(test)]
mod explorer_form_tests {
    use super::*;
    use explorer::{HeaderData, RecordData, TimestampOrder, TimestampPresence, TopicSummary};

    #[test]
    fn connection_manager_is_the_initial_window_height() {
        assert!(include_str!("../ui/app.slint").contains("locked-window-height: 900px;"));
    }

    #[test]
    fn topic_workspace_opens_on_the_messages_tab() {
        assert!(
            include_str!("../ui/app.slint")
                .contains("property <string> topic-tab: \"messages\";")
        );
    }

    #[test]
    fn message_search_collapses_advanced_filters_and_prioritizes_results() {
        let ui = include_str!("../ui/app.slint");

        assert!(ui.contains("property <bool> search-advanced-filters-open: false;"));
        assert!(ui.contains("text: root.search-advanced-filters-open ? \"Fewer filters\" : \"More filters\";"));
        assert!(ui.contains("if root.search-advanced-filters-open : VerticalLayout"));
        assert!(ui.contains("height: 320px;"));
    }

    #[test]
    fn message_results_fit_ten_compact_rows_and_detail_tabs_are_on_top() {
        let ui = include_str!("../ui/app.slint");

        assert!(ui.contains("height: 400px;"));
        assert!(ui.contains("height: 36px;\n                                            vertical-stretch: 0;\n                                            background: row-index"));
        let detail = ui
            .split("if root.record-selected : Rectangle")
            .nth(1)
            .and_then(|section| section.split("if root.topic-tab == \"consumers\"").next())
            .expect("message detail layout");
        assert!(detail.contains("tab-strip := Rectangle"));
        assert!(detail.contains("MessageDetailTab { x: 0px; width: 92px; text: \"Value\";"));
    }

    #[test]
    fn message_paging_actions_share_the_page_status_row() {
        let ui = include_str!("../ui/app.slint");
        let results = ui
            .split("if root.search-has-results && root.search-result-count > 0 : VerticalLayout")
            .nth(1)
            .expect("message results layout");

        assert!(results.contains("Text { text: \"Page \" + root.page-number + \" of \" + root.page-count;"));
        assert!(results.contains("Button { width: 68px; height: 28px; text: \"Previous\";"));
        assert!(results.contains("Button { width: 52px; height: 28px; text: \"Next\";"));
    }

    #[test]
    fn message_detail_title_has_its_own_top_row() {
        let ui = include_str!("../ui/app.slint");
        let detail = ui
            .split("if root.record-selected : Rectangle")
            .nth(1)
            .expect("message detail layout");

        assert!(detail.contains("height: 24px; text: \"MESSAGE DETAIL\""));
        assert!(detail.contains("tab-strip := Rectangle {\n                                    x: 12px;\n                                    y: 32px;"));
        assert!(detail.contains("y: 68px;"));
    }

    #[test]
    fn message_detail_content_fills_the_space_below_the_top_tab_strip() {
        let ui = include_str!("../ui/app.slint");
        let detail = ui
            .split("if root.record-selected : Rectangle")
            .nth(1)
            .expect("message detail layout");

        assert!(detail.contains("detail-content := Rectangle"));
        assert!(detail.contains("height: parent.height - 80px;"));
    }

    #[test]
    fn message_detail_renders_line_numbers_for_every_text_pane() {
        let ui = include_str!("../ui/app.slint");
        let detail = ui
            .split("if root.record-selected : Rectangle")
            .nth(1)
            .and_then(|section| section.split("if root.topic-tab == \"consumers\"").next())
            .expect("message detail layout");

        assert!(ui.contains("record-value-line-numbers"));
        assert!(ui.contains("record-key-line-numbers"));
        assert!(ui.contains("line-numbers: string"));
        assert_eq!(detail.matches("y: 20px; width: 32px; height: parent.height - 28px; text:").count(), 3);
    }

    #[test]
    fn send_message_editors_render_line_numbers_from_their_contents() {
        let ui = include_str!("../ui/app.slint");
        let dialog = ui
            .split("if root.route == \"workspace\" && root.send-dialog-open : Rectangle")
            .nth(1)
            .expect("send dialog layout");

        assert!(dialog.contains("text: root.send-key-line-numbers"));
        assert!(dialog.contains("text: root.send-value-line-numbers"));
        assert_eq!(dialog.matches("background: #ffffff;\n                                border-color: #d8e3ec;").count(), 2);
        assert_eq!(dialog.matches("x: 52px;\n                                    y: 8px;").count(), 2);
    }

    #[test]
    fn detail_line_numbers_include_empty_and_trailing_lines() {
        assert_eq!(line_numbers("single"), "1");
        assert_eq!(line_numbers("one\ntwo\n"), "1\n2\n3");
        assert_eq!(line_numbers(""), "1");
    }

    #[test]
    fn send_message_dialog_uses_a_compact_composer_layout() {
        let ui = include_str!("../ui/app.slint");

        assert!(ui.contains("height: min(520px, parent.height - 48px);"));
        assert!(ui.contains("height: 56px;\n                                min-width: 0px;\n                                background: #ffffff;"));
        assert!(ui.contains("height: 190px;\n                                min-width: 0px;\n                                background: #ffffff;"));
    }

    #[test]
    fn send_message_keeps_partition_label_and_picker_on_one_compact_row() {
        let ui = include_str!("../ui/app.slint");
        let dialog = ui
            .split("if root.route == \"workspace\" && root.send-dialog-open : Rectangle")
            .nth(1)
            .expect("send dialog layout");

        assert!(dialog.contains("Text { width: 58px; text: \"Partition\";"));
        assert!(dialog.contains("ComboBox {\n                                        width: 160px;\n                                        height: 32px;"));
        assert!(!dialog.contains("ExplorerSelect {\n                                label: \"Partition\";"));
    }

    #[test]
    fn json_beauty_formats_valid_json_and_leaves_plain_text_unchanged() {
        assert_eq!(
            json_beauty(r#"{"event":"created","items":[1,2]}"#),
            "{\n  \"event\": \"created\",\n  \"items\": [\n    1,\n    2\n  ]\n}"
        );
        assert_eq!(json_beauty("not json"), "not json");
    }

    #[test]
    fn message_previews_count_unicode_characters_and_keep_exact_record_metadata() {
        let record = RecordData {
            partition: 3,
            offset: 9_007_199_254_740_993,
            timestamp: Some(1_790_000_000_123),
            key: Some("\u{754c}".repeat(21)),
            value: "\u{1f642}".repeat(51),
            headers: Vec::new(),
        };
        let row = message_row(&record, 50, TimestampDisplay::UnixMilliseconds);

        assert_eq!(
            row.key_preview.as_str(),
            format!("{}...", "\u{754c}".repeat(20))
        );
        assert_eq!(
            row.value_preview.as_str(),
            format!("{}...", "\u{1f642}".repeat(50))
        );
        assert_eq!(row.partition.as_str(), "3");
        assert_eq!(row.offset.as_str(), "9007199254740993");
        assert_eq!(row.timestamp.as_str(), "1790000000123");
    }

    #[test]
    fn message_rows_keep_values_distinct_when_offsets_repeat_across_partitions() {
        let records = [
            RecordData {
                partition: 0,
                offset: 5,
                timestamp: Some(1),
                key: Some("fsd".into()),
                value: "sdf".into(),
                headers: Vec::new(),
            },
            RecordData {
                partition: 1,
                offset: 26,
                timestamp: Some(2),
                key: Some("et".into()),
                value: "reyhhhh".into(),
                headers: Vec::new(),
            },
        ];
        let rows: Vec<_> = records
            .iter()
            .map(|record| message_row(record, 60, TimestampDisplay::UnixMilliseconds))
            .collect();

        assert_eq!(rows[0].partition.as_str(), "0");
        assert_eq!(rows[0].offset.as_str(), "5");
        assert_eq!(rows[0].value_preview.as_str(), "sdf");
        assert_eq!(rows[1].partition.as_str(), "1");
        assert_eq!(rows[1].offset.as_str(), "26");
        assert_eq!(rows[1].value_preview.as_str(), "reyhhhh");
    }

    #[test]
    fn message_preview_escapes_line_breaks_for_a_single_table_row() {
        let record = RecordData {
            partition: 1,
            offset: 26,
            timestamp: Some(2),
            key: None,
            value: "first\r\nsecond\nthird\tfourth".into(),
            headers: Vec::new(),
        };

        let row = message_row(&record, 60, TimestampDisplay::UnixMilliseconds);

        assert_eq!(
            row.value_preview.as_str(),
            "first\\r\\nsecond\\nthird\\tfourth"
        );
    }

    #[test]
    fn message_preview_limit_is_fixed_for_a_single_line() {
        assert_eq!(message_preview_limit(), 60);
    }

    #[test]
    fn locked_window_size_uses_available_work_area() {
        assert_eq!(locked_window_size(1_366, 728), (1_100, 672));
        assert_eq!(locked_window_size(2_560, 1_400), (1_100, 1_040));
    }

    #[test]
    fn record_details_preserve_full_text_and_ordered_duplicate_headers() {
        let record = RecordData {
            partition: 1,
            offset: 8,
            timestamp: None,
            key: Some("k".repeat(80)),
            value: "v".repeat(300),
            headers: vec![
                HeaderData {
                    name: "trace".into(),
                    value: None,
                },
                HeaderData {
                    name: "trace".into(),
                    value: Some(String::new()),
                },
                HeaderData {
                    name: "trace".into(),
                    value: Some("long".repeat(90)),
                },
            ],
        };
        let detail = record_detail(&record, TimestampDisplay::UnixMilliseconds);

        assert_eq!(detail.key, "k".repeat(80));
        assert_eq!(detail.value, "v".repeat(300));
        assert_eq!(detail.timestamp, "No timestamp");
        assert_eq!(detail.headers.len(), 3);
        assert_eq!(detail.headers[0].name.as_str(), "trace");
        assert_eq!(detail.headers[0].value.as_str(), "(null)");
        assert_eq!(detail.headers[1].value.as_str(), "");
        assert_eq!(detail.headers[2].value.as_str(), "long".repeat(90));
    }

    #[test]
    fn absent_keys_remain_distinct_from_empty_keys() {
        let mut record = RecordData {
            partition: 0,
            offset: 0,
            timestamp: None,
            key: None,
            value: String::new(),
            headers: Vec::new(),
        };
        assert_eq!(
            message_row(&record, 50, TimestampDisplay::UnixMilliseconds)
                .key_preview
                .as_str(),
            "(no key)"
        );
        assert_eq!(
            record_detail(&record, TimestampDisplay::UnixMilliseconds).key,
            "(no key)"
        );
        record.key = Some(String::new());
        assert_eq!(
            message_row(&record, 50, TimestampDisplay::UnixMilliseconds)
                .key_preview
                .as_str(),
            ""
        );
        assert_eq!(
            record_detail(&record, TimestampDisplay::UnixMilliseconds).key,
            ""
        );
    }

    #[test]
    fn topic_rows_filter_cached_names_without_losing_internal_topics_or_order() {
        let topics = vec![
            TopicSummary {
                name: "__Events".into(),
                partition_count: 2,
            },
            TopicSummary {
                name: "events".into(),
                partition_count: 12,
            },
            TopicSummary {
                name: "other".into(),
                partition_count: 1,
            },
        ];
        let rows = topic_rows(&topics, " EVENTS ");
        let names: Vec<_> = rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["__Events", "events"]);
        assert_eq!(rows[1].partition_count.as_str(), "12");
        assert_eq!(topics.len(), 3);
    }

    #[test]
    fn search_form_parses_metadata_partition_and_inclusive_signed_unix_milliseconds() {
        let input = SearchForm {
            partition: " 3 ".into(),
            page_size: " 1000 ".into(),
            key_contains: " key ".into(),
            value_contains: " value ".into(),
            case_sensitive: true,
            timestamp_from: " -1 ".into(),
            timestamp_to: " 1790000000123 ".into(),
            order: "Earliest first".into(),
            timestamp_presence: "Has timestamp".into(),
        }
        .parse(&[0, 3]);

        assert!(input.errors.is_empty());
        assert_eq!(input.query.partition, Some(3));
        assert_eq!(input.query.page_size, 1000);
        assert_eq!(input.query.key_contains, " key ");
        assert_eq!(input.query.value_contains, " value ");
        assert!(input.query.case_sensitive);
        assert_eq!(input.query.timestamp_from, Some(-1));
        assert_eq!(input.query.timestamp_to, Some(1_790_000_000_123));
        assert!(matches!(input.query.order, TimestampOrder::EarliestFirst));
        assert!(matches!(
            input.query.timestamp_presence,
            TimestampPresence::HasTimestamp
        ));
    }

    #[test]
    fn search_form_parses_iso_8601_offset_datetimes() {
        let input = SearchForm {
            timestamp_from: "2026-10-31T00:00:00+07:00".into(),
            timestamp_to: "2026-10-31T23:59:59+07:00".into(),
            ..SearchForm::default()
        }
        .parse(&[0]);

        assert!(input.errors.is_empty());
        assert_eq!(input.query.timestamp_from, Some(1_793_379_600_000));
        assert_eq!(input.query.timestamp_to, Some(1_793_465_999_000));
    }

    #[test]
    fn timestamp_text_formats_unix_milliseconds_as_iso_8601() {
        assert_eq!(
            timestamp_text(Some(1_790_000_000_123), TimestampDisplay::Iso8601),
            "2026-09-21T14:13:20.123Z"
        );
        assert_eq!(
            timestamp_text(None, TimestampDisplay::Iso8601),
            "No timestamp"
        );
    }

    #[test]
    fn malformed_search_fields_have_independent_errors_and_a_safe_invalidation_query() {
        let input = SearchForm {
            partition: "2".into(),
            page_size: "1001".into(),
            timestamp_from: "tomorrow".into(),
            timestamp_to: "9223372036854775808".into(),
            ..SearchForm::default()
        }
        .parse(&[0, 3]);

        assert!(!input.errors.partition.is_empty());
        assert!(!input.errors.page_size.is_empty());
        assert!(!input.errors.timestamp_from.is_empty());
        assert!(!input.errors.timestamp_to.is_empty());
        assert_eq!(input.query.partition, None);
        assert_eq!(input.query.timestamp_from, None);
        assert_eq!(input.query.timestamp_to, None);
        assert!(input.query.normalize().is_ok());
    }

    #[test]
    fn reversed_timestamp_range_is_localized_to_timestamp_fields() {
        let input = SearchForm {
            timestamp_from: "21".into(),
            timestamp_to: "20".into(),
            ..SearchForm::default()
        }
        .parse(&[0]);
        assert!(!input.errors.timestamp_from.is_empty());
        assert!(!input.errors.timestamp_to.is_empty());
        assert!(input.errors.partition.is_empty());
        assert!(input.errors.page_size.is_empty());
    }

    #[test]
    fn blank_optional_fields_and_default_choices_form_a_valid_query() {
        let input = SearchForm::default().parse(&[0, 3]);
        assert!(input.errors.is_empty());
        assert!(input.query == explorer::SearchQuery::default());
        for page_size in ["", "0", "-1", "1.5", "18446744073709551616"] {
            let input = SearchForm {
                page_size: page_size.into(),
                ..SearchForm::default()
            }
            .parse(&[0]);
            assert!(!input.errors.page_size.is_empty());
        }
    }

    #[test]
    fn send_partition_accepts_automatic_or_an_existing_id_only() {
        assert_eq!(parse_partition("Automatic", "Automatic", &[0, 3]), Ok(None));
        assert_eq!(parse_partition("3", "Automatic", &[0, 3]), Ok(Some(3)));
        for partition in ["", "All partitions", "2", "-1", "2147483648"] {
            assert!(parse_partition(partition, "Automatic", &[0, 3]).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn delivery_notice_preserves_requested_and_actual_partition_context() {
        let notice = connection_controller::DeliveryNotice {
            success: true,
            topic: "events".into(),
            requested_partition: None,
            delivered_partition: Some(3),
            diagnostic: None,
        };
        let message = delivery_notice_text(&notice);
        assert!(message.contains("events"));
        assert!(message.contains("Automatic"));
        assert!(message.contains("partition 3"));
        let failed = connection_controller::DeliveryNotice {
            success: false,
            requested_partition: Some(2),
            delivered_partition: None,
            diagnostic: Some("Broker unavailable".into()),
            ..notice
        };
        let message = delivery_notice_text(&failed);
        assert!(message.contains("partition 2"));
        assert!(message.contains("Broker unavailable"));
    }
}

#[cfg(test)]
mod form_tests {
    use super::*;
    use models::{SaslMechanism, Secret, TlsSettings};

    #[cfg(windows)]
    #[test]
    fn remote_diagnostic_is_copyable_unchanged_when_storage_also_failed() {
        let diagnostic = "  Broker failed\r\nDiagnostic: Ω  ";
        let state = connection_controller::ControllerSnapshot {
            probe_error: Some(kafka::client::ConnectionProbeError::from_diagnostic(
                diagnostic.into(),
            )),
            storage_error: Some("Profile storage unavailable".into()),
            ..Default::default()
        };
        assert_eq!(diagnostic_panel(&state).2, diagnostic);
    }

    #[cfg(windows)]
    #[test]
    fn authentication_failure_has_a_distinct_actionable_summary() {
        let state = connection_controller::ControllerSnapshot {
            probe_error: Some(kafka::client::ConnectionProbeError {
                kind: kafka::client::ConnectionFailureKind::Authentication,
                diagnostic: "SASL authentication failed".into(),
            }),
            ..Default::default()
        };

        assert_eq!(
            diagnostic_panel(&state).1,
            "Check SASL mechanism, username, and password."
        );
    }

    #[test]
    fn editing_form_preserves_identity_and_every_security_setting() {
        let tls = TlsSettings {
            ca_path: "ca.pem".into(),
            certificate_path: Some("client.pem".into()),
            private_key_path: Some("client.key".into()),
            private_key_password: Secret::new("fixture-key-password"),
        };
        let mut profiles = vec![
            ConnectionProfile::plaintext("broker:9092"),
            ConnectionProfile::ssl("broker:9093", tls.clone()),
        ];
        for transport in [SaslTransport::Plaintext, SaslTransport::Ssl] {
            for mechanism in [
                SaslMechanism::Plain,
                SaslMechanism::ScramSha256,
                SaslMechanism::ScramSha512,
            ] {
                profiles.push(ConnectionProfile::sasl(
                    "broker:9093",
                    transport,
                    mechanism,
                    "alice",
                    "fixture-password",
                    if transport == SaslTransport::Ssl {
                        tls.clone()
                    } else {
                        TlsSettings::default()
                    },
                ));
            }
        }
        for mut profile in profiles {
            profile.id = "saved-identity".into();
            profile.name = "Production".into();
            let restored = ConnectionForm::from_profile(&profile).into_profile();
            assert_eq!(restored, profile);
        }
    }

    #[test]
    fn new_form_allocates_identity_without_inventing_a_required_name() {
        let profile = ConnectionForm::default().into_profile();
        assert!(uuid::Uuid::parse_str(&profile.id).is_ok());
        assert_eq!(profile.name, "");
        assert_eq!(profile.bootstrap_servers, "localhost:9092");
        assert_eq!(
            profile.validate(),
            Err(vec![models::ProfileValidationError::MissingName])
        );
    }

    #[test]
    fn switching_to_plaintext_drops_hidden_credentials_and_tls_settings() {
        let mut form = ConnectionForm::from_profile(&ConnectionProfile::sasl(
            "broker:9093",
            SaslTransport::Ssl,
            SaslMechanism::Plain,
            "alice",
            "fixture-password",
            TlsSettings::with_ca("ca.pem"),
        ));
        form.security_mode = "PLAINTEXT".into();
        let profile = form.into_profile();
        assert_eq!(profile.bootstrap_servers, "broker:9093");
        assert_eq!(profile.security, models::SecurityMode::Plaintext);
        assert_eq!(profile.tls, None);
    }
}
