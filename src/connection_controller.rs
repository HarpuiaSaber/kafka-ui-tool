use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use slint::ComponentHandle;
use tokio::{runtime::Handle, sync::mpsc};
use tokio_util::sync::CancellationToken;

use crate::explorer::{
    filter_and_page_cancellable, validate_send, RecordData, SearchQuery, SearchSnapshot,
    SendRequest, TopicDetail, TopicSummary,
};
use crate::kafka::client::{
    load_topic_detail, load_topics, probe_connection, search_records, send_record,
    ConnectionProbeError, ExplorerKafkaError, SendDelivery,
};
use crate::models::{ConnectionProfile, PersistedProfile, ProfileValidationError, Secret};
use crate::profile_bundle::{self, BundleError};
use crate::profile_store::{ProfileStore, StoreError};
use crate::MainWindow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Manager,
    Workspace,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    Idle,
    Testing,
    Connecting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRequest {
    pub id: u64,
    pub profile_id: String,
    pub status: OperationStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationState {
    pub route: Route,
    pub selected_profile_id: Option<String>,
    pub active_profile_id: Option<String>,
    pub status: OperationStatus,
    next_request_id: u64,
    pending: Option<OperationRequest>,
}

impl Default for OperationState {
    fn default() -> Self {
        Self {
            route: Route::Manager,
            selected_profile_id: None,
            active_profile_id: None,
            status: OperationStatus::Idle,
            next_request_id: 0,
            pending: None,
        }
    }
}

impl OperationState {
    pub fn begin(
        &mut self,
        profile_id: String,
        status: OperationStatus,
    ) -> Option<OperationRequest> {
        if self.route != Route::Manager || status == OperationStatus::Idle {
            return None;
        }
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .expect("request ID exhausted");
        let request = OperationRequest {
            id: self.next_request_id,
            profile_id,
            status,
        };
        self.selected_profile_id = Some(request.profile_id.clone());
        self.status = status;
        self.pending = Some(request.clone());
        Some(request)
    }

    pub fn is_current(&self, request: &OperationRequest) -> bool {
        self.pending.as_ref() == Some(request)
            && self.route == Route::Manager
            && self.selected_profile_id.as_ref() == Some(&request.profile_id)
            && self.status == request.status
    }

    pub fn complete(&mut self, request: &OperationRequest, success: bool) -> bool {
        if !self.is_current(request) {
            return false;
        }
        self.cancel();
        if success && request.status == OperationStatus::Connecting {
            self.active_profile_id = Some(request.profile_id.clone());
            self.route = Route::Workspace;
        }
        true
    }

    pub fn select(&mut self, profile_id: Option<String>) {
        self.cancel();
        self.selected_profile_id = profile_id;
    }

    pub fn show_manager(&mut self) {
        self.cancel();
        self.route = Route::Manager;
    }

    fn cancel(&mut self) {
        self.pending = None;
        self.status = OperationStatus::Idle;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExplorerRequest {
    session_id: u64,
    request_id: u64,
}

#[derive(Clone, Copy, Debug)]
enum ExplorerOperation {
    Refresh,
    Metadata,
    Search,
    Delivery,
}

#[derive(Clone, Debug)]
struct ExplorerWork {
    identity: ExplorerRequest,
    cancel: CancellationToken,
    started: Instant,
}

#[derive(Clone)]
struct ExplorerSession {
    id: u64,
    profile_id: String,
    next_request_id: u64,
    details: Arc<HashMap<String, TopicDetail>>,
    refresh: Option<ExplorerWork>,
    metadata: Option<ExplorerWork>,
    search: Option<ExplorerWork>,
    delivery: Option<ExplorerWork>,
}

impl std::fmt::Debug for ExplorerSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExplorerSession")
            .field("id", &self.id)
            .field("profile_id", &self.profile_id)
            .field("next_request_id", &self.next_request_id)
            .field("cached_details", &self.details.len())
            .finish_non_exhaustive()
    }
}

impl ExplorerSession {
    fn new(id: u64, profile_id: String) -> Self {
        Self {
            id,
            profile_id,
            next_request_id: 0,
            details: Arc::new(HashMap::new()),
            refresh: None,
            metadata: None,
            search: None,
            delivery: None,
        }
    }

    fn slot(&self, operation: ExplorerOperation) -> &Option<ExplorerWork> {
        match operation {
            ExplorerOperation::Refresh => &self.refresh,
            ExplorerOperation::Metadata => &self.metadata,
            ExplorerOperation::Search => &self.search,
            ExplorerOperation::Delivery => &self.delivery,
        }
    }

    fn slot_mut(&mut self, operation: ExplorerOperation) -> &mut Option<ExplorerWork> {
        match operation {
            ExplorerOperation::Refresh => &mut self.refresh,
            ExplorerOperation::Metadata => &mut self.metadata,
            ExplorerOperation::Search => &mut self.search,
            ExplorerOperation::Delivery => &mut self.delivery,
        }
    }

    fn cancel(&mut self, operation: ExplorerOperation) {
        if let Some(work) = self.slot_mut(operation).take() {
            work.cancel.cancel();
        }
    }

    fn cancel_all(&mut self) {
        for operation in [
            ExplorerOperation::Refresh,
            ExplorerOperation::Metadata,
            ExplorerOperation::Search,
            ExplorerOperation::Delivery,
        ] {
            self.cancel(operation);
        }
    }

    fn begin(&mut self, operation: ExplorerOperation) -> ExplorerWork {
        self.cancel(operation);
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .expect("explorer request ID exhausted");
        let work = ExplorerWork {
            identity: ExplorerRequest {
                session_id: self.id,
                request_id: self.next_request_id,
            },
            cancel: CancellationToken::new(),
            started: Instant::now(),
        };
        *self.slot_mut(operation) = Some(work.clone());
        work
    }

    fn accepts(&self, operation: ExplorerOperation, identity: ExplorerRequest) -> bool {
        self.id == identity.session_id
            && self
                .slot(operation)
                .as_ref()
                .is_some_and(|work| work.identity == identity && !work.cancel.is_cancelled())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryNotice {
    pub success: bool,
    pub topic: String,
    pub requested_partition: Option<i32>,
    pub delivered_partition: Option<i32>,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Default)]
pub struct ExplorerSnapshot {
    pub session_id: Option<u64>,
    pub profile_id: Option<String>,
    pub topics: Vec<TopicSummary>,
    pub topic_filter: String,
    pub selected_topic: Option<String>,
    pub topic_unavailable: bool,
    pub detail: Option<TopicDetail>,
    pub topic_error: Option<String>,
    pub detail_error: Option<String>,
    pub refreshing: bool,
    pub metadata_pending: bool,
    pub search_pending: bool,
    pub delivery_pending: bool,
    pub refresh_elapsed_ms: u64,
    pub metadata_elapsed_ms: u64,
    pub search_elapsed_ms: u64,
    pub delivery_elapsed_ms: u64,
    pub search_query: SearchQuery,
    // Elapsed ticks and UI notifications must not copy every record payload.
    pub search: Option<Arc<SearchSnapshot>>,
    pub page_index: usize,
    pub selected_record_index: Option<usize>,
    pub search_error: Option<String>,
    pub send_draft: Option<SendRequest>,
    pub send_validation_error: Option<String>,
    pub delivery_notice: Option<DeliveryNotice>,
}

impl std::fmt::Debug for ExplorerSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExplorerSnapshot")
            .field("session_id", &self.session_id)
            .field("profile_id", &self.profile_id)
            .field("topic_count", &self.topics.len())
            .field("selected_topic", &self.selected_topic)
            .field(
                "record_count",
                &self.search.as_ref().map(|search| search.records.len()),
            )
            .field("page_index", &self.page_index)
            .field("refreshing", &self.refreshing)
            .field("metadata_pending", &self.metadata_pending)
            .field("search_pending", &self.search_pending)
            .field("delivery_pending", &self.delivery_pending)
            .finish_non_exhaustive()
    }
}

impl ExplorerSnapshot {
    pub fn page(&self) -> &[RecordData] {
        self.search
            .as_ref()
            .map(|search| search.page(self.page_index, search.query.page_size))
            .unwrap_or_default()
    }

    pub fn page_count(&self) -> usize {
        self.search.as_ref().map_or(0, |search| {
            search
                .records
                .len()
                .div_ceil(search.query.page_size.clamp(1, 1_000))
        })
    }

    pub fn selected_record(&self) -> Option<&RecordData> {
        self.search
            .as_ref()?
            .records
            .get(self.selected_record_index?)
    }

    fn pending(&mut self, operation: ExplorerOperation, pending: bool) {
        match operation {
            ExplorerOperation::Refresh => self.refreshing = pending,
            ExplorerOperation::Metadata => self.metadata_pending = pending,
            ExplorerOperation::Search => self.search_pending = pending,
            ExplorerOperation::Delivery => self.delivery_pending = pending,
        }
    }

    fn elapsed(&mut self, operation: ExplorerOperation, elapsed_ms: u64) {
        match operation {
            ExplorerOperation::Refresh => self.refresh_elapsed_ms = elapsed_ms,
            ExplorerOperation::Metadata => self.metadata_elapsed_ms = elapsed_ms,
            ExplorerOperation::Search => self.search_elapsed_ms = elapsed_ms,
            ExplorerOperation::Delivery => self.delivery_elapsed_ms = elapsed_ms,
        }
    }
}

enum ExplorerCompletion {
    Topics(Result<Vec<TopicSummary>, ExplorerKafkaError>),
    Metadata(Result<TopicDetail, ExplorerKafkaError>),
    Search(Result<SearchSnapshot, ExplorerKafkaError>),
    Delivery {
        topic: String,
        requested_partition: Option<i32>,
        result: Result<SendDelivery, ExplorerKafkaError>,
    },
}

impl ExplorerCompletion {
    fn operation(&self) -> ExplorerOperation {
        match self {
            Self::Topics(_) => ExplorerOperation::Refresh,
            Self::Metadata(_) => ExplorerOperation::Metadata,
            Self::Search(_) => ExplorerOperation::Search,
            Self::Delivery { .. } => ExplorerOperation::Delivery,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExplorerLifecycle {
    next_session_id: u64,
    session: Option<ExplorerSession>,
}

#[derive(Clone, Debug, Default)]
pub struct ControllerSnapshot {
    pub operation: OperationState,
    pub profiles: Vec<ConnectionProfile>,
    pub validation_errors: Vec<ProfileValidationError>,
    pub probe_error: Option<ConnectionProbeError>,
    pub topic_count: Option<usize>,
    pub storage_error: Option<String>,
    pub import_conflict: Option<(String, String)>,
    pub pending_storage: usize,
    pub draft_profile: Option<ConnectionProfile>,
    pub active_profile: Option<ConnectionProfile>,
    pub explorer: ExplorerSnapshot,
    pub explorer_lifecycle: ExplorerLifecycle,
}

impl ControllerSnapshot {
    fn show_manager(&mut self) {
        self.discard_explorer();
        self.operation.show_manager();
        self.operation.active_profile_id = None;
        self.active_profile = None;
        self.topic_count = None;
    }

    fn select_profile_state(&mut self, id: Option<String>) {
        self.show_manager();
        self.operation.select(id.clone());
        self.draft_profile = self
            .profiles
            .iter()
            .find(|profile| Some(&profile.id) == id.as_ref())
            .cloned();
        self.validation_errors.clear();
        self.probe_error = None;
    }

    fn discard_explorer(&mut self) {
        if let Some(mut session) = self.explorer_lifecycle.session.take() {
            session.cancel_all();
        }
        self.explorer = ExplorerSnapshot::default();
    }

    fn remove_profile_state(&mut self, id: &str) {
        if self.operation.active_profile_id.as_deref() == Some(id) {
            self.show_manager();
        }
        if self.operation.selected_profile_id.as_deref() == Some(id) {
            self.operation.select(None);
            self.draft_profile = None;
            self.validation_errors.clear();
            self.probe_error = None;
        }
    }

    fn apply_probe(
        &mut self,
        request: &OperationRequest,
        result: Result<usize, ConnectionProbeError>,
    ) -> bool {
        if !self.operation.complete(request, result.is_ok()) {
            return false;
        }
        match result {
            Ok(count) => {
                self.topic_count = Some(count);
                self.probe_error = None;
                if request.status == OperationStatus::Connecting {
                    self.discard_explorer();
                    self.active_profile = self.draft_profile.clone();
                    self.explorer_lifecycle.next_session_id = self
                        .explorer_lifecycle
                        .next_session_id
                        .checked_add(1)
                        .expect("explorer session ID exhausted");
                    self.explorer_lifecycle.session = Some(ExplorerSession::new(
                        self.explorer_lifecycle.next_session_id,
                        request.profile_id.clone(),
                    ));
                    self.explorer.session_id = Some(self.explorer_lifecycle.next_session_id);
                    self.explorer.profile_id = Some(request.profile_id.clone());
                }
            }
            Err(error) => {
                self.topic_count = None;
                self.probe_error = Some(error);
            }
        }
        true
    }

    fn accepts(&self, operation: ExplorerOperation, identity: ExplorerRequest) -> bool {
        self.operation.route == Route::Workspace
            && self
                .explorer_lifecycle
                .session
                .as_ref()
                .is_some_and(|session| {
                    self.operation.active_profile_id.as_ref() == Some(&session.profile_id)
                        && session.accepts(operation, identity)
                })
    }

    fn begin_explorer(&mut self, operation: ExplorerOperation) -> Option<ExplorerWork> {
        if self.operation.route != Route::Workspace {
            return None;
        }
        let session = self.explorer_lifecycle.session.as_mut()?;
        if self.operation.active_profile_id.as_ref() != Some(&session.profile_id) {
            return None;
        }
        let work = session.begin(operation);
        self.explorer.pending(operation, true);
        self.explorer.elapsed(operation, 0);
        Some(work)
    }

    fn cancel_explorer(&mut self, operation: ExplorerOperation) {
        if let Some(session) = self.explorer_lifecycle.session.as_mut() {
            session.cancel(operation);
        }
        self.explorer.pending(operation, false);
    }

    fn begin_refresh(&mut self) -> Option<ExplorerWork> {
        let work = self.begin_explorer(ExplorerOperation::Refresh)?;
        self.explorer.topic_error = None;
        Some(work)
    }

    fn clear_topic(&mut self) {
        self.cancel_explorer(ExplorerOperation::Metadata);
        self.cancel_search();
        self.close_send_dialog();
        self.explorer.selected_topic = None;
        self.explorer.detail = None;
        self.explorer.detail_error = None;
        self.explorer.search = None;
        self.explorer.page_index = 0;
        self.explorer.selected_record_index = None;
        self.explorer.search_query = SearchQuery::default();
    }

    fn begin_metadata(&mut self, topic: String) -> Option<ExplorerWork> {
        if !self.explorer.topics.iter().any(|entry| entry.name == topic) {
            return None;
        }
        self.clear_topic();
        self.explorer.selected_topic = Some(topic);
        self.explorer.topic_unavailable = false;
        self.begin_explorer(ExplorerOperation::Metadata)
    }

    fn select_topic_state(&mut self, topic: String) -> Option<ExplorerWork> {
        if !self.explorer.topics.iter().any(|entry| entry.name == topic) {
            return None;
        }
        let cached = self
            .explorer_lifecycle
            .session
            .as_ref()
            .and_then(|session| session.details.get(&topic))
            .cloned();
        if let Some(detail) = cached {
            self.clear_topic();
            self.explorer.selected_topic = Some(topic);
            self.explorer.topic_unavailable = false;
            self.explorer.detail = Some(detail);
            None
        } else {
            self.begin_metadata(topic)
        }
    }

    fn search_form_changed(&mut self, query: SearchQuery) {
        self.cancel_search();
        self.explorer.search_query = query;
        self.explorer.search = None;
        self.explorer.page_index = 0;
        self.explorer.selected_record_index = None;
    }

    fn cancel_search(&mut self) {
        self.cancel_explorer(ExplorerOperation::Search);
        self.explorer.search_error = None;
    }

    fn begin_search(
        &mut self,
        query: SearchQuery,
    ) -> Option<(
        ExplorerWork,
        SearchQuery,
        Vec<crate::explorer::PartitionDetail>,
        String,
    )> {
        self.search_form_changed(query.clone());
        let query = match query.normalize() {
            Ok(query) => query,
            Err(_) => {
                self.explorer.search_error =
                    Some("Timestamp from must not exceed timestamp to".into());
                return None;
            }
        };
        let Some(detail) = self.explorer.detail.as_ref() else {
            self.explorer.search_error =
                Some("Wait for topic partition metadata before searching".into());
            return None;
        };
        let partitions = detail.partitions.clone();
        if partitions.is_empty()
            || query
                .partition
                .is_some_and(|selected| !partitions.iter().any(|p| p.id == selected))
        {
            self.explorer.search_error = Some("Select an available topic partition".into());
            return None;
        }
        let topic = detail.name.clone();
        let work = self.begin_explorer(ExplorerOperation::Search)?;
        self.explorer.search_query = query.clone();
        Some((work, query, partitions, topic))
    }

    fn change_page(&mut self, delta: i32) {
        let last = self.explorer.page_count().saturating_sub(1);
        self.explorer.page_index = self
            .explorer
            .page_index
            .saturating_add_signed(delta as isize)
            .min(last);
        self.explorer.selected_record_index = None;
    }

    fn select_record(&mut self, row: usize) {
        self.explorer.selected_record_index = self.explorer.search.as_ref().and_then(|search| {
            (row < self.explorer.page().len())
                .then(|| self.explorer.page_index * search.query.page_size.clamp(1, 1_000) + row)
        });
    }

    fn open_send_dialog(&mut self) {
        if self.explorer.send_draft.is_some() {
            return;
        }
        let Some(detail) = self.explorer.detail.as_ref() else {
            return;
        };
        if detail.partitions.is_empty() {
            return;
        }
        self.explorer.send_draft = Some(SendRequest {
            topic: detail.name.clone(),
            partition: None,
            key: None,
            value: String::new(),
        });
        self.explorer.send_validation_error = None;
        self.explorer.delivery_notice = None;
    }

    fn close_send_dialog(&mut self) {
        self.cancel_explorer(ExplorerOperation::Delivery);
        self.explorer.send_draft = None;
        self.explorer.send_validation_error = None;
        self.explorer.delivery_notice = None;
    }

    fn dismiss_delivery_notice(&mut self) {
        self.explorer.delivery_notice = None;
    }

    fn begin_delivery(&mut self) -> Option<(ExplorerWork, SendRequest)> {
        if self.explorer.delivery_pending {
            return None;
        }
        let request = self.explorer.send_draft.clone()?;
        self.explorer.send_validation_error = None;
        self.explorer.delivery_notice = None;
        if validate_send(&request).is_err() {
            self.explorer.send_validation_error = Some("Message value is required".into());
            return None;
        }
        let valid_topic = self.explorer.detail.as_ref().is_some_and(|detail| {
            detail.name == request.topic
                && self.explorer.selected_topic.as_ref() == Some(&request.topic)
                && !detail.partitions.is_empty()
                && request.partition.is_none_or(|selected| {
                    detail
                        .partitions
                        .iter()
                        .any(|partition| partition.id == selected)
                })
        });
        if !valid_topic {
            self.explorer.send_validation_error =
                Some("Select an available topic partition".into());
            return None;
        }
        let work = self.begin_explorer(ExplorerOperation::Delivery)?;
        Some((work, request))
    }

    fn update_elapsed(
        &mut self,
        operation: ExplorerOperation,
        identity: ExplorerRequest,
        elapsed_ms: u64,
    ) -> bool {
        if !self.accepts(operation, identity) {
            return false;
        }
        self.explorer.elapsed(operation, elapsed_ms);
        true
    }

    fn apply_explorer(&mut self, identity: ExplorerRequest, result: ExplorerCompletion) -> bool {
        let operation = result.operation();
        if !self.accepts(operation, identity) {
            return false;
        }
        let elapsed_ms = self
            .explorer_lifecycle
            .session
            .as_ref()
            .and_then(|session| session.slot(operation).as_ref())
            .map_or(0, |work| elapsed_millis(work.started));
        self.explorer.elapsed(operation, elapsed_ms);
        self.cancel_explorer(operation);
        match result {
            ExplorerCompletion::Topics(Ok(topics)) => {
                // A successful refresh makes the next detail selection reload current metadata.
                if let Some(session) = self.explorer_lifecycle.session.as_mut() {
                    session.details = Arc::new(HashMap::new());
                }
                let removed = self
                    .explorer
                    .selected_topic
                    .as_ref()
                    .is_some_and(|selected| !topics.iter().any(|topic| &topic.name == selected));
                if removed {
                    self.clear_topic();
                    self.explorer.topic_unavailable = true;
                }
                self.topic_count = Some(topics.len());
                self.explorer.topics = topics;
                self.explorer.topic_error = None;
            }
            ExplorerCompletion::Topics(Err(ExplorerKafkaError::Cancelled)) => {}
            ExplorerCompletion::Topics(Err(error)) => {
                self.explorer.topic_error = Some(error.to_string());
            }
            ExplorerCompletion::Metadata(Ok(detail)) => {
                if self.explorer.selected_topic.as_ref() == Some(&detail.name) {
                    if let Some(session) = self.explorer_lifecycle.session.as_mut() {
                        Arc::make_mut(&mut session.details)
                            .insert(detail.name.clone(), detail.clone());
                    }
                    self.explorer.detail = Some(detail);
                    self.explorer.detail_error = None;
                }
            }
            ExplorerCompletion::Metadata(Err(ExplorerKafkaError::Cancelled)) => {}
            ExplorerCompletion::Metadata(Err(error)) => {
                self.explorer.detail_error = Some(error.to_string());
            }
            ExplorerCompletion::Search(Ok(search)) => {
                self.explorer.search = Some(Arc::new(search));
                self.explorer.page_index = 0;
                self.explorer.selected_record_index = None;
                self.explorer.search_error = None;
            }
            ExplorerCompletion::Search(Err(ExplorerKafkaError::Cancelled)) => {}
            ExplorerCompletion::Search(Err(error)) => {
                self.explorer.search_error = Some(error.to_string());
            }
            ExplorerCompletion::Delivery {
                result: Err(ExplorerKafkaError::Cancelled),
                ..
            } => {}
            ExplorerCompletion::Delivery {
                topic,
                requested_partition,
                result,
            } => {
                self.explorer.delivery_notice = Some(match result {
                    Ok(delivery) => DeliveryNotice {
                        success: true,
                        topic,
                        requested_partition,
                        delivered_partition: Some(delivery.partition),
                        diagnostic: None,
                    },
                    Err(error) => DeliveryNotice {
                        success: false,
                        topic,
                        requested_partition,
                        delivered_partition: None,
                        diagnostic: Some(error.to_string()),
                    },
                });
            }
        }
        true
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u64::MAX as u128) as u64
}

#[derive(Debug, thiserror::Error)]
enum ControllerError {
    #[error("A connection with this display name already exists")]
    DuplicateName,
    #[error("Connection profile is invalid")]
    InvalidProfile,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Bundle(#[from] BundleError),
    #[error("Connection worker is unavailable")]
    WorkerUnavailable,
    #[error("Portable file operation failed: {0}")]
    PortableFile(String),
}

fn upsert_profile(
    profiles: &[ConnectionProfile],
    profile: ConnectionProfile,
) -> Result<Vec<ConnectionProfile>, ControllerError> {
    if profile.id.trim().is_empty() || profile.validate().is_err() {
        return Err(ControllerError::InvalidProfile);
    }
    if profiles
        .iter()
        .any(|existing| existing.id != profile.id && existing.name == profile.name)
    {
        return Err(ControllerError::DuplicateName);
    }
    let mut updated = profiles.to_vec();
    if let Some(existing) = updated
        .iter_mut()
        .find(|existing| existing.id == profile.id)
    {
        *existing = profile;
    } else {
        updated.push(profile);
    }
    Ok(updated)
}

struct StorageSession {
    store: ProfileStore,
    profiles: Vec<ConnectionProfile>,
    pending_import: Option<PendingImport>,
}

struct PendingImport {
    bundle: profile_bundle::PortableBundle,
    // Local identity -> portable identity chosen to replace it. Keep the
    // portable IDs unchanged until validation resolves every conflict.
    replacements: std::collections::HashMap<String, String>,
    conflict: Option<profile_bundle::ImportConflict>,
}

pub enum ImportResolution {
    Rename(String),
    Replace,
}

impl StorageSession {
    fn resolve_import(&mut self, resolution: ImportResolution) -> Result<(), ControllerError> {
        let pending = self
            .pending_import
            .as_mut()
            .ok_or(ControllerError::InvalidProfile)?;
        let conflict = pending
            .conflict
            .as_ref()
            .ok_or(ControllerError::InvalidProfile)?;
        let local = self.profiles.iter().any(|profile| {
            profile.id == conflict.existing_id && profile.name == conflict.incoming_name
        }) && !pending.replacements.contains_key(&conflict.existing_id);
        let prior = pending.bundle.profiles.iter().position(|profile| {
            profile.id == conflict.existing_id && profile.name == conflict.incoming_name
        });
        let incoming = pending
            .bundle
            .profiles
            .iter()
            .enumerate()
            .find(|(index, profile)| {
                profile.name == conflict.incoming_name
                    && (local || prior.is_some_and(|prior| *index > prior))
            })
            .map(|(index, _)| index)
            .ok_or(ControllerError::InvalidProfile)?;
        match resolution {
            ImportResolution::Rename(name) => {
                if name.trim().is_empty() {
                    return Err(BundleError::Conflict(profile_bundle::ImportConflict {
                        incoming_name: conflict.incoming_name.clone(),
                        existing_id: conflict.existing_id.clone(),
                    })
                    .into());
                }
                pending.bundle.profiles[incoming].name = name;
            }
            ImportResolution::Replace => {
                if local {
                    pending.replacements.insert(
                        conflict.existing_id.clone(),
                        pending.bundle.profiles[incoming].id.clone(),
                    );
                } else if let Some(prior) = prior {
                    let prior_id = &pending.bundle.profiles[prior].id;
                    for chosen_id in pending.replacements.values_mut() {
                        if chosen_id == prior_id {
                            *chosen_id = pending.bundle.profiles[incoming].id.clone();
                        }
                    }
                    pending.bundle.profiles.remove(prior);
                }
            }
        }
        self.finish_import()
    }

    fn open() -> Result<Self, ControllerError> {
        let store = ProfileStore::open()?;
        let profiles = store
            .load()?
            .into_iter()
            .map(ConnectionProfile::from)
            .collect();
        Ok(Self {
            store,
            profiles,
            pending_import: None,
        })
    }

    fn persist(&mut self, profiles: Vec<ConnectionProfile>) -> Result<(), ControllerError> {
        self.store.save(
            &profiles
                .iter()
                .map(PersistedProfile::from)
                .collect::<Vec<_>>(),
        )?;
        self.profiles = profiles;
        Ok(())
    }

    fn save(&mut self, profile: ConnectionProfile) -> Result<(), ControllerError> {
        self.persist(upsert_profile(&self.profiles, profile)?)
    }

    fn delete(&mut self, id: &str) -> Result<(), ControllerError> {
        let profiles = self
            .profiles
            .iter()
            .filter(|profile| profile.id != id)
            .cloned()
            .collect();
        self.persist(profiles)
    }

    fn import(&mut self, json: &str) -> Result<(), ControllerError> {
        self.pending_import = None;
        let bundle = serde_json::from_str(json).map_err(|_| BundleError::InvalidSchema)?;
        self.pending_import = Some(PendingImport {
            bundle,
            replacements: Default::default(),
            conflict: None,
        });
        self.finish_import()
    }

    fn finish_import(&mut self) -> Result<(), ControllerError> {
        let pending = self
            .pending_import
            .as_mut()
            .ok_or(ControllerError::InvalidProfile)?;
        let json = Secret::new(
            serde_json::to_string(&pending.bundle).map_err(|_| BundleError::InvalidSchema)?,
        );
        let existing: Vec<_> = self
            .profiles
            .iter()
            .filter(|profile| !pending.replacements.contains_key(&profile.id))
            .cloned()
            .collect();
        let mut imported =
            match profile_bundle::import_bundle(json.expose(), &self.store, &existing) {
                Ok(imported) => imported,
                Err(BundleError::Conflict(conflict)) => {
                    pending.conflict = Some(profile_bundle::ImportConflict {
                        incoming_name: conflict.incoming_name.clone(),
                        existing_id: conflict.existing_id.clone(),
                    });
                    return Err(BundleError::Conflict(conflict).into());
                }
                Err(error) => {
                    self.pending_import = None;
                    return Err(error.into());
                }
            };
        let replacements = self
            .pending_import
            .take()
            .expect("pending validated import")
            .replacements;
        // Reserve every explicit replacement identity before considering the
        // remaining portable IDs, regardless of incoming profile order.
        let mut ids: std::collections::HashSet<_> = existing
            .iter()
            .map(|profile| profile.id.clone())
            .chain(replacements.keys().cloned())
            .collect();
        for profile in &mut imported {
            if let Some((local_id, _)) = replacements
                .iter()
                .find(|(_, incoming_id)| *incoming_id == &profile.id)
            {
                profile.id = local_id.clone();
                continue;
            }
            // A portable ID must not silently replace an unrelated local connection.
            while !ids.insert(profile.id.clone()) {
                profile.id = uuid::Uuid::new_v4().to_string();
            }
        }
        let mut updated = existing;
        updated.extend(imported.iter().cloned());
        if let Err(error) = self.persist(updated) {
            cleanup_import(&self.store, &imported);
            return Err(error);
        }
        Ok(())
    }
}

/// Only profiles just returned by import_bundle may reach this cleanup boundary.
fn cleanup_import(store: &ProfileStore, imported: &[ConnectionProfile]) {
    let Ok(root) = store.certificates_dir().canonicalize() else {
        return;
    };
    let mut batches = std::collections::HashSet::new();
    for profile in imported {
        let Some(tls) = profile.tls() else {
            continue;
        };
        let path = std::path::Path::new(&tls.ca_path);
        let Some(batch) = path.parent().and_then(std::path::Path::parent) else {
            continue;
        };
        let Ok(batch) = batch.canonicalize() else {
            continue;
        };
        let generated = batch
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("import-"))
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok());
        if generated && batch.parent() == Some(root.as_path()) {
            batches.insert(batch);
        }
    }
    for batch in batches {
        // Validated absolute targets are individual newly generated import batches.
        let _ = std::fs::remove_dir_all(batch);
    }
}

enum StorageCommand {
    Save(ConnectionProfile),
    Delete(String),
    ImportFile,
    ExportFile,
    ResolveImport(ImportResolution),
    CancelImport,
}

/// Invoked exclusively by the blocking storage worker. The UTF-16 buffers live
/// throughout the synchronous native call; cancellation does not change state.
fn native_bundle_path(save: bool) -> Result<Option<std::path::PathBuf>, ControllerError> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Controls::Dialogs::{
        CommDlgExtendedError, GetOpenFileNameW, GetSaveFileNameW, OFN_FILEMUSTEXIST,
        OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    let filter: Vec<u16> = "Connection bundles (*.json)\0*.json\0All files (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = if save {
        "Export connections\0"
    } else {
        "Import connections\0"
    }
    .encode_utf16()
    .collect();
    let extension: Vec<u16> = "json\0".encode_utf16().collect();
    let mut file = vec![0u16; 32768];
    if save {
        for (slot, value) in file.iter_mut().zip("connections.json".encode_utf16()) {
            *slot = value;
        }
    }
    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        lpstrFilter: filter.as_ptr(),
        nFilterIndex: 1,
        lpstrFile: file.as_mut_ptr(),
        nMaxFile: file.len() as u32,
        lpstrTitle: title.as_ptr(),
        lpstrDefExt: extension.as_ptr(),
        Flags: OFN_NOCHANGEDIR
            | OFN_PATHMUSTEXIST
            | if save {
                OFN_OVERWRITEPROMPT
            } else {
                OFN_FILEMUSTEXIST
            },
        ..Default::default()
    };
    // No Slint handle crosses threads. With no owner HWND these are native
    // top-level dialogs; the Manager stays disabled until the worker completes.
    let accepted = unsafe {
        if save {
            GetSaveFileNameW(&mut dialog)
        } else {
            GetOpenFileNameW(&mut dialog)
        }
    };
    if accepted == 0 {
        let code = unsafe { CommDlgExtendedError() };
        return if code == 0 {
            Ok(None)
        } else {
            Err(ControllerError::PortableFile(format!(
                "Native file dialog error 0x{code:08X}"
            )))
        };
    }
    let length = file
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| ControllerError::PortableFile("Native file path was too long".into()))?;
    Ok(Some(std::ffi::OsString::from_wide(&file[..length]).into()))
}

enum StorageUpdate {
    Profiles(Vec<ConnectionProfile>),
}

async fn run_storage_worker(
    runtime: Handle,
    mut receiver: mpsc::UnboundedReceiver<StorageCommand>,
    open: impl FnOnce() -> Result<StorageSession, ControllerError> + Send + 'static,
    completed: impl Fn(Result<StorageUpdate, ControllerError>) + Send,
) {
    let mut session = match runtime.spawn_blocking(open).await {
        Ok(Ok(session)) => {
            completed(Ok(StorageUpdate::Profiles(session.profiles.clone())));
            Some(session)
        }
        Ok(Err(error)) => {
            completed(Err(error));
            None
        }
        Err(_) => {
            completed(Err(ControllerError::WorkerUnavailable));
            None
        }
    };
    // Awaiting one blocking job at a time preserves save/edit/import order.
    // Waiting for commands is async, so idle shutdown cannot strand a blocking worker.
    while let Some(command) = receiver.recv().await {
        let Some(mut available) = session.take() else {
            completed(Err(ControllerError::WorkerUnavailable));
            continue;
        };
        match runtime
            .spawn_blocking(move || {
                let result = match command {
                    StorageCommand::Save(profile) => available
                        .save(profile)
                        .map(|()| StorageUpdate::Profiles(available.profiles.clone())),
                    StorageCommand::Delete(id) => available
                        .delete(&id)
                        .map(|()| StorageUpdate::Profiles(available.profiles.clone())),
                    StorageCommand::ImportFile => (|| {
                        if let Some(path) = native_bundle_path(false)? {
                            let json =
                                Secret::new(std::fs::read_to_string(path).map_err(|error| {
                                    ControllerError::PortableFile(format!(
                                        "Could not read JSON ({:?})",
                                        error.kind()
                                    ))
                                })?);
                            available.import(json.expose())?;
                        }
                        Ok(StorageUpdate::Profiles(available.profiles.clone()))
                    })(),
                    StorageCommand::ExportFile => (|| {
                        if let Some(path) = native_bundle_path(true)? {
                            let json =
                                Secret::new(profile_bundle::export_bundle(&available.profiles)?);
                            std::fs::write(path, json.expose()).map_err(|error| {
                                ControllerError::PortableFile(format!(
                                    "Could not save JSON ({:?})",
                                    error.kind()
                                ))
                            })?;
                        }
                        Ok(StorageUpdate::Profiles(available.profiles.clone()))
                    })(),
                    StorageCommand::ResolveImport(resolution) => available
                        .resolve_import(resolution)
                        .map(|()| StorageUpdate::Profiles(available.profiles.clone())),
                    StorageCommand::CancelImport => {
                        available.pending_import = None;
                        Ok(StorageUpdate::Profiles(available.profiles.clone()))
                    }
                };
                (available, result)
            })
            .await
        {
            Ok((returned, result)) => {
                session = Some(returned);
                completed(result);
            }
            Err(_) => completed(Err(ControllerError::WorkerUnavailable)),
        }
    }
}

type UpdateUi = dyn Fn(&MainWindow, &ControllerSnapshot) + Send + Sync;

#[derive(Clone)]
struct UiBoundary {
    window: slint::Weak<MainWindow>,
    state: Arc<Mutex<ControllerSnapshot>>,
    update: Arc<UpdateUi>,
}

impl UiBoundary {
    fn notify(&self) {
        if let Some(window) = self.window.upgrade() {
            let snapshot = self.state.lock().expect("controller state").clone();
            (self.update)(&window, &snapshot);
        }
    }

    fn post_storage(&self, result: Result<StorageUpdate, ControllerError>) {
        let boundary = self.clone();
        let _ = slint::invoke_from_event_loop(move || {
            {
                let mut state = boundary.state.lock().expect("controller state");
                state.pending_storage = state.pending_storage.saturating_sub(1);
                state.storage_error = None;
                state.import_conflict = None;
                match result {
                    Ok(StorageUpdate::Profiles(profiles)) => state.profiles = profiles,
                    Err(error) => {
                        state.storage_error = Some(error.to_string());
                        if let ControllerError::Bundle(BundleError::Conflict(conflict)) = error {
                            state.import_conflict =
                                Some((conflict.incoming_name, conflict.existing_id));
                        }
                    }
                }
            }
            boundary.notify();
        });
    }
}

/// Owns the Rust callback actions. All methods are called on Slint's event-loop
/// thread; blocking jobs receive owned profiles and publish through UiBoundary.
#[derive(Clone)]
pub struct ConnectionController {
    ui: UiBoundary,
    runtime: Handle,
    storage: mpsc::UnboundedSender<StorageCommand>,
}

impl ConnectionController {
    /// Task 6 binds this update boundary to its fields and registers callbacks
    /// with these action methods. No legacy callback is replaced here.
    pub fn install(
        window: &MainWindow,
        runtime: Handle,
        update: impl Fn(&MainWindow, &ControllerSnapshot) + Send + Sync + 'static,
    ) -> Self {
        let ui = UiBoundary {
            window: window.as_weak(),
            state: Arc::new(Mutex::new(ControllerSnapshot {
                pending_storage: 1,
                ..ControllerSnapshot::default()
            })),
            update: Arc::new(update),
        };
        let (storage, receiver) = mpsc::unbounded_channel();
        let worker_ui = ui.clone();
        let worker_runtime = runtime.clone();
        runtime.spawn(run_storage_worker(
            worker_runtime,
            receiver,
            StorageSession::open,
            move |result| worker_ui.post_storage(result),
        ));
        let controller = Self {
            ui,
            runtime,
            storage,
        };
        controller.ui.notify();
        controller
    }

    pub fn snapshot(&self) -> ControllerSnapshot {
        self.ui.state.lock().expect("controller state").clone()
    }

    pub fn select_profile(&self, id: Option<String>) {
        {
            let mut state = self.ui.state.lock().expect("controller state");
            state.select_profile_state(id);
        }
        self.ui.notify();
    }

    pub fn add_profile(&self) {
        self.select_profile(None);
    }

    pub fn show_manager(&self) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .show_manager();
        self.ui.notify();
    }

    pub fn delete_profile(&self, id: String) {
        let exists = {
            let mut state = self.ui.state.lock().expect("controller state");
            let exists = state.profiles.iter().any(|profile| profile.id == id);
            if exists {
                state.remove_profile_state(&id);
            }
            exists
        };
        if exists {
            self.dispatch_storage(StorageCommand::Delete(id));
        }
    }

    pub fn import_file(&self) {
        self.dispatch_storage(StorageCommand::ImportFile);
    }

    /// Called only after the visible plaintext-secret confirmation is accepted.
    pub fn export_file(&self) {
        self.dispatch_storage(StorageCommand::ExportFile);
    }

    pub fn resolve_import(&self, resolution: ImportResolution) {
        self.dispatch_storage(StorageCommand::ResolveImport(resolution));
    }

    pub fn cancel_import(&self) {
        self.dispatch_storage(StorageCommand::CancelImport);
    }

    fn dispatch_storage(&self, command: StorageCommand) {
        {
            let mut state = self.ui.state.lock().expect("controller state");
            state.pending_storage += 1;
            state.storage_error = None;
            state.import_conflict = None;
            if self.storage.send(command).is_err() {
                state.pending_storage = 0;
                state.storage_error = Some(ControllerError::WorkerUnavailable.to_string());
            }
        }
        self.ui.notify();
    }

    fn validate(&self, profile: &ConnectionProfile) -> bool {
        let valid = {
            let mut state = self.ui.state.lock().expect("controller state");
            state.validation_errors = profile.validate().err().unwrap_or_default();
            if !state.validation_errors.is_empty() {
                state.operation.cancel();
            }
            state.validation_errors.is_empty()
        };
        if !valid {
            self.ui.notify();
        }
        valid
    }

    pub fn test_connection(&self, profile: ConnectionProfile) {
        self.probe(profile, OperationStatus::Testing);
    }
    pub fn connect(&self, profile: ConnectionProfile) {
        self.probe(profile, OperationStatus::Connecting);
    }

    pub fn refresh_topics(&self) {
        let prepared = {
            let mut state = self.ui.state.lock().expect("controller state");
            state
                .active_profile
                .clone()
                .and_then(|profile| state.begin_refresh().map(|work| (profile, work)))
        };
        self.ui.notify();
        let Some((profile, work)) = prepared else {
            return;
        };
        let cancel = work.cancel.clone();
        self.launch_explorer(
            work,
            ExplorerCompletion::Topics(Err(explorer_worker_error())),
            move || ExplorerCompletion::Topics(load_topics(&profile, &cancel)),
        );
    }

    pub fn filter_topics(&self, filter: String) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .explorer
            .topic_filter = filter;
        self.ui.notify();
    }

    pub fn select_topic(&self, topic: String) {
        let prepared = {
            let mut state = self.ui.state.lock().expect("controller state");
            state.active_profile.clone().and_then(|profile| {
                state
                    .select_topic_state(topic.clone())
                    .map(|work| (profile, work))
            })
        };
        self.ui.notify();
        let Some((profile, work)) = prepared else {
            return;
        };
        let cancel = work.cancel.clone();
        self.launch_explorer(
            work,
            ExplorerCompletion::Metadata(Err(explorer_worker_error())),
            move || ExplorerCompletion::Metadata(load_topic_detail(&profile, &topic, &cancel)),
        );
    }

    pub fn search_form_changed(&self, query: SearchQuery) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .search_form_changed(query);
        self.ui.notify();
    }

    pub fn search_messages(&self, query: SearchQuery) {
        let prepared = {
            let mut state = self.ui.state.lock().expect("controller state");
            state.active_profile.clone().and_then(|profile| {
                state
                    .begin_search(query)
                    .map(|prepared| (profile, prepared))
            })
        };
        self.ui.notify();
        let Some((profile, (work, query, partitions, topic))) = prepared else {
            return;
        };
        let cancel = work.cancel.clone();
        self.launch_explorer(
            work,
            ExplorerCompletion::Search(Err(explorer_worker_error())),
            move || {
                let result = search_records(&profile, &topic, &partitions, &query, &cancel);
                search_completion(result, query, &cancel)
            },
        );
    }

    pub fn cancel_search(&self) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .cancel_search();
        self.ui.notify();
    }

    pub fn change_page(&self, delta: i32) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .change_page(delta);
        self.ui.notify();
    }

    pub fn select_record(&self, row: usize) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .select_record(row);
        self.ui.notify();
    }

    pub fn open_send_dialog(&self) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .open_send_dialog();
        self.ui.notify();
    }

    pub fn update_send_form(&self, partition: Option<i32>, key: Option<String>, value: String) {
        {
            let mut state = self.ui.state.lock().expect("controller state");
            if let Some(draft) = state.explorer.send_draft.as_mut() {
                draft.partition = partition;
                draft.key = key;
                draft.value = value;
                state.explorer.send_validation_error = None;
            }
        }
        self.ui.notify();
    }

    pub fn close_send_dialog(&self) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .close_send_dialog();
        self.ui.notify();
    }

    pub fn dismiss_delivery_notice(&self) {
        self.ui
            .state
            .lock()
            .expect("controller state")
            .dismiss_delivery_notice();
        self.ui.notify();
    }

    pub fn send_message(&self) {
        let prepared = {
            let mut state = self.ui.state.lock().expect("controller state");
            state
                .active_profile
                .clone()
                .and_then(|profile| state.begin_delivery().map(|prepared| (profile, prepared)))
        };
        self.ui.notify();
        let Some((profile, (work, request))) = prepared else {
            return;
        };
        let cancel = work.cancel.clone();
        let fallback = ExplorerCompletion::Delivery {
            topic: request.topic.clone(),
            requested_partition: request.partition,
            result: Err(explorer_worker_error()),
        };
        self.launch_explorer(work, fallback, move || ExplorerCompletion::Delivery {
            result: send_record(&profile, &request, &cancel),
            topic: request.topic,
            requested_partition: request.partition,
        });
    }

    fn launch_explorer(
        &self,
        work: ExplorerWork,
        fallback: ExplorerCompletion,
        run: impl FnOnce() -> ExplorerCompletion + Send + 'static,
    ) {
        let operation = fallback.operation();
        self.start_elapsed_timer(operation, work.clone());
        let ui = self.ui.clone();
        let job = self.runtime.spawn_blocking(run);
        self.runtime.spawn(async move {
            let result = resolve_explorer_worker(job.await, fallback);
            if !ui
                .state
                .lock()
                .expect("controller state")
                .accepts(operation, work.identity)
            {
                return;
            }
            let _ = slint::invoke_from_event_loop(move || {
                let applied = ui
                    .state
                    .lock()
                    .expect("controller state")
                    .apply_explorer(work.identity, result);
                if applied {
                    ui.notify();
                }
            });
        });
    }

    fn start_elapsed_timer(&self, operation: ExplorerOperation, work: ExplorerWork) {
        let ui = self.ui.clone();
        self.runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = work.cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                }
                let boundary = ui.clone();
                let identity = work.identity;
                let elapsed_ms = elapsed_millis(work.started);
                if slint::invoke_from_event_loop(move || {
                    let applied = boundary
                        .state
                        .lock()
                        .expect("controller state")
                        .update_elapsed(operation, identity, elapsed_ms);
                    if applied {
                        boundary.notify();
                    }
                })
                .is_err()
                {
                    work.cancel.cancel();
                    break;
                }
            }
        });
    }

    fn probe(&self, profile: ConnectionProfile, status: OperationStatus) {
        if !self.validate(&profile) {
            return;
        }
        let request = {
            let mut state = self.ui.state.lock().expect("controller state");
            let Some(request) = state.operation.begin(profile.id.clone(), status) else {
                return;
            };
            state.draft_profile = Some(profile.clone());
            state.probe_error = None;
            state.topic_count = None;
            request
        };
        self.ui.notify();
        let ui = self.ui.clone();
        let storage = self.storage.clone();
        let controller = self.clone();
        let job = self.runtime.spawn_blocking({
            let profile = profile.clone();
            move || probe_connection(&profile)
        });
        self.runtime.spawn(async move {
            let result = job.await.unwrap_or_else(|_| {
                Err(ConnectionProbeError::from_diagnostic(
                    "Connection worker is unavailable".into(),
                ))
            });
            if !ui
                .state
                .lock()
                .expect("controller state")
                .operation
                .is_current(&request)
            {
                return;
            }
            let _ = slint::invoke_from_event_loop(move || {
                let save_profile = result.is_ok().then_some(profile);
                let applied = ui
                    .state
                    .lock()
                    .expect("controller state")
                    .apply_probe(&request, result);
                if applied {
                    let connected =
                        save_profile.is_some() && request.status == OperationStatus::Connecting;
                    if let Some(profile) = save_profile {
                        ui.state.lock().expect("controller state").pending_storage += 1;
                        let _ = storage.send(StorageCommand::Save(profile));
                    }
                    ui.notify();
                    if connected {
                        controller.refresh_topics();
                    }
                }
            });
        });
    }
}

fn explorer_worker_error() -> ExplorerKafkaError {
    ExplorerKafkaError::InvalidInput("Kafka worker is unavailable")
}

fn resolve_explorer_worker(
    result: Result<ExplorerCompletion, tokio::task::JoinError>,
    fallback: ExplorerCompletion,
) -> ExplorerCompletion {
    result.unwrap_or(fallback)
}

fn search_completion(
    result: crate::kafka::client::SearchKafkaResult,
    query: SearchQuery,
    cancel: &CancellationToken,
) -> ExplorerCompletion {
    if result.cancelled || cancel.is_cancelled() {
        return ExplorerCompletion::Search(Err(ExplorerKafkaError::Cancelled));
    }
    // Filtering and sorting may process many partitions, so call this only in a blocking worker.
    let result = filter_and_page_cancellable(result.records, query, || cancel.is_cancelled())
        .map_err(|_| ExplorerKafkaError::InvalidInput("Invalid timestamp range"))
        .and_then(|search| match search {
            Some(mut search) => {
                search.warnings = result.warnings;
                search.failures = result.failed_partitions;
                Ok(search)
            }
            None => Err(ExplorerKafkaError::Cancelled),
        });
    if cancel.is_cancelled() {
        ExplorerCompletion::Search(Err(ExplorerKafkaError::Cancelled))
    } else {
        ExplorerCompletion::Search(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_snapshot(id: &str) -> ControllerSnapshot {
        let mut state = ControllerSnapshot::default();
        state.draft_profile = Some(profile(id, id));
        let request = state
            .operation
            .begin(id.into(), OperationStatus::Connecting)
            .unwrap();
        assert!(state.apply_probe(&request, Ok(2)));
        state
    }

    fn topics(names: &[&str]) -> Vec<TopicSummary> {
        names
            .iter()
            .map(|name| TopicSummary {
                name: (*name).into(),
                partition_count: 1,
            })
            .collect()
    }

    fn topic_detail(name: &str) -> TopicDetail {
        TopicDetail {
            name: name.into(),
            partitions: vec![crate::explorer::PartitionDetail {
                id: 2,
                leader: 1,
                replicas: vec![1],
                isr: vec![1],
                low_offset: Some(0),
                high_offset: Some(10),
            }],
            configuration: None,
            configuration_error: Some("Configuration unavailable".into()),
        }
    }

    fn selected_snapshot() -> ControllerSnapshot {
        let mut state = connected_snapshot("one");
        let refresh = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            refresh.identity,
            ExplorerCompletion::Topics(Ok(topics(&["orders", "other"]))),
        ));
        let metadata = state.begin_metadata("orders".into()).unwrap();
        assert!(state.apply_explorer(
            metadata.identity,
            ExplorerCompletion::Metadata(Ok(topic_detail("orders"))),
        ));
        state
    }

    #[test]
    fn a_profile_switch_cancels_every_operation_and_rejects_old_session_results() {
        let mut state = selected_snapshot();
        let refresh = state.begin_refresh().unwrap();
        let search = state.begin_search(SearchQuery::default()).unwrap().0;
        state.open_send_dialog();
        state.explorer.send_draft.as_mut().unwrap().value = "private payload".into();
        let delivery = state.begin_delivery().unwrap().0;
        let old_session = refresh.identity.session_id;

        state.select_profile_state(Some("two".into()));

        assert!(refresh.cancel.is_cancelled());
        assert!(search.cancel.is_cancelled());
        assert!(delivery.cancel.is_cancelled());
        assert!(state.explorer_lifecycle.session.is_none());
        assert!(state.explorer.topics.is_empty());
        assert!(state.explorer.search.is_none());
        assert!(state.explorer.send_draft.is_none());
        assert_eq!(state.operation.route, Route::Manager);
        assert_eq!(state.operation.active_profile_id, None);

        state.draft_profile = Some(profile("two", "two"));
        let request = state
            .operation
            .begin("two".into(), OperationStatus::Connecting)
            .unwrap();
        assert!(state.apply_probe(&request, Ok(1)));
        let current = state.begin_refresh().unwrap();
        assert!(current.identity.session_id > old_session);
        assert!(!state.apply_explorer(
            refresh.identity,
            ExplorerCompletion::Topics(Ok(topics(&["stale"]))),
        ));
        assert!(state.apply_explorer(
            current.identity,
            ExplorerCompletion::Topics(Ok(topics(&["current"]))),
        ));
        assert_eq!(state.explorer.topics[0].name, "current");
    }

    #[test]
    fn refresh_replaces_cache_only_after_current_success_and_keeps_cache_on_failure() {
        let mut state = selected_snapshot();
        let older = state.begin_refresh().unwrap();
        let current = state.begin_refresh().unwrap();
        assert!(older.cancel.is_cancelled());
        assert_eq!(state.explorer.topics.len(), 2);
        assert!(!state.apply_explorer(
            older.identity,
            ExplorerCompletion::Topics(Ok(topics(&["stale"]))),
        ));
        assert!(state.apply_explorer(
            current.identity,
            ExplorerCompletion::Topics(Err(ExplorerKafkaError::Timeout("Load topics"))),
        ));
        assert_eq!(state.explorer.topics.len(), 2);
        assert!(state.explorer.topic_error.is_some());
        assert!(!state.explorer.refreshing);
        let next = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            next.identity,
            ExplorerCompletion::Topics(Ok(topics(&["orders", "new"]))),
        ));
        assert_eq!(state.explorer.topics[1].name, "new");
        assert!(state.explorer.topic_error.is_none());
    }

    #[test]
    fn removing_selected_topic_cancels_work_and_shows_unavailable_without_reselection() {
        let mut state = selected_snapshot();
        let search = state.begin_search(SearchQuery::default()).unwrap().0;
        let refresh = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            refresh.identity,
            ExplorerCompletion::Topics(Ok(topics(&["other"]))),
        ));
        assert!(search.cancel.is_cancelled());
        assert_eq!(state.explorer.selected_topic, None);
        assert!(state.explorer.topic_unavailable);
        assert!(state.explorer.detail.is_none());
        assert!(state.explorer.search.is_none());
        assert!(!state.apply_explorer(
            search.identity,
            ExplorerCompletion::Search(Ok(empty_search())),
        ));
        assert_eq!(state.explorer.topics[0].name, "other");
    }

    #[test]
    fn switching_topics_cancels_metadata_and_rejects_its_completion() {
        let mut state = selected_snapshot();
        let old = state.begin_metadata("orders".into()).unwrap();
        let current = state.begin_metadata("other".into()).unwrap();
        assert!(old.cancel.is_cancelled());
        assert!(!state.apply_explorer(
            old.identity,
            ExplorerCompletion::Metadata(Ok(topic_detail("orders"))),
        ));
        assert!(state.explorer.detail.is_none());
        assert!(state.apply_explorer(
            current.identity,
            ExplorerCompletion::Metadata(Ok(topic_detail("other"))),
        ));
        assert_eq!(state.explorer.detail.as_ref().unwrap().name, "other");
        assert!(state
            .explorer
            .detail
            .as_ref()
            .unwrap()
            .configuration_error
            .is_some());
    }

    #[test]
    fn leaving_workspace_cancels_metadata_and_clears_active_profile() {
        let mut state = selected_snapshot();
        let metadata = state.begin_metadata("orders".into()).unwrap();
        state.show_manager();
        assert!(metadata.cancel.is_cancelled());
        assert!(state.explorer_lifecycle.session.is_none());
        assert!(state.active_profile.is_none());
        assert!(state.operation.active_profile_id.is_none());
        assert!(!state.apply_explorer(
            metadata.identity,
            ExplorerCompletion::Metadata(Ok(topic_detail("orders"))),
        ));
    }

    #[test]
    fn deleting_active_profile_cancels_explorer_before_profile_state_is_cleared() {
        let mut state = selected_snapshot();
        let refresh = state.begin_refresh().unwrap();
        state.remove_profile_state("one");
        assert!(refresh.cancel.is_cancelled());
        assert!(state.explorer_lifecycle.session.is_none());
        assert_eq!(state.operation.route, Route::Manager);
        assert!(state.active_profile.is_none());
    }

    fn empty_search() -> SearchSnapshot {
        SearchSnapshot {
            query: SearchQuery::default(),
            records: Vec::new(),
            warnings: Vec::new(),
            failures: Vec::new(),
        }
    }

    #[test]
    fn accepted_search_keeps_adapter_warnings_and_partition_failures_after_filtering() {
        let mut state = selected_snapshot();
        let query = SearchQuery {
            value_contains: "match".into(),
            ..SearchQuery::default()
        };
        let work = state.begin_search(query.clone()).unwrap().0;
        let adapter_result = crate::kafka::client::SearchKafkaResult {
            records: vec![
                RecordData {
                    partition: 2,
                    offset: 7,
                    timestamp: Some(12),
                    key: None,
                    value: "match".into(),
                    headers: Vec::new(),
                },
                RecordData {
                    partition: 2,
                    offset: 8,
                    timestamp: Some(13),
                    key: None,
                    value: "discard".into(),
                    headers: Vec::new(),
                },
            ],
            warnings: vec![crate::explorer::SearchWarning {
                partition: 2,
                scanned_records: 10_000,
            }],
            failed_partitions: vec![crate::explorer::SearchFailure {
                partition: 3,
                diagnostic: "Read records: timed out".into(),
            }],
            cancelled: false,
        };
        let result = search_completion(adapter_result, query, &work.cancel);
        assert!(state.apply_explorer(work.identity, result));
        let search = state.explorer.search.as_ref().unwrap();
        assert_eq!(search.records.len(), 1);
        assert_eq!(search.records[0].offset, 7);
        assert_eq!(search.warnings.len(), 1);
        assert_eq!(search.warnings[0].partition, 2);
        assert_eq!(search.warnings[0].scanned_records, 10_000);
        assert_eq!(search.failures.len(), 1);
        assert_eq!(search.failures[0].partition, 3);
        assert_eq!(search.failures[0].diagnostic, "Read records: timed out");
        assert!(!state.explorer.search_pending);
    }

    #[test]
    fn worker_join_failure_finishes_search_and_delivery_with_safe_errors() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut state = selected_snapshot();
        let search = state.begin_search(SearchQuery::default()).unwrap().0;
        let search_join = runtime.block_on(async {
            tokio::task::spawn_blocking(|| -> ExplorerCompletion { panic!("worker failed") }).await
        });
        let completion = resolve_explorer_worker(
            search_join,
            ExplorerCompletion::Search(Err(explorer_worker_error())),
        );
        assert!(state.apply_explorer(search.identity, completion));
        assert!(!state.explorer.search_pending);
        assert!(search.cancel.is_cancelled());
        assert_eq!(
            state.explorer.search_error.as_deref(),
            Some("Kafka worker is unavailable")
        );

        state.open_send_dialog();
        state.explorer.send_draft.as_mut().unwrap().value = "secret message".into();
        let (delivery, request) = state.begin_delivery().unwrap();
        let delivery_join = runtime.block_on(async {
            tokio::task::spawn_blocking(|| -> ExplorerCompletion { panic!("worker failed") }).await
        });
        let completion = resolve_explorer_worker(
            delivery_join,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Err(explorer_worker_error()),
            },
        );
        assert!(state.apply_explorer(delivery.identity, completion));
        assert!(!state.explorer.delivery_pending);
        assert!(delivery.cancel.is_cancelled());
        let notice = state.explorer.delivery_notice.as_ref().unwrap();
        assert!(!notice.success);
        assert_eq!(
            notice.diagnostic.as_deref(),
            Some("Kafka worker is unavailable")
        );
        assert!(!format!("{notice:?}").contains("secret message"));
    }

    #[test]
    fn form_change_and_cancel_discard_search_completions_without_errors() {
        let mut state = selected_snapshot();
        let first = state.begin_search(SearchQuery::default()).unwrap().0;
        let changed = SearchQuery {
            value_contains: "different".into(),
            ..SearchQuery::default()
        };
        state.search_form_changed(changed);
        assert!(first.cancel.is_cancelled());
        assert!(!state.apply_explorer(
            first.identity,
            ExplorerCompletion::Search(Ok(empty_search())),
        ));
        let second = state.begin_search(SearchQuery::default()).unwrap().0;
        state.cancel_search();
        assert!(second.cancel.is_cancelled());
        assert!(!state.explorer.search_pending);
        assert!(state.explorer.search_error.is_none());
        assert!(!state.apply_explorer(
            second.identity,
            ExplorerCompletion::Search(Err(ExplorerKafkaError::Timeout("Read records"))),
        ));
    }

    #[test]
    fn search_requires_loaded_partition_ids_and_valid_query() {
        let mut state = connected_snapshot("one");
        assert!(state.begin_search(SearchQuery::default()).is_none());
        let mut state = selected_snapshot();
        assert!(state
            .begin_search(SearchQuery {
                partition: Some(0),
                ..SearchQuery::default()
            })
            .is_none());
        assert!(state
            .begin_search(SearchQuery {
                timestamp_from: Some(20),
                timestamp_to: Some(10),
                ..SearchQuery::default()
            })
            .is_none());
        assert!(!state.explorer.search_pending);
        let (_, query, partitions, topic) = state
            .begin_search(SearchQuery {
                partition: Some(2),
                page_size: 0,
                ..SearchQuery::default()
            })
            .unwrap();
        assert_eq!(query.page_size, 1);
        assert_eq!(partitions[0].id, 2);
        assert_eq!(partitions[0].low_offset, Some(0));
        assert_eq!(partitions[0].high_offset, Some(10));
        assert_eq!(topic, "orders");
    }

    #[test]
    fn page_navigation_reuses_snapshot_and_clears_selected_record() {
        let mut state = selected_snapshot();
        let work = state.begin_search(SearchQuery::default()).unwrap().0;
        let mut result = empty_search();
        result.query.page_size = 1;
        result.records = (0..3)
            .map(|offset| RecordData {
                partition: 2,
                offset,
                timestamp: Some(offset),
                key: None,
                value: "text".into(),
                headers: Vec::new(),
            })
            .collect();
        assert!(state.apply_explorer(work.identity, ExplorerCompletion::Search(Ok(result))));
        let snapshot = state.explorer.search.clone().unwrap();
        state.select_record(0);
        assert_eq!(state.explorer.selected_record().unwrap().offset, 0);
        state.change_page(1);
        assert_eq!(state.explorer.page()[0].offset, 1);
        assert!(state.explorer.selected_record().is_none());
        state.change_page(99);
        assert_eq!(state.explorer.page_index, 2);
        assert!(Arc::ptr_eq(
            &snapshot,
            state.explorer.search.as_ref().unwrap()
        ));
        assert!(!state.explorer.search_pending);
        state.change_page(-99);
        assert_eq!(state.explorer.page_index, 0);
    }

    #[test]
    fn closing_send_dialog_cancels_delivery_and_suppresses_late_notice() {
        let mut state = selected_snapshot();
        state.open_send_dialog();
        state.explorer.send_draft.as_mut().unwrap().value = "private payload".into();
        let (work, request) = state.begin_delivery().unwrap();
        state.close_send_dialog();
        assert!(work.cancel.is_cancelled());
        assert!(state.explorer.send_draft.is_none());
        assert!(!state.apply_explorer(
            work.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Ok(SendDelivery {
                    topic: "orders".into(),
                    partition: 2
                }),
            }
        ));
        assert!(state.explorer.delivery_notice.is_none());
    }

    #[test]
    fn delivery_preserves_inputs_reports_context_and_disables_duplicate_send() {
        let mut state = selected_snapshot();
        state.open_send_dialog();
        assert!(state.begin_delivery().is_none());
        assert!(state.explorer.send_validation_error.is_some());
        let draft = state.explorer.send_draft.as_mut().unwrap();
        draft.key = Some("private key".into());
        draft.value = "private payload".into();
        let (work, request) = state.begin_delivery().unwrap();
        assert!(state.begin_delivery().is_none());
        assert!(state.apply_explorer(
            work.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Ok(SendDelivery {
                    topic: "orders".into(),
                    partition: 2
                }),
            }
        ));
        let notice = state.explorer.delivery_notice.as_ref().unwrap();
        assert!(notice.success);
        assert_eq!(notice.requested_partition, None);
        assert_eq!(notice.delivered_partition, Some(2));
        assert_eq!(
            state.explorer.send_draft.as_ref().unwrap().value,
            "private payload"
        );
        assert_eq!(
            state.explorer.send_draft.as_ref().unwrap().key.as_deref(),
            Some("private key")
        );
        assert!(!format!("{state:?}").contains("private payload"));
        assert!(!format!("{state:?}").contains("private key"));
        assert!(!format!("{notice:?}").contains("private"));
        let (retry, request) = state.begin_delivery().unwrap();
        assert!(state.apply_explorer(
            retry.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Err(ExplorerKafkaError::Timeout("Deliver record")),
            }
        ));
        let failed_notice = state.explorer.delivery_notice.as_ref().unwrap();
        assert!(!failed_notice.success);
        assert!(!format!("{failed_notice:?}").contains("private payload"));
        assert!(!format!("{failed_notice:?}").contains("private key"));
        assert_eq!(
            state.explorer.send_draft.as_ref().unwrap().value,
            "private payload"
        );
    }

    #[test]
    fn dismissing_delivery_notice_keeps_the_send_draft_open() {
        let mut state = selected_snapshot();
        state.open_send_dialog();
        state.explorer.send_draft.as_mut().unwrap().value = "private payload".into();
        let (work, request) = state.begin_delivery().unwrap();
        assert!(state.apply_explorer(
            work.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Ok(SendDelivery {
                    topic: "orders".into(),
                    partition: 2,
                }),
            }
        ));

        state.dismiss_delivery_notice();

        assert!(state.explorer.delivery_notice.is_none());
        assert_eq!(
            state.explorer.send_draft.as_ref().unwrap().value,
            "private payload"
        );
    }

    #[test]
    fn elapsed_updates_only_accept_current_pending_identity() {
        let mut state = selected_snapshot();
        let old = state.begin_refresh().unwrap();
        let current = state.begin_refresh().unwrap();
        assert!(!state.update_elapsed(ExplorerOperation::Refresh, old.identity, 900));
        assert!(state.update_elapsed(ExplorerOperation::Refresh, current.identity, 250));
        assert_eq!(state.explorer.refresh_elapsed_ms, 250);
        assert!(state.apply_explorer(
            current.identity,
            ExplorerCompletion::Topics(Ok(topics(&["orders"])))
        ));
        assert!(!state.update_elapsed(ExplorerOperation::Refresh, current.identity, 500));
        assert!(current.cancel.is_cancelled());
    }

    #[test]
    fn elapsed_updates_stop_after_every_terminal_operation_result() {
        for outcome in 0..3 {
            let mut state = selected_snapshot();
            let work = state.begin_refresh().unwrap();
            let result = match outcome {
                0 => ExplorerCompletion::Topics(Ok(topics(&["orders", "other"]))),
                1 => ExplorerCompletion::Topics(Err(ExplorerKafkaError::Timeout("Load topics"))),
                _ => ExplorerCompletion::Topics(Err(ExplorerKafkaError::Cancelled)),
            };
            assert_terminal_elapsed(&mut state, ExplorerOperation::Refresh, work, result);

            let mut state = selected_snapshot();
            let work = state.begin_metadata("other".into()).unwrap();
            let result = match outcome {
                0 => ExplorerCompletion::Metadata(Ok(topic_detail("other"))),
                1 => ExplorerCompletion::Metadata(Err(ExplorerKafkaError::Timeout("Load detail"))),
                _ => ExplorerCompletion::Metadata(Err(ExplorerKafkaError::Cancelled)),
            };
            assert_terminal_elapsed(&mut state, ExplorerOperation::Metadata, work, result);

            let mut state = selected_snapshot();
            let work = state.begin_search(SearchQuery::default()).unwrap().0;
            let result = match outcome {
                0 => ExplorerCompletion::Search(Ok(empty_search())),
                1 => ExplorerCompletion::Search(Err(ExplorerKafkaError::Timeout("Read records"))),
                _ => ExplorerCompletion::Search(Err(ExplorerKafkaError::Cancelled)),
            };
            assert_terminal_elapsed(&mut state, ExplorerOperation::Search, work, result);

            let mut state = selected_snapshot();
            state.open_send_dialog();
            state.explorer.send_draft.as_mut().unwrap().value = "message".into();
            let (work, request) = state.begin_delivery().unwrap();
            let result = match outcome {
                0 => Ok(SendDelivery {
                    topic: "orders".into(),
                    partition: 2,
                }),
                1 => Err(ExplorerKafkaError::Timeout("Deliver record")),
                _ => Err(ExplorerKafkaError::Cancelled),
            };
            assert_terminal_elapsed(
                &mut state,
                ExplorerOperation::Delivery,
                work,
                ExplorerCompletion::Delivery {
                    topic: request.topic,
                    requested_partition: request.partition,
                    result,
                },
            );
        }
    }

    fn assert_terminal_elapsed(
        state: &mut ControllerSnapshot,
        operation: ExplorerOperation,
        work: ExplorerWork,
        result: ExplorerCompletion,
    ) {
        assert!(state.update_elapsed(operation, work.identity, 123));
        assert!(state.apply_explorer(work.identity, result));
        assert!(work.cancel.is_cancelled());
        assert!(state
            .explorer_lifecycle
            .session
            .as_ref()
            .unwrap()
            .slot(operation)
            .is_none());
        assert!(!state.update_elapsed(operation, work.identity, 999));
        let (pending, elapsed) = match operation {
            ExplorerOperation::Refresh => {
                (state.explorer.refreshing, state.explorer.refresh_elapsed_ms)
            }
            ExplorerOperation::Metadata => (
                state.explorer.metadata_pending,
                state.explorer.metadata_elapsed_ms,
            ),
            ExplorerOperation::Search => (
                state.explorer.search_pending,
                state.explorer.search_elapsed_ms,
            ),
            ExplorerOperation::Delivery => (
                state.explorer.delivery_pending,
                state.explorer.delivery_elapsed_ms,
            ),
        };
        assert!(!pending);
        assert_ne!(elapsed, 999);
    }

    #[test]
    fn initial_topic_load_failure_leaves_workspace_ready_for_retry() {
        let mut state = connected_snapshot("one");
        let first = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            first.identity,
            ExplorerCompletion::Topics(Err(ExplorerKafkaError::Timeout("Load topics"))),
        ));
        assert_eq!(state.operation.route, Route::Workspace);
        assert!(state.explorer.topics.is_empty());
        assert!(state.explorer.topic_error.is_some());
        let retry = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            retry.identity,
            ExplorerCompletion::Topics(Ok(topics(&["__internal", "orders"]))),
        ));
        assert_eq!(state.explorer.topics.len(), 2);
        assert_eq!(state.explorer.topics[0].name, "__internal");
        assert!(state.explorer.topic_error.is_none());
    }

    #[test]
    fn topic_detail_cache_is_reused_until_a_successful_topic_refresh() {
        let mut state = selected_snapshot();
        let other = state.select_topic_state("other".into()).unwrap();
        assert!(state.apply_explorer(
            other.identity,
            ExplorerCompletion::Metadata(Ok(topic_detail("other"))),
        ));
        assert!(state.select_topic_state("orders".into()).is_none());
        assert_eq!(state.explorer.detail.as_ref().unwrap().name, "orders");
        assert!(!state.explorer.metadata_pending);

        let refresh = state.begin_refresh().unwrap();
        assert!(state.apply_explorer(
            refresh.identity,
            ExplorerCompletion::Topics(Ok(topics(&["orders", "other"]))),
        ));
        assert!(state.select_topic_state("orders".into()).is_some());
        assert!(state.explorer.metadata_pending);
        assert!(state.explorer.detail.is_none());
    }

    #[test]
    fn newer_search_and_topic_selection_invalidate_prior_search_work() {
        let mut state = selected_snapshot();
        let first = state.begin_search(SearchQuery::default()).unwrap().0;
        let second = state.begin_search(SearchQuery::default()).unwrap().0;
        assert!(first.cancel.is_cancelled());
        assert!(second.identity.request_id > first.identity.request_id);
        assert!(!state.apply_explorer(
            first.identity,
            ExplorerCompletion::Search(Ok(empty_search())),
        ));
        state.begin_metadata("other".into()).unwrap();
        assert!(second.cancel.is_cancelled());
        assert!(!state.apply_explorer(
            second.identity,
            ExplorerCompletion::Search(Ok(empty_search())),
        ));
        assert!(state.explorer.search.is_none());
        assert!(!state.explorer.search_pending);
    }

    #[test]
    fn cancelled_search_completion_stops_pending_state_without_a_failure_notice() {
        let mut state = selected_snapshot();
        let work = state.begin_search(SearchQuery::default()).unwrap().0;
        assert!(state.apply_explorer(
            work.identity,
            ExplorerCompletion::Search(Err(ExplorerKafkaError::Cancelled)),
        ));
        assert!(!state.explorer.search_pending);
        assert!(state.explorer.search_error.is_none());
        assert!(state.explorer.search.is_none());
        assert!(work.cancel.is_cancelled());
    }

    #[test]
    fn fixed_delivery_validates_metadata_and_notices_keep_the_submitted_partition() {
        let mut state = selected_snapshot();
        state.open_send_dialog();
        let draft = state.explorer.send_draft.as_mut().unwrap();
        draft.key = Some("fixed private key".into());
        draft.value = "fixed private value".into();
        draft.partition = Some(0);
        assert!(state.begin_delivery().is_none());
        assert!(!state.explorer.delivery_pending);
        state.explorer.send_draft.as_mut().unwrap().partition = Some(2);
        let (work, request) = state.begin_delivery().unwrap();
        assert_eq!(request.partition, Some(2));
        state.explorer.send_draft.as_mut().unwrap().partition = None;
        assert!(state.apply_explorer(
            work.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Err(ExplorerKafkaError::Timeout("Deliver record")),
            }
        ));
        let notice = state.explorer.delivery_notice.as_ref().unwrap();
        assert_eq!(notice.requested_partition, Some(2));
        assert_eq!(state.explorer.send_draft.as_ref().unwrap().partition, None);
        assert!(!notice.success);
        assert!(!format!("{notice:?}").contains("fixed private key"));
        assert!(!format!("{notice:?}").contains("fixed private value"));

        state.explorer.send_draft.as_mut().unwrap().partition = Some(2);
        let (success, request) = state.begin_delivery().unwrap();
        assert!(state.apply_explorer(
            success.identity,
            ExplorerCompletion::Delivery {
                topic: request.topic,
                requested_partition: request.partition,
                result: Ok(SendDelivery {
                    topic: "orders".into(),
                    partition: 2
                }),
            }
        ));
        let notice = state.explorer.delivery_notice.as_ref().unwrap();
        assert!(notice.success);
        assert_eq!(notice.requested_partition, Some(2));
        assert_eq!(notice.delivered_partition, Some(2));
        assert!(!format!("{notice:?}").contains("fixed private key"));
        assert!(!format!("{notice:?}").contains("fixed private value"));
    }

    #[test]
    fn resolving_bundle_duplicate_preserves_unrelated_local_with_same_portable_id() {
        let root = TestRoot::new();
        let mut session = root.session();
        let unrelated = session.profiles[0].clone();
        let mut json: serde_json::Value = serde_json::from_str(
            &profile_bundle::export_bundle(&[
                profile("one", "Incoming"),
                profile("new-two", "Other"),
            ])
            .unwrap(),
        )
        .unwrap();
        json["profiles"][1]["name"] = "Incoming".into();
        json["profiles"][1]["bootstrap_servers"] = "replacement.invalid:9092".into();
        assert!(matches!(session.import(&json.to_string()),
            Err(ControllerError::Bundle(BundleError::Conflict(ref conflict)))
            if conflict.incoming_name == "Incoming" && conflict.existing_id == "one"));
        session.resolve_import(ImportResolution::Replace).unwrap();
        assert_eq!(session.profiles.len(), 2);
        assert_eq!(session.profiles[0], unrelated);
        assert_eq!(session.profiles[1].name, "Incoming");
        assert_eq!(
            session.profiles[1].bootstrap_servers,
            "replacement.invalid:9092"
        );
        assert_eq!(session.store.load().unwrap().len(), 2);
    }

    #[test]
    fn replacement_identity_is_reserved_before_earlier_portable_id_collision() {
        let root = TestRoot::new();
        let mut session = root.session();
        let mut replacement = profile("incoming-replacement", "First");
        replacement.bootstrap_servers = "replacement.invalid:9092".into();
        let json =
            profile_bundle::export_bundle(&[profile("one", "Unrelated incoming"), replacement])
                .unwrap();
        assert!(session.import(&json).is_err());
        session.resolve_import(ImportResolution::Replace).unwrap();
        assert_eq!(session.profiles.len(), 2);
        let replaced = session
            .profiles
            .iter()
            .find(|profile| profile.name == "First")
            .unwrap();
        assert_eq!(replaced.id, "one");
        assert_eq!(replaced.bootstrap_servers, "replacement.invalid:9092");
        let unrelated = session
            .profiles
            .iter()
            .find(|profile| profile.name == "Unrelated incoming")
            .unwrap();
        assert_ne!(unrelated.id, "one");
        assert!(uuid::Uuid::parse_str(&unrelated.id).is_ok());
        assert_eq!(session.store.load().unwrap().len(), 2);
    }

    #[test]
    fn blank_conflict_rename_keeps_resolution_available() {
        let root = TestRoot::new();
        let mut session = root.session();
        let json = profile_bundle::export_bundle(&[profile("incoming", "First")]).unwrap();
        assert!(session.import(&json).is_err());
        assert!(matches!(
            session.resolve_import(ImportResolution::Rename("   ".into())),
            Err(ControllerError::Bundle(BundleError::Conflict(_)))
        ));
        session
            .resolve_import(ImportResolution::Rename("Renamed".into()))
            .unwrap();
        assert_eq!(session.profiles.len(), 2);
    }

    #[test]
    fn replace_can_resolve_duplicate_names_inside_incoming_bundle() {
        let root = TestRoot::new();
        let mut session = root.session();
        let mut json: serde_json::Value = serde_json::from_str(
            &profile_bundle::export_bundle(&[
                profile("new-one", "New"),
                profile("new-two", "Other"),
            ])
            .unwrap(),
        )
        .unwrap();
        json["profiles"][1]["name"] = "New".into();
        json["profiles"][1]["bootstrap_servers"] = "second.invalid:9092".into();
        assert!(session.import(&json.to_string()).is_err());
        session.resolve_import(ImportResolution::Replace).unwrap();
        assert_eq!(session.profiles.len(), 2);
        assert_eq!(session.profiles[1].id, "new-two");
        assert_eq!(session.profiles[1].bootstrap_servers, "second.invalid:9092");
    }

    #[test]
    fn replacing_repeated_incoming_name_keeps_last_choice_and_local_identity() {
        let root = TestRoot::new();
        let mut session = root.session();
        let mut json: serde_json::Value = serde_json::from_str(
            &profile_bundle::export_bundle(&[
                profile("new-one", "First"),
                profile("new-two", "Other"),
            ])
            .unwrap(),
        )
        .unwrap();
        json["profiles"][1]["name"] = "First".into();
        json["profiles"][1]["bootstrap_servers"] = "last.invalid:9092".into();
        assert!(session.import(&json.to_string()).is_err());
        assert!(session.resolve_import(ImportResolution::Replace).is_err());
        session.resolve_import(ImportResolution::Replace).unwrap();
        assert_eq!(session.profiles.len(), 1);
        assert_eq!(session.profiles[0].id, "one");
        assert_eq!(session.profiles[0].bootstrap_servers, "last.invalid:9092");
    }

    #[test]
    fn returning_from_connect_clears_test_status() {
        let mut snapshot = ControllerSnapshot::default();
        let request = snapshot
            .operation
            .begin("one".into(), OperationStatus::Connecting)
            .unwrap();
        assert!(snapshot.apply_probe(&request, Ok(42)));
        snapshot.show_manager();
        assert_eq!(snapshot.operation.route, Route::Manager);
        assert_eq!(snapshot.topic_count, None);
    }

    #[test]
    fn deleting_the_active_profile_disconnects_and_clears_its_ui_state() {
        let profile = profile("one", "First");
        let mut snapshot = ControllerSnapshot {
            operation: OperationState {
                route: Route::Workspace,
                selected_profile_id: Some("one".into()),
                active_profile_id: Some("one".into()),
                ..Default::default()
            },
            topic_count: Some(3),
            draft_profile: Some(profile.clone()),
            active_profile: Some(profile),
            ..Default::default()
        };

        snapshot.remove_profile_state("one");

        assert_eq!(snapshot.operation.route, Route::Manager);
        assert_eq!(snapshot.operation.selected_profile_id, None);
        assert_eq!(snapshot.operation.active_profile_id, None);
        assert_eq!(snapshot.active_profile, None);
        assert_eq!(snapshot.draft_profile, None);
        assert_eq!(snapshot.topic_count, None);
    }

    #[test]
    fn import_conflict_can_be_renamed_without_overwriting_existing_profile() {
        let root = TestRoot::new();
        let mut session = root.session();
        let json = profile_bundle::export_bundle(&[profile("incoming", "First")]).unwrap();
        let error = session.import(&json).unwrap_err();
        assert!(
            matches!(error, ControllerError::Bundle(BundleError::Conflict(ref conflict))
            if conflict.incoming_name == "First" && conflict.existing_id == "one")
        );
        assert_eq!(session.profiles, vec![profile("one", "First")]);
        session
            .resolve_import(ImportResolution::Rename("Renamed".into()))
            .unwrap();
        assert_eq!(session.profiles.len(), 2);
        assert_eq!(session.profiles[0], profile("one", "First"));
        assert_eq!(session.profiles[1].name, "Renamed");
        assert_eq!(session.store.load().unwrap().len(), 2);
    }

    #[test]
    fn import_replace_is_staged_until_every_conflict_is_resolved() {
        let root = TestRoot::new();
        let mut session = root.session();
        session.profiles.push(profile("two", "Second"));
        let mut first = profile("incoming-one", "First");
        first.bootstrap_servers = "replacement.invalid:9092".into();
        let json =
            profile_bundle::export_bundle(&[first, profile("incoming-two", "Second")]).unwrap();
        let before = session.profiles.clone();
        assert!(session.import(&json).is_err());
        assert!(matches!(session.resolve_import(ImportResolution::Replace),
            Err(ControllerError::Bundle(BundleError::Conflict(ref conflict)))
            if conflict.incoming_name == "Second" && conflict.existing_id == "two"));
        assert_eq!(session.profiles, before);
        assert!(!session.store.path().exists());
        session
            .resolve_import(ImportResolution::Rename("Other".into()))
            .unwrap();
        assert_eq!(session.profiles.len(), 3);
        let replaced = session
            .profiles
            .iter()
            .find(|profile| profile.id == "one")
            .unwrap();
        assert_eq!(replaced.bootstrap_servers, "replacement.invalid:9092");
        assert!(session
            .profiles
            .iter()
            .any(|profile| profile.name == "Other"));
        assert_eq!(session.store.load().unwrap().len(), 3);
    }

    #[test]
    fn stale_probe_completion_cannot_replace_newer_operation() {
        let mut state = OperationState::default();
        let older = state
            .begin("first".into(), OperationStatus::Connecting)
            .unwrap();
        let newer = state
            .begin("second".into(), OperationStatus::Testing)
            .unwrap();
        assert!(newer.id > older.id);
        assert!(!state.complete(&older, true));
        assert_eq!(state.status, OperationStatus::Testing);
        assert!(state.complete(&newer, true));
        assert_eq!(state.route, Route::Manager);
        assert_eq!(state.active_profile_id, None);
    }

    #[test]
    fn successful_test_stays_in_manager() {
        let mut state = OperationState::default();
        let request = state
            .begin("profile".into(), OperationStatus::Testing)
            .unwrap();
        assert!(state.complete(&request, true));
        assert_eq!(state.route, Route::Manager);
        assert_eq!(state.active_profile_id, None);
        assert_eq!(state.status, OperationStatus::Idle);
    }

    #[test]
    fn successful_current_connect_enters_workspace_once() {
        let mut state = OperationState::default();
        let request = state
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        assert!(state.complete(&request, true));
        assert_eq!(state.route, Route::Workspace);
        assert_eq!(state.active_profile_id.as_deref(), Some("profile"));
        assert!(!state.complete(&request, true));
    }

    #[test]
    fn failed_connect_does_not_enter_workspace() {
        let mut state = OperationState::default();
        let request = state
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        assert!(state.complete(&request, false));
        assert_eq!(state.route, Route::Manager);
        assert_eq!(state.active_profile_id, None);
        assert_eq!(state.status, OperationStatus::Idle);
    }

    #[test]
    fn selecting_away_and_back_invalidates_pending_completion() {
        let mut state = OperationState::default();
        let request = state
            .begin("first".into(), OperationStatus::Connecting)
            .unwrap();
        state.select(Some("second".into()));
        state.select(Some("first".into()));
        assert!(!state.is_current(&request));
        assert!(!state.complete(&request, true));
        assert_eq!(state.route, Route::Manager);
    }

    #[test]
    fn returning_to_manager_cancels_in_flight_operation() {
        let mut state = OperationState::default();
        let request = state
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        state.show_manager();
        assert!(!state.complete(&request, true));
        assert_eq!(state.status, OperationStatus::Idle);
        let next = state
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        assert!(next.id > request.id);
    }

    #[test]
    fn workspace_and_idle_requests_are_rejected() {
        let mut state = OperationState::default();
        assert!(state
            .begin("profile".into(), OperationStatus::Idle)
            .is_none());
        let request = state
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        state.complete(&request, true);
        assert!(state
            .begin("other".into(), OperationStatus::Connecting)
            .is_none());
    }

    #[test]
    fn stale_probe_does_not_replace_diagnostic_or_topic_count() {
        let mut snapshot = ControllerSnapshot::default();
        let old = snapshot
            .operation
            .begin("profile".into(), OperationStatus::Connecting)
            .unwrap();
        let current = snapshot
            .operation
            .begin("profile".into(), OperationStatus::Testing)
            .unwrap();
        let error = ConnectionProbeError::from_diagnostic("Connection refused".into());
        assert!(snapshot.apply_probe(&current, Err(error.clone())));
        assert!(!snapshot.apply_probe(&old, Ok(90)));
        assert_eq!(snapshot.probe_error, Some(error));
        assert_eq!(snapshot.topic_count, None);
        assert_eq!(snapshot.operation.route, Route::Manager);
    }

    fn profile(id: &str, name: &str) -> ConnectionProfile {
        let mut profile = ConnectionProfile::plaintext("example.invalid:9092");
        profile.id = id.into();
        profile.name = name.into();
        profile
    }

    #[test]
    fn editing_replaces_matching_id_and_preserves_other_profiles() {
        let existing = vec![profile("one", "First"), profile("two", "Second")];
        let result = upsert_profile(&existing, profile("one", "Edited")).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "Edited");
        assert_eq!(result[1], existing[1]);
        let result = upsert_profile(&result, profile("three", "Third")).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn duplicate_names_and_invalid_profiles_are_rejected_before_save() {
        let existing = vec![profile("one", "First")];
        assert!(matches!(
            upsert_profile(&existing, profile("two", "First")),
            Err(ControllerError::DuplicateName)
        ));
        assert!(matches!(
            upsert_profile(&existing, profile("two", " ")),
            Err(ControllerError::InvalidProfile)
        ));
        assert!(matches!(
            upsert_profile(&existing, profile(" ", "Second")),
            Err(ControllerError::InvalidProfile)
        ));
    }

    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Self {
            Self(
                std::env::temp_dir().join(format!("kafka-controller-test-{}", uuid::Uuid::new_v4())),
            )
        }
        fn session(&self) -> StorageSession {
            StorageSession {
                store: ProfileStore::with_test_protector(self.0.clone()).unwrap(),
                profiles: vec![profile("one", "First")],
                pending_import: None,
            }
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn failed_save_preserves_the_in_memory_profiles_and_existing_store() {
        let root = TestRoot::new();
        let mut session = root.session();
        // This destination can never be replaced by a regular file, even when DPAPI is available.
        std::fs::create_dir(session.store.path()).unwrap();
        let before = session.profiles.clone();
        assert!(session.save(profile("one", "Edited")).is_err());
        assert_eq!(session.profiles, before);
        assert!(session.store.path().is_dir());
    }

    #[test]
    fn deleting_a_saved_profile_removes_it_from_memory_and_encrypted_store() {
        let root = TestRoot::new();
        let mut session = root.session();
        session.save(profile("two", "Second")).unwrap();

        session.delete("one").unwrap();

        assert_eq!(session.profiles, vec![profile("two", "Second")]);
        let stored: Vec<_> = session
            .store
            .load()
            .unwrap()
            .into_iter()
            .map(ConnectionProfile::from)
            .collect();
        assert_eq!(stored, vec![profile("two", "Second")]);
    }

    #[test]
    fn failed_import_persistence_removes_only_new_certificate_batch() {
        let root = TestRoot::new();
        let mut session = root.session();
        std::fs::create_dir(session.store.path()).unwrap();
        let keep = session.store.certificates_dir().join("keep.pem");
        std::fs::write(&keep, b"keep").unwrap();
        let json = r#"{"version":1,"profiles":[{"id":"new","name":"New","bootstrap_servers":"example.invalid:9093","security":"Ssl","tls":{"ca_certificate":"Y2E=","client_certificate":null,"private_key":null,"private_key_password":""}}]}"#;
        let before = session.profiles.clone();
        assert!(session.import(json).is_err());
        assert_eq!(session.profiles, before);
        assert_eq!(std::fs::read(keep).unwrap(), b"keep");
        assert_eq!(
            std::fs::read_dir(session.store.certificates_dir())
                .unwrap()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn failed_startup_completes_every_queued_storage_request_and_stops_on_close() {
        let root = TestRoot::new();
        let store = ProfileStore::for_test(root.0.clone()).unwrap();
        std::fs::write(store.path(), b"invalid ciphertext").unwrap();
        let (sender, receiver) = mpsc::unbounded_channel();
        sender
            .send(StorageCommand::Delete("unused".into()))
            .ok()
            .unwrap();
        sender
            .send(StorageCommand::Save(profile("new", "New")))
            .ok()
            .unwrap();
        drop(sender);
        let results = Arc::new(Mutex::new(Vec::new()));
        let collected = results.clone();
        let worker = run_storage_worker(
            Handle::current(),
            receiver,
            move || {
                let profiles = store
                    .load()?
                    .into_iter()
                    .map(ConnectionProfile::from)
                    .collect();
                Ok(StorageSession {
                    store,
                    profiles,
                    pending_import: None,
                })
            },
            move |result| collected.lock().unwrap().push(result),
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), worker)
            .await
            .unwrap();
        let results = results.lock().unwrap();
        assert_eq!(results.len(), 3);
        assert!(matches!(
            &results[0],
            Err(ControllerError::Store(StoreError::Decrypt))
        ));
        assert!(matches!(
            &results[1],
            Err(ControllerError::WorkerUnavailable)
        ));
        assert!(matches!(
            &results[2],
            Err(ControllerError::WorkerUnavailable)
        ));
    }
}
