use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

pub const MAX_RECORDS_PER_PARTITION: usize = 10_000;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicSummary {
    pub name: String,
    pub partition_count: usize,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicDetail {
    pub name: String,
    pub partitions: Vec<PartitionDetail>,
    pub configuration: Option<TopicConfiguration>,
    pub configuration_error: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionDetail {
    pub id: i32,
    pub leader: i32,
    pub replicas: Vec<i32>,
    pub isr: Vec<i32>,
    pub low_offset: Option<i64>,
    pub high_offset: Option<i64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicConfiguration {
    pub entries: Vec<(String, String)>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderData {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordData {
    pub partition: i32,
    pub offset: i64,
    pub timestamp: Option<i64>,
    pub key: Option<String>,
    pub value: String,
    pub headers: Vec<HeaderData>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampOrder {
    LatestFirst,
    EarliestFirst,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimestampPresence {
    All,
    HasTimestamp,
    NoTimestamp,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    pub partition: Option<i32>,
    pub page_size: usize,
    pub key_contains: String,
    pub value_contains: String,
    pub case_sensitive: bool,
    pub timestamp_from: Option<i64>,
    pub timestamp_to: Option<i64>,
    pub order: TimestampOrder,
    pub timestamp_presence: TimestampPresence,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            partition: None,
            page_size: 20,
            key_contains: String::new(),
            value_contains: String::new(),
            case_sensitive: false,
            timestamp_from: None,
            timestamp_to: None,
            order: TimestampOrder::LatestFirst,
            timestamp_presence: TimestampPresence::All,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchQueryError {
    InvalidTimestampRange,
}

impl SearchQuery {
    pub fn normalize(mut self) -> Result<Self, SearchQueryError> {
        if matches!((self.timestamp_from, self.timestamp_to), (Some(from), Some(to)) if from > to) {
            return Err(SearchQueryError::InvalidTimestampRange);
        }
        self.page_size = self.page_size.clamp(1, 1_000);
        Ok(self)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchWarning {
    pub partition: i32,
    pub scanned_records: usize,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchFailure {
    pub partition: i32,
    pub diagnostic: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchSnapshot {
    pub query: SearchQuery,
    pub records: Vec<RecordData>,
    pub warnings: Vec<SearchWarning>,
    pub failures: Vec<SearchFailure>,
}

impl SearchSnapshot {
    pub fn page(&self, page_index: usize, page_size: usize) -> &[RecordData] {
        let page_size = page_size.clamp(1, 1_000);
        let Some(start) = page_index.checked_mul(page_size) else {
            return &[];
        };
        let Some(tail) = self.records.get(start..) else {
            return &[];
        };
        &tail[..tail.len().min(page_size)]
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendRequest {
    pub topic: String,
    pub partition: Option<i32>,
    pub key: Option<String>,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendValidationError {
    MissingValue,
}

pub fn validate_send(request: &SendRequest) -> Result<(), SendValidationError> {
    if request.value.trim().is_empty() {
        Err(SendValidationError::MissingValue)
    } else {
        Ok(())
    }
}

pub fn topic_filter(topics: &[TopicSummary], filter: &str) -> Vec<TopicSummary> {
    let needle = filter.trim().to_lowercase();
    topics
        .iter()
        .filter(|topic| topic.name.to_lowercase().contains(&needle))
        .cloned()
        .collect()
}

pub fn preview_text(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let prefix: String = chars.by_ref().take(limit).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

#[cfg(test)]
pub fn filter_and_page(
    records: Vec<RecordData>,
    query: SearchQuery,
) -> Result<SearchSnapshot, SearchQueryError> {
    Ok(filter_and_page_cancellable(records, query, || false)?
        .expect("non-cancellable filtering must produce a snapshot"))
}

pub fn filter_and_page_cancellable(
    records: Vec<RecordData>,
    query: SearchQuery,
    mut is_cancelled: impl FnMut() -> bool,
) -> Result<Option<SearchSnapshot>, SearchQueryError> {
    let query = query.normalize()?;
    let key_needle = if query.case_sensitive {
        query.key_contains.clone()
    } else {
        query.key_contains.to_lowercase()
    };
    let value_needle = if query.case_sensitive {
        query.value_contains.clone()
    } else {
        query.value_contains.to_lowercase()
    };
    let mut filtered = Vec::new();
    for record in records {
        if is_cancelled() {
            return Ok(None);
        }
        if query
            .partition
            .is_some_and(|partition| record.partition != partition)
        {
            continue;
        }
        match query.timestamp_presence {
            TimestampPresence::All => {}
            TimestampPresence::HasTimestamp if record.timestamp.is_none() => continue,
            TimestampPresence::NoTimestamp if record.timestamp.is_some() => continue,
            _ => {}
        }
        if query.timestamp_from.is_some() || query.timestamp_to.is_some() {
            let Some(timestamp) = record.timestamp else {
                continue;
            };
            if query.timestamp_from.is_some_and(|from| timestamp < from)
                || query.timestamp_to.is_some_and(|to| timestamp > to)
            {
                continue;
            }
        }
        if contains_filter(record.key.as_deref(), &key_needle, query.case_sensitive)
            && contains_filter(Some(&record.value), &value_needle, query.case_sensitive)
        {
            filtered.push(record);
        }
    }
    if is_cancelled() {
        return Ok(None);
    }
    filtered.sort_by(|left, right| compare_records(left, right, query.order));
    if is_cancelled() {
        return Ok(None);
    }
    Ok(Some(SearchSnapshot {
        query,
        records: filtered,
        warnings: Vec::new(),
        failures: Vec::new(),
    }))
}

fn contains_filter(value: Option<&str>, needle: &str, case_sensitive: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    value.is_some_and(|text| {
        if case_sensitive {
            text.contains(needle)
        } else {
            text.to_lowercase().contains(needle)
        }
    })
}

fn compare_records(left: &RecordData, right: &RecordData, order: TimestampOrder) -> Ordering {
    let timestamp_order = match order {
        TimestampOrder::LatestFirst => match (left.timestamp, right.timestamp) {
            (Some(left), Some(right)) => right.cmp(&left),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        TimestampOrder::EarliestFirst => left.timestamp.cmp(&right.timestamp),
    };
    timestamp_order
        .then_with(|| left.partition.cmp(&right.partition))
        .then_with(|| match order {
            TimestampOrder::LatestFirst => right.offset.cmp(&left.offset),
            TimestampOrder::EarliestFirst => left.offset.cmp(&right.offset),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        partition: i32,
        offset: i64,
        timestamp: Option<i64>,
        key: Option<&str>,
        value: &str,
    ) -> RecordData {
        RecordData {
            partition,
            offset,
            timestamp,
            key: key.map(str::to_owned),
            value: value.to_owned(),
            headers: Vec::new(),
        }
    }

    #[test]
    fn topic_filter_ignores_case_and_keeps_cache_order() {
        let topics = vec![
            TopicSummary {
                name: "Alpha".into(),
                partition_count: 1,
            },
            TopicSummary {
                name: "alphabet".into(),
                partition_count: 2,
            },
            TopicSummary {
                name: "Beta".into(),
                partition_count: 3,
            },
        ];

        let names: Vec<_> = topic_filter(&topics, "ALP")
            .into_iter()
            .map(|topic| topic.name)
            .collect();

        assert_eq!(names, vec!["Alpha".to_owned(), "alphabet".to_owned()]);
    }

    #[test]
    fn send_rejects_only_whitespace_value_and_accepts_missing_key() {
        let mut request = SendRequest {
            topic: "orders".into(),
            partition: None,
            key: None,
            value: " \t ".into(),
        };
        assert_eq!(
            validate_send(&request),
            Err(SendValidationError::MissingValue)
        );

        request.value = "hello".into();
        assert_eq!(validate_send(&request), Ok(()));
    }

    #[test]
    fn preview_counts_unicode_characters_and_ellipsizes_only_if_omitted() {
        assert_eq!(preview_text("a\u{1f600}b", 2), "a\u{1f600}...");
        assert_eq!(preview_text("a\u{1f600}", 2), "a\u{1f600}");
        assert_eq!(preview_text("", 2), "");
    }

    #[test]
    fn filters_before_latest_order_and_local_pages() {
        let query = SearchQuery {
            value_contains: "match".into(),
            page_size: 1,
            ..SearchQuery::default()
        };
        let snapshot = filter_and_page(
            vec![
                record(0, 1, Some(1), None, "match oldest"),
                record(0, 2, Some(3), None, "ignore newest"),
                record(0, 3, Some(2), None, "match middle"),
            ],
            query,
        )
        .unwrap();

        assert_eq!(snapshot.records.len(), 2);
        assert_eq!(snapshot.page(0, 1)[0].offset, 3);
        assert_eq!(snapshot.page(1, 1)[0].offset, 1);
        assert!(snapshot.page(2, 1).is_empty());
    }

    #[test]
    fn timestamp_range_excludes_records_without_timestamp() {
        let query = SearchQuery {
            timestamp_from: Some(10),
            timestamp_to: Some(20),
            ..SearchQuery::default()
        };
        let snapshot = filter_and_page(
            vec![
                record(0, 0, None, None, "none"),
                record(0, 1, Some(10), None, "lower"),
                record(0, 2, Some(20), None, "upper"),
                record(0, 3, Some(21), None, "outside"),
            ],
            query,
        )
        .unwrap();

        let offsets: Vec<_> = snapshot.records.iter().map(|item| item.offset).collect();
        assert_eq!(offsets, [2, 1]);
    }

    #[test]
    fn timestamp_less_order_is_stable_in_both_directions() {
        let input = vec![
            record(1, 3, None, None, "none b"),
            record(0, 2, Some(10), None, "dated"),
            record(0, 1, None, None, "none a"),
        ];
        let latest = filter_and_page(input.clone(), SearchQuery::default()).unwrap();
        let earliest = filter_and_page(
            input,
            SearchQuery {
                order: TimestampOrder::EarliestFirst,
                ..SearchQuery::default()
            },
        )
        .unwrap();

        let latest_offsets: Vec<_> = latest.records.iter().map(|item| item.offset).collect();
        let earliest_offsets: Vec<_> = earliest.records.iter().map(|item| item.offset).collect();
        assert_eq!(latest_offsets, [2, 1, 3]);
        assert_eq!(earliest_offsets, [1, 3, 2]);
    }

    #[test]
    fn key_and_value_filters_are_case_sensitive_together() {
        let records = vec![
            record(0, 0, Some(1), Some("ID-a"), "PayLoad"),
            record(0, 1, Some(2), Some("id-b"), "payload"),
            record(0, 2, Some(3), Some("ID-c"), "other"),
        ];
        let query = SearchQuery {
            key_contains: "ID".into(),
            value_contains: "load".into(),
            case_sensitive: true,
            ..SearchQuery::default()
        };
        assert!(filter_and_page(records.clone(), query.clone())
            .unwrap()
            .records
            .is_empty());

        let insensitive = SearchQuery {
            case_sensitive: false,
            ..query
        };
        let offsets: Vec<_> = filter_and_page(records, insensitive)
            .unwrap()
            .records
            .iter()
            .map(|item| item.offset)
            .collect();
        assert_eq!(offsets, [1, 0]);
    }

    #[test]
    fn key_and_value_filters_match_literal_leading_and_trailing_whitespace() {
        let records = vec![
            record(0, 0, Some(1), Some("order "), " paid"),
            record(0, 1, Some(2), Some("order"), "paid"),
            record(0, 2, Some(3), Some(" order"), "paid "),
        ];
        let query = SearchQuery {
            key_contains: "order ".into(),
            value_contains: " paid".into(),
            case_sensitive: true,
            ..SearchQuery::default()
        };

        let snapshot = filter_and_page(records, query).unwrap();

        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].offset, 0);
        assert_eq!(snapshot.query.key_contains, "order ");
        assert_eq!(snapshot.query.value_contains, " paid");
    }

    #[test]
    fn invalid_timestamp_range_is_rejected() {
        let query = SearchQuery {
            timestamp_from: Some(21),
            timestamp_to: Some(20),
            ..SearchQuery::default()
        };
        assert!(matches!(
            filter_and_page(Vec::new(), query),
            Err(SearchQueryError::InvalidTimestampRange)
        ));
    }

    #[test]
    fn local_filtering_stops_when_cancellation_is_observed() {
        let records = (0..100)
            .map(|offset| record(0, offset, Some(offset), None, "value"))
            .collect();
        let mut checks = 0;

        let snapshot = filter_and_page_cancellable(records, SearchQuery::default(), || {
            checks += 1;
            checks > 3
        })
        .unwrap();

        assert!(snapshot.is_none());
        assert_eq!(checks, 4);
    }
}
