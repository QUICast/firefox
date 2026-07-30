// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    cell::RefCell,
    fmt::{self, Display},
    fs::OpenOptions,
    io::BufWriter,
    path::PathBuf,
    rc::Rc,
    time::{Instant, SystemTime},
};

use qlog::{
    CommonFields, Configuration, TraceSeq, VantagePoint, VantagePointType, streamer::QlogStreamer,
};

use crate::Role;

#[derive(Debug, Clone, Default)]
pub struct Qlog {
    /// Both the inner and the outer `Option` are set to `None`
    /// on failure. The inner `None` will disable qlog for all other
    /// references (correctness). The outer `None` will prevent
    /// the local instance from de-referencing the `Rc` again
    /// (performance).
    inner: Option<Rc<RefCell<Option<SharedStreamer>>>>,
}

pub struct SharedStreamer {
    qlog_path: PathBuf,
    streamer: QlogStreamer,
    output_transaction: Option<Vec<(qlog::events::EventData, Instant)>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputTransactionError {
    AlreadyPending,
    NotPending,
    InvalidCheckpoint,
}

impl Qlog {
    /// Create an enabled `Qlog` configuration backed by a file.
    ///
    /// # Errors
    ///
    /// Will return `qlog::Error` if it cannot write to the new file.
    pub fn enabled_with_file<D: Display>(
        mut qlog_path: PathBuf,
        role: Role,
        title: Option<String>,
        description: Option<String>,
        file_prefix: D,
        now: Instant,
    ) -> Result<Self, qlog::Error> {
        qlog_path.push(format!("{file_prefix}.sqlog"));

        let file = OpenOptions::new()
            .write(true)
            // As a server, the original DCID is chosen by the client. Using
            // create_new() prevents attackers from overwriting existing logs.
            .create_new(true)
            .open(&qlog_path)?;

        let streamer = QlogStreamer::new(
            qlog::QLOG_VERSION.to_string(),
            title,
            description,
            None,
            now,
            new_trace(role),
            qlog::events::EventImportance::Extra,
            Box::new(BufWriter::new(file)),
        );
        Self::enabled(streamer, qlog_path)
    }

    /// Create an enabled `Qlog` configuration.
    ///
    /// This needs to be called before the connection is used, because otherwise `Qlog`-logging will
    /// remain disabled (for performance reasons).
    ///
    /// # Errors
    ///
    /// Will return `qlog::Error` if it cannot write to the new log.
    pub fn enabled(mut streamer: QlogStreamer, qlog_path: PathBuf) -> Result<Self, qlog::Error> {
        streamer.start_log()?;

        Ok(Self {
            inner: Some(Rc::new(RefCell::new(Some(SharedStreamer {
                qlog_path,
                streamer,
                output_transaction: None,
            })))),
        })
    }

    /// Create a disabled `Qlog` configuration.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Returns true if qlog is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.inner.as_ref().is_some_and(|rc| rc.borrow().is_some())
    }

    /// If logging enabled, closure may generate an event to be logged.
    pub fn add_event_at<F>(&mut self, f: F, now: Instant)
    where
        F: FnOnce() -> Option<qlog::events::EventData>,
    {
        let Some(inner) = self.inner.clone() else {
            return;
        };

        let mut borrow = inner.borrow_mut();
        let Some(shared_streamer) = borrow.as_mut() else {
            drop(borrow);
            self.inner = None;
            return;
        };

        let Some(ev_data) = f() else {
            return;
        };
        if let Some(events) = shared_streamer.output_transaction.as_mut() {
            events.push((ev_data, now));
            return;
        }

        let result = shared_streamer
            .streamer
            .add_event_data_with_instant(ev_data, now);
        Self::handle_result(&mut self.inner, borrow, result);
    }

    /// If logging enabled, closure is given the Qlog stream to write events and
    /// frames to.
    pub fn add_event_with_stream<F>(&mut self, f: F)
    where
        F: FnOnce(&mut QlogStreamer) -> Result<(), qlog::Error>,
    {
        let Some(inner) = self.inner.clone() else {
            return;
        };

        let mut borrow = inner.borrow_mut();

        let Some(shared_streamer) = borrow.as_mut() else {
            drop(borrow);
            // Set the outer Option to None to prevent future dereferences.
            self.inner = None;
            return;
        };

        if shared_streamer.output_transaction.is_some() {
            debug_assert!(
                false,
                "add_event_with_stream cannot be used during an output transaction"
            );
            return;
        }

        let result = f(&mut shared_streamer.streamer);
        Self::handle_result(&mut self.inner, borrow, result);
    }

    fn handle_result(
        inner: &mut Option<Rc<RefCell<Option<SharedStreamer>>>>,
        mut borrow: std::cell::RefMut<'_, Option<SharedStreamer>>,
        result: Result<(), qlog::Error>,
    ) {
        match result {
            // `Error::Done` means "event was below the importance threshold" - not an actual error.
            Ok(()) | Err(qlog::Error::Done) => (),
            Err(e) => {
                log::error!("Qlog event generation failed with error {e}; closing qlog.");
                // Set the inner Option to None to disable future logging for other references.
                *borrow = None;
                // Explicitly drop the RefCell borrow to release the mutable borrow.
                drop(borrow);
                // Set the outer Option to None to prevent future dereferences.
                *inner = None;
            }
        }
    }

    /// Defer qlog writes until generated output is accepted or abandoned.
    ///
    /// # Errors
    ///
    /// Returns [`OutputTransactionError::AlreadyPending`] if a transaction is
    /// already active on this shared qlog streamer.
    pub fn begin_output_transaction(&mut self) -> Result<(), OutputTransactionError> {
        let Some(inner) = self.inner.clone() else {
            return Ok(());
        };
        let mut borrow = inner.borrow_mut();
        let Some(shared_streamer) = borrow.as_mut() else {
            drop(borrow);
            self.inner = None;
            return Ok(());
        };
        if shared_streamer.output_transaction.is_some() {
            return Err(OutputTransactionError::AlreadyPending);
        }
        shared_streamer.output_transaction = Some(Vec::new());
        Ok(())
    }

    /// Return the number of deferred events in the active transaction.
    ///
    /// # Errors
    ///
    /// Returns [`OutputTransactionError::NotPending`] if qlog is enabled but
    /// no transaction is active.
    pub fn output_transaction_checkpoint(&self) -> Result<usize, OutputTransactionError> {
        let Some(inner) = self.inner.as_ref() else {
            return Ok(0);
        };
        let borrow = inner.borrow();
        let Some(shared_streamer) = borrow.as_ref() else {
            return Ok(0);
        };
        shared_streamer
            .output_transaction
            .as_ref()
            .map(Vec::len)
            .ok_or(OutputTransactionError::NotPending)
    }

    /// Discard deferred events after `checkpoint`.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active transaction or the checkpoint
    /// lies beyond the deferred event list.
    pub fn truncate_output_transaction(
        &mut self,
        checkpoint: usize,
    ) -> Result<(), OutputTransactionError> {
        let Some(inner) = self.inner.clone() else {
            return Ok(());
        };
        let mut borrow = inner.borrow_mut();
        let Some(shared_streamer) = borrow.as_mut() else {
            drop(borrow);
            self.inner = None;
            return Ok(());
        };
        let events = shared_streamer
            .output_transaction
            .as_mut()
            .ok_or(OutputTransactionError::NotPending)?;
        if checkpoint > events.len() {
            return Err(OutputTransactionError::InvalidCheckpoint);
        }
        events.truncate(checkpoint);
        Ok(())
    }

    /// Finish the active output transaction, writing deferred events when
    /// `commit` is true and discarding them otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`OutputTransactionError::NotPending`] if qlog is enabled but
    /// no transaction is active.
    pub fn finish_output_transaction(
        &mut self,
        commit: bool,
    ) -> Result<(), OutputTransactionError> {
        let Some(inner) = self.inner.clone() else {
            return Ok(());
        };
        let mut borrow = inner.borrow_mut();
        let Some(shared_streamer) = borrow.as_mut() else {
            drop(borrow);
            self.inner = None;
            return Ok(());
        };
        let events = shared_streamer
            .output_transaction
            .take()
            .ok_or(OutputTransactionError::NotPending)?;
        if !commit {
            return Ok(());
        }

        let result = events.into_iter().try_for_each(|(event, now)| {
            shared_streamer
                .streamer
                .add_event_data_with_instant(event, now)
        });
        Self::handle_result(&mut self.inner, borrow, result);
        Ok(())
    }
}

impl fmt::Debug for SharedStreamer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Qlog writing to {}", self.qlog_path.display())
    }
}

impl Drop for SharedStreamer {
    fn drop(&mut self) {
        if let Err(e) = self.streamer.finish_log() {
            log::error!("Error dropping Qlog: {e}");
        }
    }
}

#[must_use]
pub fn new_trace(role: Role) -> TraceSeq {
    TraceSeq {
        vantage_point: VantagePoint {
            name: Some(format!("neqo-{role}")),
            ty: match role {
                Role::Client => VantagePointType::Client,
                Role::Server => VantagePointType::Server,
            },
            flow: None,
        },
        title: Some(format!("neqo-{role} trace")),
        description: Some(format!("neqo-{role} trace")),
        configuration: Some(Configuration {
            time_offset: Some(0.0),
            original_uris: None,
        }),
        common_fields: Some(CommonFields {
            group_id: None,
            protocol_type: None,
            reference_time: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs_f64() * 1_000.0)
                .ok(),
            time_format: Some("relative".to_string()),
        }),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod test {
    use test_fixture::EXPECTED_LOG_HEADER;

    use super::Qlog;

    const EV_DATA: qlog::events::EventData =
        qlog::events::EventData::SpinBitUpdated(qlog::events::connectivity::SpinBitUpdated {
            state: true,
        });

    const EXPECTED_LOG_EVENT: &str = concat!(
        "\u{1e}",
        r#"{"time":0.0,"name":"connectivity:spin_bit_updated","data":{"state":true}}"#,
        "\n"
    );

    #[test]
    fn new_neqo_qlog() {
        let (_log, contents) = test_fixture::new_neqo_qlog();
        assert_eq!(contents.to_string(), EXPECTED_LOG_HEADER);
    }

    #[test]
    fn add_event_at() {
        const TIME_PREFIX: &str = "\"time\":";
        let (mut log, contents) = test_fixture::new_neqo_qlog();
        log.add_event_at(|| Some(EV_DATA), test_fixture::now());
        let mut output = contents.to_string();
        if let Some(range) = output.find(TIME_PREFIX).and_then(|start| {
            let time_start = start + TIME_PREFIX.len();
            output[time_start..]
                .find(',')
                .map(|end| time_start..time_start + end)
        }) {
            output.replace_range(range, "0.0");
        }
        assert_eq!(output, format!("{EXPECTED_LOG_HEADER}{EXPECTED_LOG_EVENT}"));
    }

    #[test]
    fn shared_streamer_debug() {
        let (log, _contents) = test_fixture::new_neqo_qlog();
        assert!(format!("{log:?}").contains("Qlog writing to"));
    }

    #[test]
    fn add_event_with_stream_error_disables_logging() {
        let (mut log, contents) = test_fixture::new_neqo_qlog();
        let mut log_clone = log.clone();
        let before_error = contents.to_string();
        log.add_event_with_stream(|_| Err(qlog::Error::IoError(std::io::Error::other("e"))));
        // The cloned instance still has inner=Some, but the RefCell contains None.
        log_clone.add_event_at(|| Some(EV_DATA), test_fixture::now());
        assert_eq!(contents.to_string(), before_error);
    }

    #[test]
    fn is_enabled() {
        // Disabled by default.
        assert!(!Qlog::disabled().is_enabled());
        // Enabled when backed by a live streamer.
        let (log, _contents) = test_fixture::new_neqo_qlog();
        assert!(log.is_enabled());
        // Disabled on a clone whose underlying streamer was killed by a write error.
        let mut log = log;
        let clone = log.clone();
        log.add_event_with_stream(|_| Err(qlog::Error::IoError(std::io::Error::other("e"))));
        assert!(!clone.is_enabled());
    }

    #[test]
    fn output_transaction_commit_and_truncate() {
        let (mut log, contents) = test_fixture::new_neqo_qlog();
        log.begin_output_transaction().unwrap();
        log.add_event_at(|| Some(EV_DATA), test_fixture::now());
        let checkpoint = log.output_transaction_checkpoint().unwrap();
        log.add_event_at(|| Some(EV_DATA), test_fixture::now());
        assert_eq!(contents.to_string(), EXPECTED_LOG_HEADER);
        log.truncate_output_transaction(checkpoint).unwrap();
        log.finish_output_transaction(true).unwrap();
        assert!(
            contents
                .to_string()
                .contains("connectivity:spin_bit_updated")
        );
        assert_eq!(
            contents
                .to_string()
                .matches("connectivity:spin_bit_updated")
                .count(),
            1
        );
    }

    #[test]
    fn output_transaction_abandon_and_double_begin() {
        let (mut log, contents) = test_fixture::new_neqo_qlog();
        log.begin_output_transaction().unwrap();
        assert_eq!(
            format!("{:?}", log.begin_output_transaction().unwrap_err()),
            "AlreadyPending"
        );
        log.add_event_at(|| Some(EV_DATA), test_fixture::now());
        log.finish_output_transaction(false).unwrap();
        assert_eq!(contents.to_string(), EXPECTED_LOG_HEADER);
    }
}
