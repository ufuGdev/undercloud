// SPDX-License-Identifier: Apache-2.0
//! Dedicated thread owns the SQLite connection and serializes catalog jobs.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use rusqlite::Connection;

use crate::error::CatalogError;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Owns the catalog executor thread and connection.
pub(crate) struct CatalogExecutor;

impl CatalogExecutor {
    /// Spawns the executor thread and runs initialization there.
    pub(crate) fn spawn(
        init: impl FnOnce() -> Result<Connection, CatalogError> + Send + 'static,
    ) -> Result<CatalogExecutorHandle, CatalogError> {
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), CatalogError>>();

        thread::Builder::new()
            .name("catalog-executor".to_string())
            .spawn(move || {
                let mut conn = match init() {
                    Ok(conn) => conn,
                    Err(err) => {
                        // Ignore replies when the caller has stopped waiting.
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));

                while let Ok(job) = job_rx.recv() {
                    job(&mut conn);
                }
            })
            // Map thread-start failures to executor-unavailable.
            .map_err(|_| CatalogError::ExecutorUnavailable)?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(CatalogExecutorHandle {
                sender: job_tx,
                round_trips: Arc::new(AtomicU64::new(0)),
            }),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(CatalogError::ExecutorUnavailable),
        }
    }
}

/// Cloneable async handle for serialized catalog access.
#[derive(Clone, Debug)]
pub(crate) struct CatalogExecutorHandle {
    sender: mpsc::Sender<Job>,
    /// Counts completed `call()` round trips (channel hops to the executor
    /// thread), shared across clones of this handle. Cheap enough to leave
    /// always-on: used by performance tests/benches to assert a listing
    /// stays O(1) catalog round trips as file count grows, rather than
    /// trusting wall-clock timing alone.
    round_trips: Arc<AtomicU64>,
}

impl CatalogExecutorHandle {
    /// Runs `f` with exclusive access to the executor connection.
    pub(crate) async fn call<F, T>(&self, f: F) -> Result<T, CatalogError>
    where
        F: FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let parent = tracing::Span::current();
        let job: Job = Box::new(move |conn| {
            let result = parent.in_scope(|| f(conn));
            // The job still ran; only its reply was dropped.
            let _ = reply_tx.send(result);
        });

        self.sender
            .send(job)
            .map_err(|_| CatalogError::ExecutorUnavailable)?;

        let result = reply_rx
            .await
            .map_err(|_| CatalogError::ExecutorUnavailable)?;
        self.round_trips.fetch_add(1, Ordering::Relaxed);
        result
    }

    pub(crate) fn round_trip_count(&self) -> u64 {
        self.round_trips.load(Ordering::Relaxed)
    }

    pub(crate) fn reset_round_trip_count(&self) {
        self.round_trips.store(0, Ordering::Relaxed);
    }
}
