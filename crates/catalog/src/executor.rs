// SPDX-License-Identifier: Apache-2.0
//! `CatalogExecutor`: the single dedicated background thread that owns `crates/catalog`'s one `rusqlite::Connection` (ADR-003 "Concurrency") — rather than a `Mutex`-shared connection risking blocked async threads or lock-ordering bugs, every operation is a `Box<dyn FnOnce(&mut Connection) + Send>` job sent over `std::sync::mpsc` to one OS thread that owns the connection outright; `&mut Connection` (not `&`) because `rusqlite::Connection::transaction` needs exclusive access to prevent nested transactions at compile time.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use rusqlite::Connection;

use crate::error::CatalogError;

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Owns the background thread and its `rusqlite::Connection`; dropping every `CatalogExecutorHandle` closes the job channel and ends the thread's receive loop, and nothing here joins it explicitly, matching a desktop app's process-lifetime resource model.
pub(crate) struct CatalogExecutor;

impl CatalogExecutor {
    /// Spawns the dedicated executor thread; `init` runs *on that thread* (not the caller's) to open the connection and apply migrations before jobs start (ADR-003 "Migrations"/"Storage engine and durability policy"), blocking the caller only until `init` reports its result.
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
                        // Receiver may already be gone if the caller stopped waiting; nothing to do about that.
                        let _ = ready_tx.send(Err(err));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));

                while let Ok(job) = job_rx.recv() {
                    job(&mut conn);
                }
            })
            // `thread::Builder::spawn` failing has no natural `CatalogError` variant of its own, so it collapses to the same "executor unavailable" signal as any other executor-startup failure.
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

/// A cheap-to-clone async-facing handle to the executor thread; every catalog operation goes through `call` and never holds the connection directly.
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
    /// Runs `f` on the executor thread with exclusive connection access and returns its result; `f` must not block on anything but SQLite I/O, since it runs on the single thread serializing every catalog operation.
    pub(crate) async fn call<F, T>(&self, f: F) -> Result<T, CatalogError>
    where
        F: FnOnce(&mut Connection) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let parent = tracing::Span::current();
        let job: Job = Box::new(move |conn| {
            let result = parent.in_scope(|| f(conn));
            // If the caller dropped the receiving future, the job still ran to completion; only the reply is discarded, no state is lost.
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
