use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use uuid::Uuid;

#[derive(Clone)]
struct DailyFile {
    directory: PathBuf,
    date: String,
    file: Arc<Mutex<File>>,
}

impl DailyFile {
    fn open(directory: &Path) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let date = current_date();
        let file = open_log_file(directory, &date)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            date,
            file: Arc::new(Mutex::new(file)),
        })
    }
}

impl Write for DailyFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let date = current_date();
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?;
        if date != self.date {
            file.flush()?;
            *file = open_log_file(&self.directory, &date)?;
            self.date = date;
        }
        file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("log lock poisoned"))?
            .flush()
    }
}

fn open_log_file(directory: &Path, date: &str) -> io::Result<File> {
    let path = directory.join(format!("undercloud-{date}.log"));
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(file)
}

fn current_date() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    let (year, month, day) = civil_date(days as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

fn civil_date(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month + 2) / 5 + 1;
    let year = year + if month < 10 { 0 } else { 1 };
    let month = month + if month < 10 { 3 } else { -9 };
    (year, month, day)
}

#[derive(Debug, Clone, Serialize)]
pub struct LoggingStatus {
    pub directory: String,
    pub level: String,
    pub persistent: bool,
    pub warning: Option<String>,
    pub application_version: String,
    pub build_profile: String,
}

pub struct LoggingState {
    pub directory: PathBuf,
    pub status: LoggingStatus,
    _guard: Option<WorkerGuard>,
}

pub fn initialize(app: &AppHandle) -> LoggingState {
    let (directory, directory_warning) = match app.path().app_log_dir() {
        Ok(path) => (path, None),
        Err(_error) => (
            std::env::temp_dir().join("undercloud"),
            Some(
                "Application log directory unavailable; using a temporary local directory.".into(),
            ),
        ),
    };
    let result = DailyFile::open(&directory).map(|writer| {
        let (non_blocking, guard) = tracing_appender::non_blocking(writer);
        let fmt = tracing_subscriber::fmt::layer().json().with_writer(non_blocking).with_current_span(true).with_span_list(true).with_span_events(FmtSpan::CLOSE);
        let filter = EnvFilter::new("undercloud=info,undercloud_desktop=info,undercloud_core=info,undercloud_catalog=info,undercloud_provider_cloud=info,undercloud_credentials=info");
        let console = tracing_subscriber::fmt::layer().compact().with_ansi(cfg!(debug_assertions)).with_target(false).with_thread_ids(false).with_thread_names(false).with_file(false).with_line_number(false);
        let _ = tracing_subscriber::registry().with(filter).with(fmt).with(console).try_init();
        guard
    });
    let (guard, warning) = match result {
        Ok(guard) => (Some(guard), None),
        Err(_error) => {
            let _ = tracing_subscriber::registry().with(EnvFilter::new("undercloud=info,undercloud_desktop=info,undercloud_core=info,undercloud_catalog=info,undercloud_provider_cloud=info,undercloud_credentials=info")).with(tracing_subscriber::fmt::layer().compact().with_ansi(cfg!(debug_assertions)).with_target(false).with_thread_ids(false).with_thread_names(false).with_file(false).with_line_number(false)).try_init();
            (
                None,
                Some("Persistent logging unavailable on this device.".into()),
            )
        }
    };
    let status = LoggingStatus {
        directory: "Application data logs".into(),
        level: "info".into(),
        persistent: guard.is_some(),
        warning: directory_warning.or(warning),
        application_version: env!("CARGO_PKG_VERSION").into(),
        build_profile: if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
    };
    std::panic::set_hook(Box::new(|_| {
        tracing::error!(target: "undercloud.panic", subsystem="runtime", operation="panic", operation_id=%Uuid::new_v4(), stage="panic_hook", outcome="panic", message="application panic captured; sensitive panic payload omitted");
    }));
    tracing::info!(target: "undercloud", subsystem="startup", operation="logging_init", operation_id=%Uuid::new_v4(), outcome="complete", "logging initialized");
    LoggingState {
        directory,
        status,
        _guard: guard,
    }
}

pub fn log_directory(app: &AppHandle) -> PathBuf {
    app.state::<LoggingState>().directory.clone()
}
pub fn status(app: &AppHandle) -> LoggingStatus {
    app.state::<LoggingState>().status.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_file_uses_date_in_filename_and_appends() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = DailyFile::open(directory.path()).unwrap();
        writer.write_all(b"first\n").unwrap();
        writer.write_all(b"second\n").unwrap();
        let entries: Vec<_> = fs::read_dir(directory.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let name = entries[0]
            .as_ref()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .into_owned();
        assert!(name.starts_with("undercloud-"));
        assert!(name.ends_with(".log"));
        assert_eq!(
            fs::read_to_string(directory.path().join(name)).unwrap(),
            "first\nsecond\n"
        );
    }
}
