use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// Defines the severity level of a log message
#[allow(dead_code)]
#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    fn as_str(&self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

// Formats and computes time from the UNIX epoch manually
fn timestamp() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let ms   = d.subsec_millis();
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600)  / 60;
    let s =  secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, ms)
}

// Thread safe logger
struct Logger {
    file_path: String,
    // The mutex guards access to the underlying file writing logic
    inner: Mutex<Option<std::fs::File>>,
}

impl Logger {
    // Singleton
    fn new(file_path: &str) -> Self {
        Logger {
            file_path: file_path.to_string(),
            inner: Mutex::new(None),
        }
    }


    // This must be called once at program startup
    fn init(&self) -> io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&self.file_path)?;

        // Replace the initial None with the opened file handle
        *self.inner.lock().unwrap() = Some(file);
        Ok(())
    }

    // Core logging function
    fn log(&self, level: Level, module: &str, message: &str) {
        // Get current local time
        let timestamp = timestamp();

        // Format the log entry: [Timestamp] [LEVEL] [Module] Message
        let log_entry = format!("[{}] [{:^5}] [{}]: {}\n", timestamp, level.as_str(), module, message);

        // Lock the mutex before writing
        let mut file_guard = self.inner.lock().unwrap();
        if let Some(file) = file_guard.as_mut() {
            match write!(file, "{}", log_entry) {
                Ok(_) => {
                    // Flush ensures the data hits the disk immediately (good for logging)
                    let _ = file.sync_data();
                },
                Err(e) => {
                    eprintln!("FATAL: Could not write to log file '{}': {}", self.file_path, e);
                }
            }
        } else {
            eprintln!("FATAL: Logger not initialized. Cannot write log entry.");
        }
    }
}

// --- Public Interface & Global Access ---

// Globally accessible, thread-safe logger instance.
static LOGGER: once_cell::sync::Lazy<Arc<Logger>> = once_cell::sync::Lazy::new(|| {
    Arc::new(Logger::new("pupscan.log"))
});


// Must be called once at the beginning of the application
pub fn initialize_logger() -> Result<(), String> {
    match LOGGER.init() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to initialize logger: {}", e)),
    }
}

// Helper macro to be used across modules
pub fn log_message(level: Level, module: &str, message: &str) {
    LOGGER.log(level, module, message);
}