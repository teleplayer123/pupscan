use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use chrono::Local;

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
        let now = Local::now();
        // Use strftime-like formatting
        let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

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