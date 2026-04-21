use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Defines the severity level of a log message.
#[derive(Debug, PartialEq, PartialOrd, Eq, Clone, Copy)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    /// Converts the level to a printable string.
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

// --- Global State Management ---

/// The state object that holds the file handle (or a mechanism to open it).
/// It must be thread-safe, hence the Mutex.
struct Logger {
    file_path: String,
    /// The mutex guards access to the underlying file writing logic.
    inner: Mutex<Option<std::fs::File>>,
}

impl Logger {
    /// Creates a new Logger instance.
    fn new(file_path: &str) -> Self {
        Logger {
            file_path: file_path.to_string(),
            inner: Mutex::new(None),
        }
    }

    /// Initializes the logger, ensuring the file is opened/created.
    /// This must be called once at program startup.
    fn init(&self) -> io::Result<()> {
        // Open or create the file in append mode.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&self.file_path)?;

        // Replace the initial None with the opened file handle
        *self.inner.lock().unwrap() = Some(file);
        Ok(())
    }

    /// Core function to write the formatted message to the file.
    fn log(&self, level: Level, module: &str, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| format!("{}", d.as_secs()))
            .unwrap_or_default();

        // Format the log entry: [Timestamp] [LEVEL] [Module] Message
        let log_entry = format!("[{}] [{:^5}] [{}]: {}\n",
                                timestamp,
                                level.as_str(),
                                module,
                                message);

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

/// A globally accessible, thread-safe logger instance.
/// This simulates the initialization of a global logger context.
static LOGGER: once_cell::sync::Lazy<Arc<Logger>> = once_cell::sync::Lazy::new(|| {
    Arc::new(Logger::new("app.log"))
});


/// Initializes the logger by opening the file handle.
/// Must be called once at the beginning of the application.
pub fn initialize_logger() -> Result<(), String> {
    match LOGGER.init() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Failed to initialize logger: {}", e)),
    }
}

/// Helper macro to dispatch the logging logic (simulates the `log` crate facade).
/// Because we are simulating a macro, we use a function that mimics the behavior.
/// This function is the gateway used by other modules.
pub fn log_message(level: Level, module: &str, message: &str) {
    // In a real logger, you might check a global minimum level here.
    // For simplicity, we log everything for this example.
    LOGGER.log(level, module, message);
}

// We must include `once_cell` for the lazy static initialization.
// Add `once_cell = "1.18"` to your Cargo.toml