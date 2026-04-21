use std::fs::OpenOptions;
use std::io::Write;
use chrono::Local;

pub struct Logger {
    pub file_path: String,
} 

impl Logger {
    fn log_event(&self, event: &str) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path).unwrap();
        
        writeln!(file, "{}", event).unwrap();
    }

    pub fn log_info(&self, text: &str) {
        // Get current local time
        let now = Local::now();
        // Use strftime-like formatting
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();

        let event: &str = &format!("[{}] - [INFO] - {}", formatted_time, text).to_string();
        self.log_event(event);
    }

    pub fn log_debug(&self, text: &str) {
        // Get current local time
        let now = Local::now();
        // Use strftime-like formatting
        let formatted_time = now.format("%Y-%m-%d %H:%M:%S").to_string();

        let event: &str = &format!("[{}] - [DEBUG] - {}", formatted_time, text).to_string();
        self.log_event(event);
    }
}