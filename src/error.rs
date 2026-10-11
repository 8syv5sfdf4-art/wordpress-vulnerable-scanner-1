//! Error types for WordPress vulnerability scanner

use std::io;
use thiserror::Error;

/// Result type alias using our Error
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during vulnerability scanning
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid URL provided
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// HTTP client creation failed
    #[error("failed to create HTTP client: {0}")]
    HttpClient(String),

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpRequest(String),

    /// HTTP response had non-success status
    #[error("HTTP error: status {0}")]
    HttpStatus(u16),

    /// Failed to parse API response
    #[error("failed to parse API response: {0}")]
    ApiParse(String),

    /// Vulnerability API returned an error
    #[error("vulnerability API error: {0}")]
    VulnApi(String),

    /// No input provided (no URL, plugins, themes, or manifest)
    #[error(
        "no input provided: specify a URL, --plugins, --themes, --core, --manifest, or --inventory"
    )]
    NoInput,

    /// Failed to read manifest file
    #[error("failed to read manifest file: {0}")]
    ManifestRead(String),

    /// Failed to parse manifest file
    #[error("failed to parse manifest file: {0}")]
    ManifestParse(String),

    /// Invalid plugin format (expected slug:version)
    #[error("invalid plugin format '{0}': expected 'slug:version' or 'slug'")]
    InvalidPluginFormat(String),

    /// Invalid theme format (expected slug:version)
    #[error("invalid theme format '{0}': expected 'slug:version' or 'slug'")]
    InvalidThemeFormat(String),

    /// Output failed
    #[error("output failed: {0}")]
    OutputFailed(#[from] io::Error),

    /// JSON serialization failed
    #[error("JSON serialization failed: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    /// Invalid output format
    #[error("invalid output format: {0}")]
    InvalidOutputFormat(String),

    /// Invalid severity level
    #[error("invalid severity level: {0}")]
    InvalidSeverity(String),

    /// Wordfence feed could not be read or fetched
    #[error("wordfence: {0}")]
    Wordfence(String),

    /// Inventory could not be taken
    #[error("inventory failed: {0}")]
    Inventory(String),

    /// Local database is unusable (unknown format, unreadable index)
    #[error("local database: {0}")]
    Database(String),

    /// Aliases file could not be read or is invalid
    #[error("invalid aliases file: {0}")]
    Aliases(String),

    /// Settings (`.env` file, environment variables) are missing or invalid
    #[error("configuration: {0}")]
    Config(String),
}
