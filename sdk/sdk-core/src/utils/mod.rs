// Cross-platform utility functions.
//
// Migrated from frontend TypeScript to enable sharing between
// web (sdk-wasm) and mobile (sdk-ffi) clients.

use serde::{Deserialize, Serialize};

// ─── File category detection ────────────────────────────────────────────────

/// Broad category for a file, determined by its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileCategory {
    Folder,
    Image,
    Video,
    Pdf,
    Document,
    Spreadsheet,
    Archive,
    Audio,
    Code,
    Unknown,
}

/// Determine the category of a file from its name (extension-based).
pub fn detect_file_type(filename: &str) -> FileCategory {
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "webp" | "ico" | "heic" | "tiff"
        | "tif" => FileCategory::Image,
        "mp4" | "avi" | "mkv" | "mov" | "wmv" | "flv" | "webm" => FileCategory::Video,
        "pdf" => FileCategory::Pdf,
        "doc" | "docx" | "txt" | "md" | "rtf" | "odt" | "pages" => FileCategory::Document,
        "xls" | "xlsx" | "csv" | "ods" | "numbers" => FileCategory::Spreadsheet,
        "zip" | "tar" | "gz" | "rar" | "7z" | "bz2" | "xz" | "zst" => FileCategory::Archive,
        "mp3" | "wav" | "flac" | "aac" | "ogg" | "m4a" | "wma" | "opus" => FileCategory::Audio,
        "js" | "ts" | "jsx" | "tsx" | "py" | "rs" | "java" | "cpp" | "c" | "h" | "html" | "css"
        | "json" | "xml" | "go" | "rb" | "php" | "swift" | "kt" | "sh" | "yaml" | "yml"
        | "toml" | "sql" | "r" | "lua" | "dart" => FileCategory::Code,
        _ => FileCategory::Unknown,
    }
}

/// Return the Phosphor icon name for a file category (per DESIGN.md Section 27).
pub fn file_type_icon(category: FileCategory) -> &'static str {
    match category {
        FileCategory::Folder => "folder",
        FileCategory::Image => "image",
        FileCategory::Video => "video-camera",
        FileCategory::Pdf => "file-text",
        FileCategory::Document => "file-text",
        FileCategory::Spreadsheet => "table",
        FileCategory::Archive => "file-zip",
        FileCategory::Audio => "music-note",
        FileCategory::Code => "file-code",
        FileCategory::Unknown => "file",
    }
}

// ─── MIME type lookup ───────────────────────────────────────────────────────

/// Return a MIME type string for a filename based on its extension.
pub fn mime_type_from_filename(filename: &str) -> &'static str {
    let ext = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        // Images
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "tiff" | "tif" => "image/tiff",
        // Video
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "wmv" => "video/x-ms-wmv",
        "flv" => "video/x-flv",
        // Audio
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "ogg" => "audio/ogg",
        "opus" => "audio/opus",
        "wma" => "audio/x-ms-wma",
        // Documents
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "rtf" => "application/rtf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "odt" => "application/vnd.oasis.opendocument.text",
        // Spreadsheets
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv" => "text/csv",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        // Archives
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        "bz2" => "application/x-bzip2",
        // Code / text
        "html" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "yaml" | "yml" => "text/yaml",
        "toml" => "text/plain",
        _ => "application/octet-stream",
    }
}

// ─── Unique name generation ─────────────────────────────────────────────────

/// Generate a unique filename given a set of existing names.
///
/// If `desired` is not in `existing`, returns it unchanged.
/// Otherwise appends ` (1)`, ` (2)`, etc. before the extension.
pub fn generate_unique_name(desired: &str, existing: &[&str]) -> String {
    if !existing.contains(&desired) {
        return desired.to_string();
    }

    let (base, ext) = match desired.rfind('.') {
        Some(idx) if idx > 0 => (&desired[..idx], &desired[idx..]),
        _ => (desired, ""),
    };

    let mut counter = 1u32;
    loop {
        let candidate = format!("{base} ({counter}){ext}");
        if !existing.iter().any(|n| *n == candidate) {
            return candidate;
        }
        counter += 1;
    }
}

// ─── File size formatting ───────────────────────────────────────────────────

/// Format a byte count as a human-readable string (base-1024 units).
pub fn format_file_size(bytes: u64) -> String {
    if bytes == 0 {
        return "0 Bytes".to_string();
    }

    const UNITS: [&str; 5] = ["Bytes", "KB", "MB", "GB", "TB"];
    let i = (bytes as f64).log(1024.0).floor() as usize;
    let i = i.min(UNITS.len() - 1);
    let value = bytes as f64 / 1024_f64.powi(i as i32);

    if i == 0 {
        format!("{bytes} Bytes")
    } else {
        // Strip trailing zeros: "1.50" → "1.5", "2.00" → "2"
        let s = format!("{value:.2}");
        let s = s.trim_end_matches('0').trim_end_matches('.');
        format!("{s} {}", UNITS[i])
    }
}

// ─── Sorting ────────────────────────────────────────────────────────────────

/// Field to sort by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortBy {
    Name,
    Date,
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// A sortable item — callers extract the relevant fields.
pub fn compare_by_name(a: &str, b: &str, direction: SortDirection) -> std::cmp::Ordering {
    let ord = a.to_lowercase().cmp(&b.to_lowercase());
    match direction {
        SortDirection::Ascending => ord,
        SortDirection::Descending => ord.reverse(),
    }
}

/// Compare two timestamps (ISO-8601 strings or unix seconds as strings).
pub fn compare_by_date(a: &str, b: &str, direction: SortDirection) -> std::cmp::Ordering {
    let ord = a.cmp(b);
    match direction {
        SortDirection::Ascending => ord,
        SortDirection::Descending => ord.reverse(),
    }
}

// ─── Client-side filtering ──────────────────────────────────────────────────

/// Check whether a filename matches a search query (case-insensitive substring).
pub fn matches_query(filename: &str, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    filename.to_lowercase().contains(&query.to_lowercase())
}

/// Check whether a filename's extension matches a file-type filter string.
pub fn matches_file_type(filename: &str, file_type: &str) -> bool {
    if file_type.is_empty() {
        return true;
    }
    let ext = filename.rsplit('.').next().unwrap_or("");
    ext.eq_ignore_ascii_case(file_type)
}

/// Check if a date string falls within an optional range.
/// `date`, `from`, `to` are ISO-8601 date strings (e.g. "2025-01-15T10:00:00Z").
/// Lexicographic comparison works for ISO-8601.
pub fn matches_date_range(date: &str, from: Option<&str>, to: Option<&str>) -> bool {
    if let Some(f) = from {
        if date < f {
            return false;
        }
    }
    if let Some(t) = to {
        if date > t {
            return false;
        }
    }
    true
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── File type detection ──

    #[test]
    fn detect_common_types() {
        assert_eq!(detect_file_type("photo.jpg"), FileCategory::Image);
        assert_eq!(detect_file_type("photo.JPEG"), FileCategory::Image);
        assert_eq!(detect_file_type("clip.mp4"), FileCategory::Video);
        assert_eq!(detect_file_type("report.pdf"), FileCategory::Pdf);
        assert_eq!(detect_file_type("notes.txt"), FileCategory::Document);
        assert_eq!(detect_file_type("data.xlsx"), FileCategory::Spreadsheet);
        assert_eq!(detect_file_type("backup.zip"), FileCategory::Archive);
        assert_eq!(detect_file_type("song.mp3"), FileCategory::Audio);
        assert_eq!(detect_file_type("main.rs"), FileCategory::Code);
        assert_eq!(detect_file_type("README"), FileCategory::Unknown);
        assert_eq!(detect_file_type("no_ext"), FileCategory::Unknown);
    }

    #[test]
    fn icon_names_match_design_md() {
        assert_eq!(file_type_icon(FileCategory::Folder), "folder");
        assert_eq!(file_type_icon(FileCategory::Image), "image");
        assert_eq!(file_type_icon(FileCategory::Archive), "file-zip");
        assert_eq!(file_type_icon(FileCategory::Unknown), "file");
    }

    // ── MIME type ──

    #[test]
    fn mime_types() {
        assert_eq!(mime_type_from_filename("a.jpg"), "image/jpeg");
        assert_eq!(mime_type_from_filename("a.PDF"), "application/pdf");
        assert_eq!(
            mime_type_from_filename("a.unknown"),
            "application/octet-stream"
        );
        assert_eq!(mime_type_from_filename("noext"), "application/octet-stream");
    }

    // ── Unique name ──

    #[test]
    fn unique_name_no_conflict() {
        assert_eq!(generate_unique_name("file.txt", &["other.txt"]), "file.txt");
    }

    #[test]
    fn unique_name_increments() {
        let existing = vec!["file.txt", "file (1).txt"];
        assert_eq!(generate_unique_name("file.txt", &existing), "file (2).txt");
    }

    #[test]
    fn unique_name_no_extension() {
        assert_eq!(generate_unique_name("README", &["README"]), "README (1)");
    }

    #[test]
    fn unique_name_dot_at_start() {
        assert_eq!(
            generate_unique_name(".gitignore", &[".gitignore"]),
            ".gitignore (1)"
        );
    }

    // ── File size formatting ──

    #[test]
    fn format_sizes() {
        assert_eq!(format_file_size(0), "0 Bytes");
        assert_eq!(format_file_size(500), "500 Bytes");
        assert_eq!(format_file_size(1024), "1 KB");
        assert_eq!(format_file_size(1536), "1.5 KB");
        assert_eq!(format_file_size(1_048_576), "1 MB");
        assert_eq!(format_file_size(1_073_741_824), "1 GB");
    }

    // ── Sorting ──

    #[test]
    fn sort_by_name() {
        use std::cmp::Ordering;
        assert_eq!(
            compare_by_name("alpha", "Beta", SortDirection::Ascending),
            Ordering::Less
        );
        assert_eq!(
            compare_by_name("alpha", "Beta", SortDirection::Descending),
            Ordering::Greater
        );
    }

    // ── Filtering ──

    #[test]
    fn query_matching() {
        assert!(matches_query("Photo_2025.jpg", "photo"));
        assert!(matches_query("Photo_2025.jpg", ""));
        assert!(!matches_query("Photo_2025.jpg", "video"));
    }

    #[test]
    fn file_type_matching() {
        assert!(matches_file_type("photo.jpg", "jpg"));
        assert!(matches_file_type("photo.JPG", "jpg"));
        assert!(!matches_file_type("photo.jpg", "png"));
        assert!(matches_file_type("photo.jpg", ""));
    }

    #[test]
    fn date_range_matching() {
        assert!(matches_date_range(
            "2025-06-15",
            Some("2025-01-01"),
            Some("2025-12-31")
        ));
        assert!(!matches_date_range("2024-06-15", Some("2025-01-01"), None));
        assert!(matches_date_range("2025-06-15", None, None));
    }
}
