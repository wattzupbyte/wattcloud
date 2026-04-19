#![deny(clippy::unwrap_used, clippy::expect_used)]

pub mod api;
pub mod byo;
pub mod crypto;
pub mod error;
pub mod exif;
pub mod keys;
pub mod utils;
pub mod validation;

pub fn health_check() -> &'static str {
    "sdk-core ok"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check() {
        assert_eq!(health_check(), "sdk-core ok");
    }
}
