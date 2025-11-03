//! Core hash algorithm implementations.
//!
//! Pure Rust implementations of SHA-2 family algorithms following
//! the FIPS 180-4 specification.
//!
//! # Algorithms
//!
//! - [`Sha256`] - SHA-256 (256-bit output)
//! - [`Sha512`] - SHA-512 (512-bit output)
//!
//! # Usage
//!
//! These are low-level implementations. For Python usage, see the
//! top-level module documentation.

pub mod sha256;
pub mod sha512;

pub use sha256::Sha256;
pub use sha512::Sha512;
