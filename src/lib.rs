//! Fast cryptographic hash functions implemented in Rust for Python.
//!
//! RsHash provides high-performance implementations of SHA-256 and SHA-512
//! with a Python API compatible with the standard `hashlib` module.
//!
//! # Features
//!
//! - Pure Rust implementations following FIPS 180-4
//! - hashlib-compatible API
//! - Incremental hashing support
//! - Zero-copy operations where possible
//!
//! # Examples
//!
//! ```python
//! import RsHash
//!
//! # Direct hashing
//! hasher = RsHash.SHA256(b"hello world")
//! print(hasher.hexdigest())
//!
//! # Incremental hashing
//! hasher = RsHash.SHA256()
//! hasher.update(b"hello ")
//! hasher.update(b"world")
//! print(hasher.hexdigest())
//!
//! # Factory function
//! hasher = RsHash.new("sha512", b"data")
//! print(hasher.digest())
//! ```

use pyo3::prelude::*;

mod core;
mod python;
#[allow(dead_code)]
mod utils;

/// Python module initialization.
///
/// Exposes SHA256, SHA512 classes and the `new()` factory function.
#[pymodule]
#[pyo3(name = "RsHash")]
fn rshash(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<python::PySHA256>()?;
    m.add_class::<python::PySHA512>()?;
    m.add_function(wrap_pyfunction!(python::new, m)?)?;
    
    Ok(())
}
