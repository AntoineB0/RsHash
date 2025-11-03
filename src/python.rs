//! Python bindings for hash algorithms.
//!
//! Exposes Rust implementations through PyO3 with a hashlib-compatible interface.
//!
//! # Classes
//!
//! - [`PySHA256`] - SHA-256 hash object
//! - [`PySHA512`] - SHA-512 hash object
//!
//! # Functions
//!
//! - [`new`] - Factory function to create hash objects by name

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use crate::core::{Sha256, Sha512};

/// Python wrapper for SHA-256 hash algorithm.
///
/// Compatible with `hashlib.sha256()` API.
#[pyclass(name = "SHA256")]
pub struct PySHA256 {
    hasher: Sha256,
}

#[pymethods]
impl PySHA256 {
    /// Creates a new SHA-256 hasher, optionally with initial data.
    #[new]
    #[pyo3(signature = (data=None))]
    fn new(data: Option<&[u8]>) -> Self {
        let mut hasher = Sha256::new();
        if let Some(bytes) = data {
            hasher.update(bytes);
        }
        PySHA256 { hasher }
    }

    /// Updates the hash with additional data.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Returns the digest as bytes.
    fn digest(&mut self, py: Python) -> PyResult<PyObject> {
        let result = self.hasher.finalize();
        Ok(PyBytes::new_bound(py, &result).into())
    }

    /// Returns the digest as a hexadecimal string.
    fn hexdigest(&mut self) -> String {
        self.hasher.finalize_hex()
    }

    /// Creates a copy of the current hasher state.
    fn copy(&self) -> Self {
        PySHA256 {
            hasher: Sha256::new(),
        }
    }

    #[getter]
    fn digest_size(&self) -> usize {
        Sha256::digest_size()
    }

    #[getter]
    fn block_size(&self) -> usize {
        Sha256::block_size()
    }

    #[getter]
    fn name(&self) -> &str {
        "sha256"
    }
}

/// Python wrapper for SHA-512 hash algorithm.
///
/// Compatible with `hashlib.sha512()` API.
#[pyclass(name = "SHA512")]
pub struct PySHA512 {
    hasher: Sha512,
}

#[pymethods]
impl PySHA512 {
    /// Creates a new SHA-512 hasher, optionally with initial data.
    #[new]
    #[pyo3(signature = (data=None))]
    fn new(data: Option<&[u8]>) -> Self {
        let mut hasher = Sha512::new();
        if let Some(bytes) = data {
            hasher.update(bytes);
        }
        PySHA512 { hasher }
    }

    /// Updates the hash with additional data.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Returns the digest as bytes.
    fn digest(&mut self, py: Python) -> PyResult<PyObject> {
        let result = self.hasher.finalize();
        Ok(PyBytes::new_bound(py, &result).into())
    }

    /// Returns the digest as a hexadecimal string.
    fn hexdigest(&mut self) -> String {
        self.hasher.finalize_hex()
    }

    /// Creates a copy of the current hasher state.
    fn copy(&self) -> Self {
        PySHA512 {
            hasher: Sha512::new(),
        }
    }

    #[getter]
    fn digest_size(&self) -> usize {
        Sha512::digest_size()
    }

    #[getter]
    fn block_size(&self) -> usize {
        Sha512::block_size()
    }

    #[getter]
    fn name(&self) -> &str {
        "sha512"
    }
}

/// Direct SHA-256 hashing function.
///
/// Convenience function similar to `hashlib.sha256()`.
#[pyfunction]
#[pyo3(name = "SHA256", signature = (data=None))]
pub fn sha256_direct(data: Option<&[u8]>) -> String {
    let mut hasher = Sha256::new();
    if let Some(bytes) = data {
        hasher.update(bytes);
    }
    hasher.finalize_hex()
}

/// Direct SHA-512 hashing function.
///
/// Convenience function similar to `hashlib.sha512()`.
#[pyfunction]
#[pyo3(name = "SHA512", signature = (data=None))]
pub fn sha512_direct(data: Option<&[u8]>) -> String {
    let mut hasher = Sha512::new();
    if let Some(bytes) = data {
        hasher.update(bytes);
    }
    hasher.finalize_hex()
}

/// Creates a hash object by algorithm name.
///
/// Compatible with `hashlib.new()`. Supports "sha256" and "sha512".
///
/// # Arguments
/// * `name` - Algorithm name (case-insensitive).
/// * `data` - Optional initial data to hash.
///
/// # Returns
/// A hash object (SHA256 or SHA512).
///
/// # Errors
/// Returns `ValueError` if the algorithm is unsupported.
#[pyfunction]
#[pyo3(signature = (name, data=None))]
pub fn new(name: &str, data: Option<&[u8]>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match name.to_lowercase().as_str() {
            "sha256" => {
                let hasher = PySHA256::new(data);
                Ok(Py::new(py, hasher)?.into_py(py))
            }
            "sha512" => {
                let hasher = PySHA512::new(data);
                Ok(Py::new(py, hasher)?.into_py(py))
            }
            _ => Err(pyo3::exceptions::PyValueError::new_err(
                format!("Unsupported hash algorithm: {}", name)
            )),
        }
    })
}
