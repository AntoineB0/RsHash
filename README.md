#  RsHash

Fast cryptographic hash functions in Rust for Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

High-performance SHA-256 and SHA-512 with a hashlib-compatible API. Pure Rust implementation following FIPS 180-4.

## Installation

```bash
pip install maturin
maturin develop              # Development
maturin build --release      # Production wheel
```

**Requirements:** Python ≥ 3.8, Rust ≥ 1.78

## Usage

```python
import RsHash

# Direct hashing
sha = RsHash.SHA256(b"hello world")
print(sha.hexdigest())      # Hex string
print(sha.digest())         # Raw bytes

# Incremental
sha = RsHash.SHA256()
sha.update(b"hello ")
sha.update(b"world")
print(sha.hexdigest())

# Factory function
sha = RsHash.new("sha512", b"data")
print(sha.digest_size)      # 64
print(sha.block_size)       # 128
```

**Algorithms:** SHA-256 (32 bytes), SHA-512 (64 bytes)

## Development

```bash
# Setup
git clone https://github.com/yourusername/RsHash.git
cd RsHash
pip install maturin

# Workflow
maturin develop    # Rebuild after changes
cargo test         # Rust tests
pytest pytests/    # Python tests
cargo fmt          # Format
cargo clippy       # Lint

# Documentation
cargo doc --open   # API docs
```

**Structure:**
```
src/
├── lib.rs         # Module entry
├── python.rs      # PyO3 bindings
├── utils.rs       # Utilities
└── core/
    ├── sha256.rs  # SHA-256
    └── sha512.rs  # SHA-512
```

## Contributing

Fork, create a feature branch, commit, push, and open a PR. Follow code style in `hashlib_com.md`.

## License

MIT License - see [LICENSE](LICENSE).

## Disclaimer

**Educational project.** For production cryptography, use audited libraries like `hashlib` or `cryptography`.

---

**Resources:** [PyO3](https://pyo3.rs/) · [Maturin](https://www.maturin.rs/) · [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
