#  RsHash

Fast cryptographic hash functions in Rust for Python.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78%2B-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

High-performance SHA-256 and SHA-512 with a hashlib-compatible API. Pure Rust implementation following FIPS 180-4.

## Benchmark Results

### Average Times (ms)
| Data Size | hashlib 256 | RsHash 256 | hashlib 512 | RsHash 512 |
|---:|---:|---:|---:|---:|
| 512 B  | 0.005 | 0.010 | 0.006 | 0.026 |
| 1 KB   | 0.003 | 0.027 | 0.008 | 0.026 |
| 10 KB  | 0.020 | 0.096 | 0.031 | 0.088 |
| 100 KB | 0.122 | 0.463 | 0.157 | 0.297 |
| 512 KB | 0.347 | 2.507 | 1.848 | 1.956 |
| 1 MB   | 0.699 | 8.354 | 3.393 | 4.644 |
| 4 MB   | 3.044 | 21.792 | 10.722 | 12.194 |
| 16 MB  | 19.779 | 73.476 | 28.720 | 53.928 |

### Throughput (MB/s)
| Data Size | hashlib 256 | RsHash 256 | hashlib 512 | RsHash 512 |
|---:|---:|---:|---:|---:|
| 512 B  | 105.37 | 49.38  | 82.22  | 18.78  |
| 1 KB   | 374.16 | 36.34  | 123.11 | 37.73  |
| 10 KB  | 482.13 | 101.45 | 318.63 | 111.50 |
| 100 KB | 801.41 | 210.95 | 622.48 | 329.24 |
| 512 KB | 1439.09| 199.42 | 270.56 | 255.59 |
| 1 MB   | 1431.19| 119.70 | 294.75 | 215.35 |
| 4 MB   | 1313.95| 183.56 | 373.07 | 328.03 |
| 16 MB  | 808.93 | 217.76 | 557.10 | 296.69 |

### Overall Performance Ratio (RsHash / hashlib)
- SHA-256: RsHash is 0.21x slower on average  
- SHA-512: RsHash is 0.56x slower on average

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
