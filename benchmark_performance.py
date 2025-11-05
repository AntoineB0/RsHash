"""
Performance Benchmark: hashlib vs RsHash

Compare the performance of Python's built-in hashlib against RsHash
for SHA-256 and SHA-512 hashing algorithms.

Usage:
    python benchmark_performance.py

Requirements:
    pip install pytest-benchmark
    maturin develop (to build RsHash)
"""

import hashlib
import time
import os
from typing import Callable, Dict, List, Tuple

try:
    import RsHash
    RSHASH_AVAILABLE = True
except ImportError:
    RSHASH_AVAILABLE = False
    print("Warning: RsHash not available. Run 'maturin develop' first.")


# Test data sizes (in bytes) with adaptive iterations
# Format: "name": (size_bytes, iterations)
# Note: RsHash shows performance issues with large data, so we reduce iterations
DATA_SIZES = {
    "512 B": (512, 200),
    "1 KB": (1024, 200),
    "10 KB": (10 * 1024, 100),
    "100 KB": (100 * 1024, 50),
    "512 KB": (512 * 1024, 40),
    "1 MB": (1024 * 1024, 25),
    "4 MB": (4 * 1024 * 1024, 10),
    "16 MB": (16 * 1024 * 1024, 3),  # large sizes use very few iterations due to RsHash limitations
}


def generate_test_data(size: int) -> bytes:
    """Generate random test data of specified size."""
    return os.urandom(size)


def benchmark_function(func: Callable, data: bytes, iterations: int) -> Tuple[float, float]:
    """
    Benchmark a hashing function.
    
    Returns:
        Tuple of (average_time_ms, throughput_mb_per_sec)
    """
    times = []
    
    for _ in range(iterations):
        start = time.perf_counter()
        func(data)
        end = time.perf_counter()
        times.append(end - start)
    
    avg_time = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)
    
    # Calculate throughput in MB/s
    data_size_mb = len(data) / (1024 * 1024)
    throughput = data_size_mb / avg_time
    
    return avg_time * 1000, throughput  # Convert to ms


def hashlib_sha256(data: bytes) -> str:
    """Hash data using hashlib SHA-256."""
    return hashlib.sha256(data).hexdigest()


def rshash_sha256(data: bytes) -> str:
    """Hash data using RsHash SHA-256."""
    hasher = RsHash.SHA256()
    hasher.update(data)
    return hasher.hexdigest()


def hashlib_sha512(data: bytes) -> str:
    """Hash data using hashlib SHA-512."""
    return hashlib.sha512(data).hexdigest()


def rshash_sha512(data: bytes) -> str:
    """Hash data using RsHash SHA-512."""
    hasher = RsHash.SHA512()
    hasher.update(data)
    return hasher.hexdigest()


def run_benchmark_suite():
    """Run complete benchmark suite."""
    
    if not RSHASH_AVAILABLE:
        print("\n❌ RsHash not available. Please run 'maturin develop' to build the module.")
        return
    
    print("=" * 80)
    print("Performance Benchmark: hashlib vs RsHash")
    print("=" * 80)
    print("Iterations vary by data size (100 for small, fewer for large)")
    print()
    
    results: Dict[str, Dict[str, Tuple[float, float]]] = {}
    
    # Run benchmarks for each data size
    for size_name, (size_bytes, iterations) in DATA_SIZES.items():
        print(f"\n{'=' * 80}")
        print(f"Testing with {size_name} data ({size_bytes:,} bytes, {iterations} iterations)")
        print('=' * 80)
        
        # Generate test data
        test_data = generate_test_data(size_bytes)
        
        results[size_name] = {}
        
        # SHA-256 benchmarks
        print("\nSHA-256:")
        print("-" * 40)
        
        print("  hashlib.sha256()...", end=" ", flush=True)
        hashlib_256_time, hashlib_256_throughput = benchmark_function(
            hashlib_sha256, test_data, iterations
        )
        results[size_name]["hashlib_sha256"] = (hashlib_256_time, hashlib_256_throughput)
        print(f"✓ {hashlib_256_time:.3f} ms ({hashlib_256_throughput:.2f} MB/s)")
        
        print("  RsHash.sha256()...", end=" ", flush=True)
        rshash_256_time, rshash_256_throughput = benchmark_function(
            rshash_sha256, test_data, iterations
        )
        results[size_name]["rshash_sha256"] = (rshash_256_time, rshash_256_throughput)
        print(f"✓ {rshash_256_time:.3f} ms ({rshash_256_throughput:.2f} MB/s)")
        
        # Calculate speedup
        speedup_256 = hashlib_256_time / rshash_256_time
        if speedup_256 > 1:
            print(f"  → RsHash is {speedup_256:.2f}x FASTER")
        elif speedup_256 < 1:
            print(f"  → hashlib is {1/speedup_256:.2f}x FASTER")
        else:
            print(f"  → Performance is EQUAL")
        
        # SHA-512 benchmarks
        print("\nSHA-512:")
        print("-" * 40)
        
        print("  hashlib.sha512()...", end=" ", flush=True)
        hashlib_512_time, hashlib_512_throughput = benchmark_function(
            hashlib_sha512, test_data, iterations
        )
        results[size_name]["hashlib_sha512"] = (hashlib_512_time, hashlib_512_throughput)
        print(f"✓ {hashlib_512_time:.3f} ms ({hashlib_512_throughput:.2f} MB/s)")
        
        print("  RsHash.sha512()...", end=" ", flush=True)
        rshash_512_time, rshash_512_throughput = benchmark_function(
            rshash_sha512, test_data, iterations
        )
        results[size_name]["rshash_sha512"] = (rshash_512_time, rshash_512_throughput)
        print(f"✓ {rshash_512_time:.3f} ms ({rshash_512_throughput:.2f} MB/s)")
        
        # Calculate speedup
        speedup_512 = hashlib_512_time / rshash_512_time
        if speedup_512 > 1:
            print(f"  → RsHash is {speedup_512:.2f}x FASTER")
        elif speedup_512 < 1:
            print(f"  → hashlib is {1/speedup_512:.2f}x FASTER")
        else:
            print(f"  → Performance is EQUAL")
    
    # Summary table
    print("\n\n" + "=" * 80)
    print("SUMMARY - Average Times (ms)")
    print("=" * 80)
    print(f"{'Data Size':<15} {'hashlib 256':<15} {'RsHash 256':<15} {'hashlib 512':<15} {'RsHash 512':<15}")
    print("-" * 80)
    
    for size_name in DATA_SIZES.keys():
        hashlib_256 = results[size_name]["hashlib_sha256"][0]
        rshash_256 = results[size_name]["rshash_sha256"][0]
        hashlib_512 = results[size_name]["hashlib_sha512"][0]
        rshash_512 = results[size_name]["rshash_sha512"][0]
        
        print(f"{size_name:<15} {hashlib_256:<15.3f} {rshash_256:<15.3f} {hashlib_512:<15.3f} {rshash_512:<15.3f}")
    
    print("\n" + "=" * 80)
    print("SUMMARY - Throughput (MB/s)")
    print("=" * 80)
    print(f"{'Data Size':<15} {'hashlib 256':<15} {'RsHash 256':<15} {'hashlib 512':<15} {'RsHash 512':<15}")
    print("-" * 80)
    
    for size_name in DATA_SIZES.keys():
        hashlib_256_tp = results[size_name]["hashlib_sha256"][1]
        rshash_256_tp = results[size_name]["rshash_sha256"][1]
        hashlib_512_tp = results[size_name]["hashlib_sha512"][1]
        rshash_512_tp = results[size_name]["rshash_sha512"][1]
        
        print(f"{size_name:<15} {hashlib_256_tp:<15.2f} {rshash_256_tp:<15.2f} {hashlib_512_tp:<15.2f} {rshash_512_tp:<15.2f}")
    
    print("\n" + "=" * 80)
    print("Overall Performance Ratio (RsHash / hashlib)")
    print("=" * 80)
    
    # Calculate average speedup across all sizes
    total_speedup_256 = 0
    total_speedup_512 = 0
    count = len(DATA_SIZES)
    
    for size_name in DATA_SIZES.keys():
        hashlib_256_time = results[size_name]["hashlib_sha256"][0]
        rshash_256_time = results[size_name]["rshash_sha256"][0]
        hashlib_512_time = results[size_name]["hashlib_sha512"][0]
        rshash_512_time = results[size_name]["rshash_sha512"][0]
        
        total_speedup_256 += hashlib_256_time / rshash_256_time
        total_speedup_512 += hashlib_512_time / rshash_512_time
    
    avg_speedup_256 = total_speedup_256 / count
    avg_speedup_512 = total_speedup_512 / count
    
    print(f"SHA-256: RsHash is {avg_speedup_256:.2f}x {'faster' if avg_speedup_256 > 1 else 'slower'} on average")
    print(f"SHA-512: RsHash is {avg_speedup_512:.2f}x {'faster' if avg_speedup_512 > 1 else 'slower'} on average")
    print()


if __name__ == "__main__":
    run_benchmark_suite()
