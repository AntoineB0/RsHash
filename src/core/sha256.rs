//! SHA-256 cryptographic hash function implementation.
//!
//! Pure Rust implementation following FIPS 180-4 specification.
//!
//! # Algorithm Details
//!
//! - **Block size**: 512 bits (64 bytes)
//! - **Digest size**: 256 bits (32 bytes)
//! - **Rounds**: 64
//!
//! # Security
//!
//! SHA-256 is considered cryptographically secure as of 2025.
//! No practical collision attacks are known.

/// SHA-256 hasher state.
///
/// Maintains the internal state for incremental hashing.
/// Uses a fixed-size buffer for optimal streaming performance.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],      // Fixed 64-byte buffer (1 block)
    buffer_len: usize,      // Number of bytes currently in buffer
    total_len: u64,         // Total bytes processed (for final length)
}

impl Sha256 {
    /// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    /// Creates a new SHA-256 hasher with initial state.
    pub fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feeds data into the hasher.
    ///
    /// Processes complete 512-bit blocks immediately with zero-copy streaming.
    /// Only incomplete blocks (< 64 bytes) are buffered.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;
        
        // If buffer has partial data, try to complete it first
        if self.buffer_len > 0 {
            let to_fill = 64 - self.buffer_len;
            let available = data.len().min(to_fill);
            
            self.buffer[self.buffer_len..self.buffer_len + available]
                .copy_from_slice(&data[..available]);
            
            self.buffer_len += available;
            offset += available;
            
            // If buffer is now full, process it immediately
            if self.buffer_len == 64 {
                let block_copy = self.buffer;
                self.process_block(&block_copy);
                self.buffer_len = 0;
            }
        }
        
        // Process complete 64-byte blocks directly from input (zero-copy!)
        while offset + 64 <= data.len() {
            let block: [u8; 64] = data[offset..offset + 64].try_into().unwrap();
            self.process_block(&block);
            offset += 64;
        }
        
        // Buffer any remaining bytes (< 64)
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalizes the hash and returns the digest as bytes.
    ///
    /// Applies padding, processes remaining blocks, and outputs the final 256-bit digest.
    pub fn finalize(&mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        
        // Add padding: 0x80 byte followed by zeros
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        
        // If not enough space for length (need 8 bytes), pad and process block
        if self.buffer_len > 56 {
            // Fill rest with zeros and process
            self.buffer[self.buffer_len..].fill(0);
            let block_copy = self.buffer;
            self.process_block(&block_copy);
            self.buffer.fill(0);
            self.buffer_len = 0;
        }
        
        // Pad with zeros until 56 bytes
        self.buffer[self.buffer_len..56].fill(0);
        
        // Append length as big-endian 64-bit integer
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        
        // Process final block
        let block_copy = self.buffer;
        self.process_block(&block_copy);
        
        // Extract result from state
        let mut result = [0u8; 32];
        for (i, &word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        
        result
    }

    /// Returns the digest as a hexadecimal string.
    pub fn finalize_hex(&mut self) -> String {
        let digest = self.finalize();
        hex::encode(digest)
    }

    /// Processes a single 512-bit block through the SHA-256 compression function.
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    /// Returns the output size in bytes (32 for SHA-256).
    pub fn digest_size() -> usize {
        32
    }

    /// Returns the block size in bytes (64 for SHA-256).
    pub fn block_size() -> usize {
        64
    }
}

mod hex {
    /// Encodes bytes as lowercase hexadecimal string.
    pub fn encode(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize_hex();
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let result = hasher.finalize_hex();
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
