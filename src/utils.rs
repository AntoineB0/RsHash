//! Utility functions for byte manipulation and endianness conversions.

/// Converts a byte slice to u32 in big-endian order.
pub fn bytes_to_u32_be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Converts a byte slice to u64 in big-endian order.
pub fn bytes_to_u64_be(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Converts u32 to bytes in big-endian order.
pub fn u32_to_bytes_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

/// Converts u64 to bytes in big-endian order.
pub fn u64_to_bytes_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_conversion() {
        let value: u32 = 0x12345678;
        let bytes = u32_to_bytes_be(value);
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(bytes_to_u32_be(&bytes), value);
    }

    #[test]
    fn test_u64_conversion() {
        let value: u64 = 0x123456789ABCDEF0;
        let bytes = u64_to_bytes_be(value);
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(bytes_to_u64_be(&bytes), value);
    }
}
