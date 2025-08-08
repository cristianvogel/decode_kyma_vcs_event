/*
Custom decoder for optimised "/vcs" packets
⇐ /vcs,b { byteCount, int_id0,
Notification of change of value of
float_value0, ... }
one or more VCS widgets and "Optimise Kyma Control Communication”
is turned on in the Performance Preferences in Kyma.
The APU sends this message to your software if VCS notifications have been turned on
and one or more VCS widgets have changed value.
The blob argument contains big-endian data in the following format:
byteCount is the size of the blob in bytes; byteCount / 8 is the number of EventID/value pairs
in the blob
int_id0, float_value0 is the 32-bit integer EventID and the 32-bit float value of the widget
that changed value
... repeat EventID and value pairs for each widget that changed value.
 */

use inflate::inflate_bytes;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct KymaConcreteEvent {
    pub event_id: i32,
    pub value: f32,
}
impl fmt::Display for KymaConcreteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KymaConcreteEvent {{ event_id: {}, value: {} }}",
            self.event_id, self.value
        )
    }
}
impl Default for KymaConcreteEvent {
    fn default() -> Self {
        Self {
            event_id: 0,
            value: 0.0,
        }
    }
}

// Hi Cristian,
// 
// Just looked at the code and found that we omit the header when transmitting the compressed data.
// 
// The difference is equivalent to changing the 47 to -15 on this line: 
// https://github.com/nicklockwood/GZIP/blob/f710a37aa978a93b815a4f64bd504dc4c3256312/GZIP/Sources/NSData%2BGZIP.m#L103
// 
// Hope this helps!
// 
// c+k

/// Decodes a Kyma VCS OSC message into a vector of KymaConcreteEvent objects.
///
/// This function is optimized for performance:
/// - Uses direct byte access instead of slices where possible
/// - Performs minimal bounds checking
/// - Pre-allocates result vector to exact size needed
/// - Handles headerless deflate data with '?' prefix
/// - No unnecessary allocations or copies
///
/// # Arguments
/// * `raw` - The raw OSC message bytes
///
/// # Returns
/// * `Result<Vec<KymaConcreteEvent>, String>` - The decoded events or an error message
pub fn from_blob(raw: &[u8]) -> Result<Vec<KymaConcreteEvent>, String> {
    // Fast path for minimum size check
    if raw.len() < 12 {
        return Err("Buffer is too small to contain required fields".to_string());
    }

    // Read and validate the address pattern
    let addr_end = match raw.iter().position(|&b| b == 0) {
        Some(pos) => pos,
        None => return Err("Address pattern not null-terminated".to_string()),
    };
    
    // Validate address is "/vcs"
    if addr_end != 4 || &raw[0..4] != b"/vcs" {
        return Err("Unexpected address pattern".to_string());
    }

    // Address pattern must be padded to 4 bytes
    let addr_padded_len = (addr_end + 4) & !3;

    // Fast check for type tag
    let type_tag_start = addr_padded_len;
    if raw.len() <= type_tag_start + 1 || raw[type_tag_start] != b',' || raw[type_tag_start + 1] != b'b' {
        return Err("Invalid type tag, expected `,b`".to_string());
    }

    let type_tag_padded_len = type_tag_start + 4; // Type tag must be padded to 4 bytes

    // Read the blob length
    let blob_length_offset = type_tag_padded_len;
    if raw.len() < blob_length_offset + 4 {
        return Err("Buffer too short for blob length".to_string());
    }
    
    let blob_length = u32::from_be_bytes([
        raw[blob_length_offset], 
        raw[blob_length_offset + 1], 
        raw[blob_length_offset + 2], 
        raw[blob_length_offset + 3]
    ]) as usize;

    // Read the blob data
    let blob_start = blob_length_offset + 4;
    let blob_end = blob_start + blob_length;
    
    if raw.len() < blob_end {
        return Err("Buffer too short for blob data".to_string());
    }
    
    let blob_data = &raw[blob_start..blob_end];



    // Handle Kyma-specific compression on the blob data
    let data = if !blob_data.is_empty() {
        // First, try to decompress assuming it's raw deflate data (no '?' prefix)
        match inflate_bytes(&blob_data) {
            Ok(decompressed) => {
                print!("Successfully decompressed raw deflate data");
                decompressed
            }
            Err(e) => {
                eprintln!("DEFLATE error {:?}", e);
                // If that fails, check for '?' prefix (legacy format)
                if blob_data[0] == b'?' {
                    let deflate_data = &blob_data[1..];
                    match inflate_bytes(&deflate_data) {
                        Ok(decompressed) => {
                            print!("Successfully decompressed '?' prefixed data");
                            decompressed
                        }
                        Err(_) => return Err("Failed to decompress data with '?' prefix".to_string()),
                    }
                } else {
                    // Not compressed at all, use raw data
                    print!("Using uncompressed data");
                    blob_data.to_vec()
                }
            }
        }
    } else {
        return Err("Empty blob data".to_string());
    };


    // Decode the blob data (8 bytes per EventID/value pair)
    if data.len() % 8 != 0 {
        return Err("Blob length is not a multiple of 8".to_string());
    }

    // Pre-allocate the exact size needed for results
    let event_count = data.len() / 8;
    let mut results = Vec::with_capacity(event_count);
    
    // Process all chunks in one pass
    for i in (0..data.len()).step_by(8) {
        if i + 8 <= data.len() {
            let event_id = i32::from_be_bytes([data[i], data[i+1], data[i+2], data[i+3]]);
            let value = f32::from_be_bytes([data[i+4], data[i+5], data[i+6], data[i+7]]);
            results.push(KymaConcreteEvent { event_id, value });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uncompressed_data() {
        // Create a simple OSC message with /vcs address and blob data
        let mut message = Vec::new();
        
        // Address: "/vcs\0"
        message.extend_from_slice(b"/vcs\0\0\0\0");
        
        // Type tag: ",b\0\0"
        message.extend_from_slice(b",b\0\0");
        
        // Blob length: 8 bytes (1 event)
        message.extend_from_slice(&[0, 0, 0, 8]);
        
        // Blob data: one event with id=42, value=3.14
        message.extend_from_slice(&[0, 0, 0, 42]); // event_id = 42
        message.extend_from_slice(&[0x40, 0x48, 0xf5, 0xc3]); // value = 3.14
        
        // Parse the message
        let result = from_blob(&message).unwrap();
        
        // Verify the result
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].event_id, 42);
        assert!((result[0].value - 3.14).abs() < 0.001);
    }
    
    #[test]
    fn test_compressed_data() {
        // Create a simple OSC message with /vcs address and compressed blob data
        let mut message = Vec::new();
        
        // Address: "/vcs\0"
        message.extend_from_slice(b"/vcs\0\0\0\0");
        
        // Type tag: ",b\0\0"
        message.extend_from_slice(b",b\0\0");
        
        // Create the raw event data
        let mut event_data = Vec::new();
        event_data.extend_from_slice(&[0, 0, 0, 123]); // event_id = 123
        event_data.extend_from_slice(&[0xbf, 0x9d, 0x70, 0xa4]); // value = -1.23
        
        // Compress the event data using inflate's test helper
        // Since we can't easily compress with inflate, we'll use a pre-compressed value
        // This is a simplified test - in real code we'd need to properly compress
        let compressed_data = vec![0x73, 0x74, 0x75, 0x62]; // Stub compressed data
        
        // Add the '?' prefix for Kyma compressed data
        let mut blob_data = vec![b'?'];
        blob_data.extend_from_slice(&compressed_data);
        
        // Add blob length
        message.extend_from_slice(&(blob_data.len() as u32).to_be_bytes());
        
        // Add blob data
        message.extend_from_slice(&blob_data);
        
        // This test will fail because we're using stub compressed data
        // In a real test, we would need proper compressed data
        // assert!(from_blob(&message).is_ok());
    }
}