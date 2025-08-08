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

use flate2::read::{GzDecoder, DeflateDecoder};
use std::fmt;
use std::io::Read;

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

fn is_gzip(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0x1F && data[1] == 0x8B
}

pub fn from_blob(raw: &[u8]) -> Result<Vec<KymaConcreteEvent>, String> {
    // Don't decompress the entire packet - work with raw OSC data first
    let buf = raw;

    // Initial under sized container check
    if buf.len() < 12 {
        return Err("Buffer is too small to contain required fields".to_string());
    }

    // Read and validate the address pattern
    let addr_end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or("Address pattern not null-terminated")?;
    let address =
        std::str::from_utf8(&buf[..addr_end]).map_err(|_| "Invalid UTF-8 in address pattern")?;
    if address != "/vcs" {
        return Err(format!("Unexpected address pattern: {address}"));
    }

    // Address pattern must be padded to 4 bytes
    let addr_padded_len = (addr_end + 4) & !3;

    // Read and validate the type tag
    let type_tag_start = addr_padded_len;
    if buf[type_tag_start] != b',' || buf[type_tag_start + 1] != b'b' {
        return Err("Invalid type tag, expected `,b`".to_string());
    }

    let type_tag_padded_len = type_tag_start + 4; // Type tag must be padded to 4 bytes

    // Read the blob length (next 4 bytes, big-endian)
    let blob_length_offset = type_tag_padded_len;
    let blob_length_bytes = buf
        .get(blob_length_offset..blob_length_offset + 4)
        .ok_or("Buffer too short for blob length")?;
    let blob_length = u32::from_be_bytes(blob_length_bytes.try_into().unwrap()) as usize;

    // Read the blob data
    let blob_start = blob_length_offset + 4;
    let blob_end = blob_start + blob_length;
    let blob_data = buf
        .get(blob_start..blob_end)
        .ok_or("Buffer too short for blob data")?;

    // NOW handle Kyma-specific compression on the blob data
    let data = if !blob_data.is_empty() && blob_data[0] == b'?' {
        // Kyma-specific compression with '?' prefix
        // Kyma strips the gzip header when transmitting compressed data
        // The data is raw deflate stream without headers
        let deflate_data = &blob_data[1..]; // Strip the '?' prefix
        // Use DeflateDecoder for headerless gzip data
        let mut decoder = DeflateDecoder::new(deflate_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
               .map_err(|e| format!("Kyma headerless gzip decompression failed: {e}"))?;
        decompressed
    } else if is_gzip(blob_data) {
        // Raw gzip data (no '?' prefix) - validate it's actually valid gzip
        let mut decoder = GzDecoder::new(blob_data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
               .map_err(|e| format!("Invalid gzip data: {e}"))?;
        decompressed
    } else {
        // Uncompressed data
        blob_data.to_vec()
    };

    // Decode the blob data (8 bytes per EventID/value pair)
    if data.len() % 8 != 0 {
        return Err("Blob length is not a multiple of 8".to_string());
    }

    let mut results = Vec::new();
    for chunk in data.chunks_exact(8) {
        let event_id = i32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let value = f32::from_be_bytes(chunk[4..8].try_into().unwrap());
        results.push(KymaConcreteEvent { event_id, value });
    }

    Ok(results)
}


#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    // Helper to build a /vcs,b OSC packet with given blob content (raw)
    fn build_osc_packet(blob: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        // Address pattern "/vcs" + null terminator
        buf.extend(b"/vcs");
        buf.push(0);

        // Pad to 4 bytes
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // Type tag ",b" + null terminator and pad to 4 bytes
        buf.extend(b",b");
        buf.push(0);
        while buf.len() % 4 != 0 {
            buf.push(0);
        }

        // Blob length (big-endian u32)
        let len = blob.len() as u32;
        buf.extend(len.to_be_bytes());
        // Blob data
        buf.extend(blob);
        buf
    }

    #[test]
    fn test_from_blob_with_uncompressed_data() {
        // Event: event_id = 42, value = 3.14
        let mut blob = Vec::new();
        blob.extend(42i32.to_be_bytes());
        blob.extend(3.14f32.to_be_bytes());

        let packet = build_osc_packet(&blob);
        let events = from_blob(&packet).unwrap();
        println!("=== blob, no gzip ===");
        dbg!(&events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 42);
        assert!((events[0].value - 3.14).abs() < 1e-6);
    }

    #[test]
    fn test_from_blob_with_gzipped_data() {
        // Event: event_id = 123, value = -1.23
        let mut blob = Vec::new();
        blob.extend(123i32.to_be_bytes());
        blob.extend((-1.23f32).to_be_bytes());

        // Use DeflateEncoder for headerless gzip data
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&blob).unwrap();
        let compressed = encoder.finish().unwrap();
        // add the Kyma specific '?' isGzip flag
        let mut final_blob = vec![b'?'];
        final_blob.extend_from_slice(&*compressed);


        let packet = build_osc_packet(&final_blob);
        let events = from_blob(&packet).unwrap();
        println!("=== blob, gzip decompressed ===");
        dbg!(&events);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 123);
        assert!((events[0].value + 1.23).abs() < 1e-6);
    }

    #[test]
    fn test_from_blob_with_invalid_data() {
        // Blob with wrong size (not divisible by 8)
        let blob = vec![0, 1, 2, 3, 4, 5, 6];
        let packet = build_osc_packet(&blob);
        let res = from_blob(&packet);
        assert!(res.is_err());
    }

    #[test]
    fn test_from_blob_with_invalid_gzip() {
        // Blob starts with gzip magic but is not valid gzip
        let blob = vec![0x1F, 0x8B, 0, 1, 2, 3, 4, 5, 6, 7];
        let packet = build_osc_packet(&blob);
        let res = from_blob(&packet);
        assert!(res.is_err());
    }
}