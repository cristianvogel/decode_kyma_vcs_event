/*
Custom decoder for optimised "/vcs" packets
⇐ /vcs,b { byteCount, int_id0,
Notification of change of value of
float_value0, ... }
one or more VCS widgets and "Optimize Kyma Control Communication”
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


fn decode_kyma_vcs_event_blob(buf: &[u8]) -> Result<Vec<(i32, f32)>, String> {
    // Initial checks
    if buf.len() < 12 {
        return Err("Buffer is too small to contain required fields".to_string());
    }

    // Read and validate the address pattern
    let addr_end = buf.iter().position(|&b| b == 0).ok_or("Address pattern not null-terminated")?;
    let address = std::str::from_utf8(&buf[..addr_end]).map_err(|_| "Invalid UTF-8 in address pattern")?;
    if address != "/vcs" {
        return Err(format!("Unexpected address pattern: {} (expected '/vcs')", address));
    }

    let addr_padded_len = (addr_end + 4) & !3;    // Address pattern must be padded to 4 bytes

    // Read and validate the type tag
    let type_tag_start = addr_padded_len;
    if buf[type_tag_start] != b',' || buf[type_tag_start + 1] != b'b' {
        return Err("Invalid type tag, expected `,b`".to_string());
    }

    // Type tag must be padded to 4 bytes
    let type_tag_padded_len = type_tag_start + 4;

    // Read the blob length (next 4 bytes, big-endian)
    let blob_length_offset = type_tag_padded_len;
    let blob_length_bytes = buf.get(blob_length_offset..blob_length_offset + 4).ok_or("Buffer too short for blob length")?;
    let blob_length = u32::from_be_bytes(blob_length_bytes.try_into().unwrap()) as usize;

    // Read the blob data
    let blob_start = blob_length_offset + 4;
    let blob_end = blob_start + blob_length;
    let blob_data = buf.get(blob_start..blob_end).ok_or("Buffer too short for blob data")?;

    // Decode the blob data (8 bytes per EventID/value pair)
    if blob_length % 8 != 0 {
        return Err("Blob length is not a multiple of 8".to_string());
    }
    
    let mut results = Vec::with_capacity(blob_length / 8);
    // Return empty Vec if there were no events
    if blob_length == 0 {
        return Ok(results)
    }
    // Builder for EventId, Value results
    for chunk in blob_data.chunks_exact(8) {
        let event_id = i32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let value = f32::from_be_bytes(chunk[4..8].try_into().unwrap());
        results.push((event_id, value));
    }

    Ok(results)
}

fn main() {
    let buf: &[u8] = b"/vcs\0\0\0\0,b\0\0\0\0\0\0\0\0"; // Minimal valid data
    
    match decode_kyma_vcs_event_blob(buf) {
        Ok(result) => println!("Decoded successfully: {:?}", result),
        Err(err) => eprintln!("Error decoding packet: {}", err),
    }
}

#[test]
fn test_vcs_decoder() {
    let buf = b"/vcs\0\0\0\0,b\0\0\0\0\0\0\0\0"; // Empty blob
    assert_eq!(decode_kyma_vcs_event_blob(buf), Ok(vec![]));
}