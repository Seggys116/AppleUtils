use std::ops::Range;

use super::{bytes, le32, refusal};

struct Der {
    tag: u8,
    body: Range<usize>,
    end: usize,
}

fn der(data: &[u8], start: usize, limit: usize) -> Result<Der, String> {
    let header = bytes(data, start, 2)?;
    if header[0] & 0x1f == 0x1f {
        return Err(refusal(
            "trustcache-der",
            "high-tag-number encoding is unsupported",
        ));
    }
    let mut offset = start + 2;
    let length = if header[1] & 0x80 == 0 {
        header[1] as usize
    } else {
        let count = (header[1] & 0x7f) as usize;
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(refusal("trustcache-der", "invalid definite length"));
        }
        let encoded = bytes(data, offset, count)?;
        if encoded[0] == 0 {
            return Err(refusal("trustcache-der", "nonminimal length"));
        }
        offset += count;
        let mut length = 0usize;
        for byte in encoded {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(*byte as usize))
                .ok_or_else(|| refusal("trustcache-der", "length overflow"))?;
        }
        if length < 128 {
            return Err(refusal("trustcache-der", "nonminimal long length"));
        }
        length
    };
    let end = offset
        .checked_add(length)
        .ok_or_else(|| refusal("trustcache-der", "length overflow"))?;
    if end > limit {
        return Err(refusal("trustcache-der", "element exceeds container"));
    }
    bytes(data, offset, length)?;
    Ok(Der {
        tag: header[0],
        body: offset..end,
        end,
    })
}

fn payload(data: &[u8]) -> Result<Range<usize>, String> {
    let root = der(data, 0, data.len())?;
    if root.tag != 0x30 || root.end != data.len() {
        return Err(refusal(
            "trustcache-im4p",
            "expected one complete DER sequence",
        ));
    }
    let mut cursor = root.body.start;
    let mut fields = Vec::new();
    while cursor < root.end {
        let field = der(data, cursor, root.end)?;
        cursor = field.end;
        fields.push(field);
    }
    if fields.len() < 4
        || fields[0].tag != 0x16
        || &data[fields[0].body.clone()] != b"IM4P"
        || fields[1].tag != 0x16
        || &data[fields[1].body.clone()] != b"rtsc"
        || fields[2].tag != 0x16
        || fields[3].tag != 0x04
    {
        return Err(refusal(
            "trustcache-im4p",
            "expected IM4P restore trustcache payload",
        ));
    }
    Ok(fields[3].body.clone())
}

pub(super) fn replace(data: &[u8], old: [u8; 20], new: [u8; 20]) -> Result<Vec<u8>, String> {
    let range = payload(data)?;
    let cache = &data[range.clone()];
    if le32(cache, 0)? != 1 {
        return Err(refusal("trustcache-version", "only v1 entries are proven"));
    }
    let count = le32(cache, 20)? as usize;
    let length = count
        .checked_mul(22)
        .and_then(|n| n.checked_add(24))
        .ok_or_else(|| refusal("trustcache-layout", "entry count overflow"))?;
    if length != cache.len() {
        return Err(refusal(
            "trustcache-layout",
            "v1 payload length disagrees with count",
        ));
    }
    let (chunks, _) = cache[24..].as_chunks::<22>();
    let mut entries: Vec<[u8; 22]> = chunks.to_vec();
    if entries
        .windows(2)
        .any(|pair| pair[0][..20] >= pair[1][..20])
    {
        return Err(refusal(
            "trustcache-order",
            "CDHashes must be sorted and unique",
        ));
    }
    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry[..20] == old).then_some(index))
        .collect();
    if matches.len() != 1 {
        return Err(refusal(
            "trustcache-cdhash",
            format!("expected one old CDHash, found {}", matches.len()),
        ));
    }
    let index = matches[0];
    if entries[index][20] != 2 || entries[index][21] != 0 {
        return Err(refusal(
            "trustcache-entry",
            "expected SHA256 entry with flags zero",
        ));
    }
    if entries
        .iter()
        .enumerate()
        .any(|(i, entry)| i != index && entry[..20] == new)
    {
        return Err(refusal(
            "trustcache-collision",
            "new CDHash already belongs to another entry",
        ));
    }
    entries[index][..20].copy_from_slice(&new);
    entries.sort_by(|a, b| a[..20].cmp(&b[..20]));
    let mut output = data.to_vec();
    for (index, entry) in entries.iter().enumerate() {
        let offset = range.start + 24 + index * 22;
        output[offset..offset + 22].copy_from_slice(entry);
    }
    Ok(output)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn fixture(hashes: &[[u8; 20]]) -> Vec<u8> {
        let mut cache = Vec::from(1u32.to_le_bytes());
        cache.extend_from_slice(&[0x71; 16]);
        cache.extend_from_slice(&(hashes.len() as u32).to_le_bytes());
        for hash in hashes {
            cache.extend_from_slice(hash);
            cache.extend_from_slice(&[2, 0]);
        }
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut result = vec![tag];
            if body.len() < 128 {
                result.push(body.len() as u8);
            } else if body.len() <= 255 {
                result.extend_from_slice(&[0x81, body.len() as u8]);
            } else {
                result.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]);
            }
            result.extend_from_slice(body);
            result
        }
        let mut fields = tlv(0x16, b"IM4P");
        fields.extend(tlv(0x16, b"rtsc"));
        fields.extend(tlv(0x16, b"fixture"));
        fields.extend(tlv(0x04, &cache));
        fields.extend(tlv(0x30, &[]));
        tlv(0x30, &fields)
    }

    #[test]
    fn replacement_resorts_and_preserves_uuid_entry_metadata_and_der() {
        let input = fixture(&[[0x10; 20], [0x20; 20], [0x30; 20], [0x40; 20], [0x50; 20]]);
        let range = payload(&input).unwrap();
        let output = replace(&input, [0x20; 20], [0x60; 20]).unwrap();
        assert_eq!(&output[..range.start + 24], &input[..range.start + 24]);
        assert_eq!(&output[range.end..], &input[range.end..]);
        let expected = fixture(&[[0x10; 20], [0x30; 20], [0x40; 20], [0x50; 20], [0x60; 20]]);
        assert_eq!(output, expected);
    }

    #[test]
    fn malformed_entry_records_named_refusal() {
        let mut input = fixture(&[[0x20; 20]]);
        let range = payload(&input).unwrap();
        input[range.start + 44] = 1;
        assert!(
            replace(&input, [0x20; 20], [0x30; 20])
                .unwrap_err()
                .starts_with("skip-tcon-trustcache-entry:")
        );
    }
}
