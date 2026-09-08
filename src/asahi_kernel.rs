use std::io::{self, Write};

fn fields(bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    crate::ramrod::fdr_trust::top_level_elements(bytes)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(start, end)| {
            let field = &bytes[start..end];
            if field.len() < 2 || field[0] & 0x1f == 0x1f {
                return Err("unsupported IM4P DER tag".into());
            }
            let n = field[1];
            let header = if n & 0x80 == 0 {
                2
            } else {
                let count = usize::from(n & 0x7f);
                if count == 0
                    || count > std::mem::size_of::<usize>()
                    || field.len() < 2 + count
                    || field[2] == 0
                {
                    return Err("noncanonical IM4P DER length".into());
                }
                let length = field[2..2 + count]
                    .iter()
                    .try_fold(0usize, |v, b| {
                        v.checked_mul(256)?.checked_add(usize::from(*b))
                    })
                    .ok_or("DER length overflow")?;
                if length < 128 {
                    return Err("noncanonical IM4P DER length".into());
                }
                2 + count
            };
            Ok((field[0], &field[header..]))
        })
        .collect()
}

fn integer(field: &(u8, &[u8])) -> Result<usize, String> {
    let (tag, bytes) = field;
    if *tag != 2
        || bytes.is_empty()
        || bytes[0] & 0x80 != 0
        || (bytes.len() > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0)
    {
        return Err("invalid IM4P compression integer".into());
    }
    bytes
        .iter()
        .try_fold(0usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })
        .ok_or("IM4P compression integer overflow".into())
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decoded kernel exceeds output bound",
                )
            })?;
        self.bytes
            .try_reserve(length - self.bytes.len())
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecodedIm4p {
    pub payload_type: [u8; 4],
    pub bytes: Vec<u8>,
}

pub fn decode_im4p(bytes: &[u8], maximum_output: usize) -> Result<DecodedIm4p, String> {
    let outer = fields(bytes)?;
    if outer.len() != 1 || outer[0].0 != 0x30 {
        return Err("kernel must be one IM4P SEQUENCE".into());
    }
    let inner = fields(outer[0].1)?;
    if inner.len() < 4
        || inner[0] != (0x16, b"IM4P".as_slice())
        || (inner[1].0 != 0x16 || inner[1].1.len() != 4 || !inner[1].1.is_ascii())
        || inner[2].0 != 0x16
        || !inner[2].1.is_ascii()
        || inner[3].0 != 4
    {
        return Err("invalid kernel IM4P fields".into());
    }
    let mut compression = None;
    let mut properties = false;
    for field in &inner[4..] {
        match field.0 {
            4 => return Err("encrypted IM4P kernel requires a decryption key".into()),
            0x30 if compression.is_none() && !properties => {
                let values = fields(field.1)?;
                if values.len() != 2 {
                    return Err("invalid IM4P compression descriptor".into());
                }
                let algorithm = integer(&values[0])?;
                let length = integer(&values[1])?;
                if algorithm != 1 {
                    return Err(format!(
                        "unsupported IM4P compression algorithm {algorithm}"
                    ));
                }
                if length == 0 || length > maximum_output {
                    return Err("declared kernel size exceeds output bound or is zero".into());
                }
                compression = Some(length);
            }
            0xa0 if !properties => {
                fields(field.1)?;
                properties = true;
            }
            _ => return Err("unexpected or duplicate IM4P optional field".into()),
        }
    }
    let payload = inner[3].1;
    let framed = payload.len() >= 4
        && matches!(
            &payload[..4],
            b"bvx1" | b"bvx2" | b"bvx-" | b"bvxn" | b"bvx$"
        );
    let output = if framed {
        let mut output = BoundedOutput {
            bytes: Vec::new(),
            limit: compression.unwrap_or(maximum_output),
        };
        let (consumed, written) = lzfse_rust::LzfseRingDecoder::default()
            .decode(&mut io::Cursor::new(payload), &mut output)
            .map_err(|e| e.to_string())?;
        if consumed != payload.len() as u64 || written != output.bytes.len() as u64 {
            return Err("LZFSE kernel stream length mismatch".into());
        }
        output.bytes
    } else {
        if compression.is_some() {
            return Err("IM4P compression descriptor requires an LZFSE stream".into());
        }
        if payload.len() > maximum_output {
            return Err("kernel exceeds output bound".into());
        }
        payload.to_vec()
    };
    if compression.is_some_and(|length| length != output.len()) {
        return Err("decoded kernel differs from declared size".into());
    }
    Ok(DecodedIm4p {
        payload_type: inner[1].1.try_into().map_err(|_| "invalid IM4P type")?,
        bytes: output,
    })
}

pub fn decode_kernel_im4p(bytes: &[u8], maximum_output: usize) -> Result<Vec<u8>, String> {
    let decoded = decode_im4p(bytes, maximum_output)?;
    if decoded.payload_type != *b"krnl" || !decoded.bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return Err("decoded kernel is not a krnl little-endian 64-bit Mach-O".into());
    }
    Ok(decoded.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ramrod::der;
    fn image(payload: &[u8], declared: Option<usize>) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, data) in [
            (0x16, b"IM4P".as_slice()),
            (0x16, b"krnl".as_slice()),
            (0x16, b"test".as_slice()),
            (4, payload),
        ] {
            body.extend(der::tlv(&[tag], data));
        }
        if let Some(length) = declared {
            let mut descriptor = der::integer_u64(1);
            descriptor.extend(der::integer_u64(length as u64));
            body.extend(der::tlv(&[0x30], &descriptor));
        }
        der::tlv(&[0x30], &body)
    }
    fn raw() -> Vec<u8> {
        let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe];
        bytes.extend([0u8; 28]);
        bytes
    }
    fn stored(raw: &[u8]) -> Vec<u8> {
        let mut bytes = b"bvx-".to_vec();
        bytes.extend((raw.len() as u32).to_le_bytes());
        bytes.extend(raw);
        bytes.extend(b"bvx$");
        bytes
    }
    #[test]
    fn compressed_round_trip_and_encrypted_refusal() {
        let mut original = raw();
        original.extend(vec![42u8; 8192]);
        let mut packed = Vec::new();
        lzfse_rust::LzfseRingEncoder::default()
            .encode_bytes(&original, &mut packed)
            .unwrap();
        assert!(packed.len() < original.len());
        assert_eq!(
            decode_kernel_im4p(&image(&packed, Some(original.len())), original.len()).unwrap(),
            original
        );
        let base = image(&original, None);
        let mut body = fields(&base).unwrap()[0].1.to_vec();
        body.extend(der::tlv(&[4], b"encrypted keybag"));
        assert!(decode_im4p(&der::tlv(&[0x30], &body), 16384).is_err());
    }

    #[test]
    fn generic_payload_accepts_xml_without_claiming_kernel() {
        let mut im4p = image(b"<plist/>", None);
        let at = im4p.windows(4).position(|w| w == b"krnl").unwrap();
        im4p[at..at + 4].copy_from_slice(b"mtfw");
        let decoded = decode_im4p(&im4p, 100).unwrap();
        assert_eq!(decoded.payload_type, *b"mtfw");
        assert_eq!(decoded.bytes, b"<plist/>");
        assert!(decode_kernel_im4p(&im4p, 100).is_err());
    }
    #[test]
    fn raw_and_framed_kernel_preserve_bytes() {
        let raw = raw();
        assert_eq!(decode_kernel_im4p(&image(&raw, None), 1024).unwrap(), raw);
        assert_eq!(
            decode_kernel_im4p(&image(&stored(&raw), Some(raw.len())), 1024).unwrap(),
            raw
        );
    }
    #[test]
    fn rejects_bounds_truncation_size_mismatch_and_trailing_stream() {
        let raw = raw();
        let packed = stored(&raw);
        assert!(decode_kernel_im4p(&image(&packed, Some(raw.len() + 1)), 1024).is_err());
        assert!(decode_kernel_im4p(&image(&packed, Some(raw.len() - 1)), 1024).is_err());
        assert!(decode_kernel_im4p(&image(&packed, None), 1).is_err());
        let mut trailing = packed.clone();
        trailing.push(0);
        assert!(decode_kernel_im4p(&image(&trailing, None), 1024).is_err());
        let im4p = image(&packed, None);
        assert!(decode_kernel_im4p(&im4p[..im4p.len() - 1], 1024).is_err());
        let mut extra = im4p;
        extra.extend(der::integer_u64(0));
        assert!(decode_kernel_im4p(&extra, 1024).is_err());
    }
}
