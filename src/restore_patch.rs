mod code_signature;
mod recipe;
mod trustcache;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedPatch {
    pub executable: Vec<u8>,
    pub trustcache_im4p: Vec<u8>,
    pub old_cdhash: [u8; 20],
    pub new_cdhash: [u8; 20],
}

/// Prepares an opt-in restore patch without modifying its input buffers.
pub fn prepare_skip_tcon(
    executable: &[u8],
    trustcache_im4p: &[u8],
) -> Result<PreparedPatch, String> {
    let image = recipe::MachO::parse(executable)?;
    let signature = code_signature::ValidatedSignature::parse(executable, image.signature.clone())?;
    let mut patched = executable.to_vec();
    recipe::apply(executable, &image, &mut patched)?;
    let (old_cdhash, new_cdhash) = signature.rehash(executable, &mut patched)?;
    let trustcache_im4p = trustcache::replace(trustcache_im4p, old_cdhash, new_cdhash)?;
    Ok(PreparedPatch {
        executable: patched,
        trustcache_im4p,
        old_cdhash,
        new_cdhash,
    })
}

fn refusal(name: &str, detail: impl std::fmt::Display) -> String {
    format!("skip-tcon-{name}: {detail}")
}

fn bytes(data: &[u8], offset: usize, len: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| refusal("bounds", "offset overflow"))?;
    data.get(offset..end)
        .ok_or_else(|| refusal("bounds", format!("range {offset:#x}..{end:#x}")))
}

fn le32(data: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}

fn le64(data: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}

fn be32(data: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_be_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}

fn usize64(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| refusal("bounds", "offset exceeds address space"))
}
