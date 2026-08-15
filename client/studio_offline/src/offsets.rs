use serde::Deserialize;
use std::path::PathBuf;
use windows::Win32::System::Memory::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlEntry {
    pub rva: usize,
    pub encoding: String,
    pub length: usize,
    pub original: String,
    pub replacement: String,
    #[serde(default)]
    pub skipped: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternEntry {
    pub name: String,
    pub rva: usize,
    pub kind: String, // "hook" or "bytepatch"
    pub patch_offset: Option<usize>,
    pub patch_bytes: Option<Vec<u8>>,
    pub pattern_bytes: Vec<u8>,
    pub pattern_mask: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCookieEntry {
    pub jz_rva: usize,
    pub original_opcode: Vec<u8>,
    pub patch_bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OffsetsFile {
    pub format_version: u32,
    pub urls: Vec<UrlEntry>,
    pub patterns: Vec<PatternEntry>,
    pub security_cookie: Option<SecurityCookieEntry>,
}

pub fn find_offsets_file() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidates = [
        exe_dir.join("offsets.json"),
        PathBuf::from("offsets.json"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

pub fn load() -> Option<OffsetsFile> {
    let path = find_offsets_file()?;
    let content = std::fs::read_to_string(&path).ok()?;
    let offsets: OffsetsFile = serde_json::from_str(&content).ok()?;
    if offsets.format_version != 1 {
        println!("offsets.json format version {} not supported", offsets.format_version);
        return None;
    }
    println!("Loaded offsets from {}", path.display());
    Some(offsets)
}

unsafe fn write_bytes(addr: usize, bytes: &[u8]) -> bool {
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if VirtualProtect(
        addr as *const _,
        bytes.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .is_err()
    {
        return false;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
    let _ = VirtualProtect(addr as *const _, bytes.len(), old_protect, &mut old_protect);
    true
}

unsafe fn write_padded_ascii(addr: usize, replacement: &str, original_len: usize) -> bool {
    let rb = replacement.as_bytes();
    let n = rb.len().min(original_len);
    let mut buf = vec![0u8; original_len];
    buf[..n].copy_from_slice(&rb[..n]);
    write_bytes(addr, &buf)
}

unsafe fn write_padded_utf16(addr: usize, replacement: &str, original_len_bytes: usize) -> bool {
    let units: Vec<u16> = replacement.encode_utf16().collect();
    let repl_bytes = units.len() * 2;
    let n = repl_bytes.min(original_len_bytes);
    let mut buf = vec![0u8; original_len_bytes];
    for (i, u) in units.iter().enumerate() {
        if i * 2 + 1 < n {
            buf[i * 2] = (u & 0xff) as u8;
            buf[i * 2 + 1] = (u >> 8) as u8;
        }
    }
    write_bytes(addr, &buf)
}

pub unsafe fn apply(
    offsets: &OffsetsFile,
    base: usize,
    hook_fn: impl Fn(&PatternEntry),
) {
    // 1. URL string patches
    for u in &offsets.urls {
        if u.skipped {
            continue;
        }
        // Verify the original URL is still at the expected rva before patching
        // (protects against a stale offsets.json from a different Roblox build).
        let addr = base + u.rva;
        let mut verified = false;
        match u.encoding.as_str() {
            "utf16" => {
                let orig_bytes: Vec<u8> = u
                    .original
                    .encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                if std::slice::from_raw_parts(addr as *const u8, orig_bytes.len())
                    == orig_bytes.as_slice()
                {
                    verified = true;
                }
            }
            _ => {
                let orig_bytes = u.original.as_bytes();
                if std::slice::from_raw_parts(addr as *const u8, orig_bytes.len())
                    == orig_bytes
                {
                    verified = true;
                }
            }
        }
        if !verified {
            println!("SKIP URL at rva 0x{:x}: original not found (stale offsets?)", u.rva);
            continue;
        }
        let ok = match u.encoding.as_str() {
            "utf16" => write_padded_utf16(addr, &u.replacement, u.length),
            _ => write_padded_ascii(addr, &u.replacement, u.length),
        };
        if ok {
            println!("Patched URL {} -> {} at 0x{:x}", u.host_or_id(), u.replacement, u.rva);
        } else {
            println!("Failed to patch URL at rva 0x{:x}", u.rva);
        }
    }

    // 2. Pattern hooks + byte patches
    for p in &offsets.patterns {
        // Verify the pattern bytes still match at the expected rva.
        if !pattern_matches(base + p.rva, &p.pattern_bytes, &p.pattern_mask) {
            println!("SKIP {} at rva 0x{:x}: pattern mismatch (stale offsets?)", p.name, p.rva);
            continue;
        }
        if p.kind == "hook" {
            hook_fn(p);
        } else if p.kind == "bytepatch" {
            if let (Some(off), Some(bytes)) = (p.patch_offset, &p.patch_bytes) {
                let addr = base + p.rva + off;
                if write_bytes(addr, bytes) {
                    println!("Patched {} at rva 0x{:x} (+0x{off:x})", p.name, p.rva);
                } else {
                    println!("Failed to patch {} at rva 0x{:x}", p.name, p.rva);
                }
            }
        }
    }

    // 3. Security cookie JZ->JNZ
    if let Some(sc) = &offsets.security_cookie {
        let addr = base + sc.jz_rva;
        // Verify the original opcode before patching so a stale offsets file
        // can't corrupt memory.
        let actual = std::slice::from_raw_parts(addr as *const u8, sc.original_opcode.len());
        if actual == sc.original_opcode.as_slice() {
            if write_bytes(addr, &sc.patch_bytes) {
                println!("Patched security cookie JZ at rva 0x{:x}", sc.jz_rva);
            } else {
                println!("Failed to patch security cookie at rva 0x{:x}", sc.jz_rva);
            }
        } else {
            println!("SKIP security cookie at rva 0x{:x}: opcode mismatch (stale offsets?)", sc.jz_rva);
        }
    }
}

unsafe fn pattern_matches(addr: usize, pattern: &[u8], mask: &[u8]) -> bool {
    let data = std::slice::from_raw_parts(addr as *const u8, mask.len());
    for (i, m) in mask.iter().enumerate() {
        if *m != b'?' && data[i] != pattern[i] {
            return false;
        }
    }
    true
}

impl UrlEntry {
    fn host_or_id(&self) -> String {
        self.original
            .split("://")
            .nth(1)
            .unwrap_or(&self.original)
            .chars()
            .take(24)
            .collect()
    }
}
