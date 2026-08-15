use crate::pe::PeImage;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatternEntry {
    pub name: String,
    pub rva: usize,
    pub kind: String, // "hook" or "bytepatch"
    pub patch_offset: Option<usize>,
    pub patch_bytes: Option<Vec<u8>>,
    pub pattern_bytes: Vec<u8>,
    pub pattern_mask: Vec<u8>,
    pub description: String,
}

pub fn find_byte_pattern(image: &PeImage, pattern: &[u8], mask: &[u8]) -> Option<usize> {
    let buf = &image.reconstructed;
    let plen = mask.len();
    if plen == 0 || buf.len() < plen {
        return None;
    }
    let mut i = 0usize;
    while i + plen <= buf.len() {
        let mut ok = true;
        for k in 0..plen {
            if mask[k] != b'?' && buf[i + k] != pattern[k] {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(i);
        }
        i += 1;
    }
    None
}

pub fn scan_patterns(image: &PeImage) -> Vec<PatternEntry> {
    let mut out = Vec::new();

    macro_rules! hook {
        ($name:expr, $bytes:expr, $mask:expr, $desc:expr) => {
            if let Some(rva) = find_byte_pattern(image, $bytes, $mask) {
                out.push(PatternEntry {
                    name: $name.to_string(),
                    rva,
                    kind: "hook".to_string(),
                    patch_offset: None,
                    patch_bytes: None,
                    pattern_bytes: $bytes.to_vec(),
                    pattern_mask: $mask.to_vec(),
                    description: $desc.to_string(),
                });
            }
        };
    }

    macro_rules! bytepatch {
        ($name:expr, $bytes:expr, $mask:expr, $offset:expr, $patch:expr, $desc:expr) => {
            if let Some(rva) = find_byte_pattern(image, $bytes, $mask) {
                out.push(PatternEntry {
                    name: $name.to_string(),
                    rva,
                    kind: "bytepatch".to_string(),
                    patch_offset: Some($offset),
                    patch_bytes: Some($patch.to_vec()),
                    pattern_bytes: $bytes.to_vec(),
                    pattern_mask: $mask.to_vec(),
                    description: $desc.to_string(),
                });
            }
        };
    }

    // Ported from client/studio_offline/src/patterns.rs
    hook!(
        "URL_ONCOMPONENT",
        b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x78\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x45\xF0\x4D\x8B\xF9\x4D\x8B\xF0\x4C\x8B\xE9",
        b"xxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxxx",
        "HttpRequest FromComponents - rewrite scheme/host to localhost"
    );

    hook!(
        "TRUSTCHECK",
        b"\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xE1\x48\x81\xEC\xD8\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x45\x07\x45\x0F\xB6\xE1\x45\x0F\xB6\xF8",
        b"xxxxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxxx",
        "TrustCheck - trust localhost URLs"
    );

    hook!(
        "HTTP_REQUEST_URL",
        b"\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x00\x48\x8B\xFA\x48\x8B\xF1\xE8\x00\x00\x00\x00\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\x48\x8B\xC8",
        b"xxxx?xxxx?xxxxxxx????xxxxx????xxx",
        "HttpRequest notTrusted hook - always return trusted"
    );

    bytepatch!(
        "FETCHER_JNE_THROW",
        b"\x80\xBD\xA8\x01\x00\x00\x00\x0F\x85\x66\x02\x00\x00\x49\x8B\xD5\x48\x8D\x4C\x24\x50",
        b"xxxxxxxxxxxxxxxxxxxxx",
        7,
        vec![0x90, 0x90, 0x90, 0x90, 0x90, 0x90],
        "NOP out fetcher jne so latest-place-version falls through to dispatcher"
    );

    bytepatch!(
        "ASYNC_TRUST_CHECK",
        b"\x44\x0F\xB6\x4C\x24\x40\x45\x0F\xB6\xC4\x33\xD2\xE8\x00\x00\x00\x00\x84\xC0\x0F\x85\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00",
        b"xxxxxxxxxxxxx????xxxx????xxx????",
        17,
        vec![0x0C, 0x01],
        "AsyncHttpQueue trust check: test al,al -> or al,1 so jne always takes success path"
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeImage;

    fn fake_image(payload: Vec<u8>) -> PeImage {
        let len = payload.len();
        PeImage {
            image_base: 0x140000000,
            image_size: len,
            sections: vec![],
            reconstructed: payload,
            sha256: "test".to_string(),
            file_size: len as u64,
        }
    }

    #[test]
    fn finds_async_trust_check() {
        let pattern = b"\x44\x0F\xB6\x4C\x24\x40\x45\x0F\xB6\xC4\x33\xD2\xE8\x00\x00\x00\x00\x84\xC0\x0F\x85\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00";
        let mut buf = vec![0u8; 512];
        buf[100..100 + pattern.len()].copy_from_slice(pattern);
        let img = fake_image(buf);
        let found = scan_patterns(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "ASYNC_TRUST_CHECK");
        assert_eq!(found[0].rva, 100);
        assert_eq!(found[0].patch_offset, Some(17));
        assert_eq!(found[0].patch_bytes, Some(vec![0x0C, 0x01]));
    }

    #[test]
    fn finds_fetcher_jne() {
        let pattern = b"\x80\xBD\xA8\x01\x00\x00\x00\x0F\x85\x66\x02\x00\x00\x49\x8B\xD5\x48\x8D\x4C\x24\x50";
        let mut buf = vec![0u8; 512];
        buf[50..50 + pattern.len()].copy_from_slice(pattern);
        let img = fake_image(buf);
        let found = scan_patterns(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "FETCHER_JNE_THROW");
        assert_eq!(found[0].rva, 50);
    }
}

