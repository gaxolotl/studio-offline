use crate::pe::PeImage;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlEntry {
    pub rva: usize,
    pub encoding: String,
    pub length: usize,
    pub original: String,
    pub replacement: String,
    pub host: String,
    pub skipped: bool,
    pub reason: Option<String>,
}

fn parse_url(url: &str) -> Option<(String, String)> {
    // Returns (authority, rest_after_authority)
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let auth_end = rest
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = rest[..auth_end].to_string();
    let rest_after = rest[auth_end..].to_string();
    Some((authority, rest_after))
}

pub fn localhost_replacement(url: &str) -> Option<(String, bool, String)> {
    // Hand-crafted same-length replacements for known URLs that the generic
    // scheme cannot fit (e.g. short placeholder authorities).
    const KNOWN: &[(&str, &str)] = &[(
        "https://data.%1/Data/Upload.ashx?assetid=%2",
        "http://localhost/Data/Upload.ashx?a=%1&b=%2",
    )];
    for (orig, repl) in KNOWN {
        if url == *orig {
            return Some((repl.to_string(), false, "data.%1".to_string()));
        }
    }

    let (authority, rest_after) = parse_url(url)?;
    if authority.is_empty() {
        return None;
    }
    let host = authority.split(':').next().unwrap_or(&authority).to_lowercase();
    if host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "0.0.0.0" {
        return None; // already local
    }
    // Preserve the authority when it contains format placeholders (e.g. data.%1)
    // so the runtime format substitution keeps its argument references.
    if authority.contains('%') {
        let replacement = format!("http://localhost{rest_after}");
        return Some((replacement, true, host));
    }
    let replacement = format!("http://localhost{rest_after}");
    Some((replacement, false, host))
}

pub fn scan_ascii_urls(image: &[u8]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let markers = [b"http://".as_slice(), b"https://".as_slice()];
    for (i, _) in image.iter().enumerate() {
        if i + 8 > image.len() {
            break;
        }
        let mut matched = None;
        for (_, m) in markers.iter().enumerate() {
            if image[i..].starts_with(m) {
                matched = Some(m.len());
                break;
            }
        }
        let Some(marker_len) = matched else { continue };
        // Expand to a printable string ending at NUL / whitespace / control / non-ASCII
        let mut end = i + marker_len;
        while end < image.len() {
            let b = image[end];
            if b == 0 || b < 0x20 || b >= 0x80 || b == 0x7f {
                break;
            }
            end += 1;
        }
        let s = String::from_utf8_lossy(&image[i..end]).to_string();
        if s.chars().count() >= 8 {
            out.push((i, s));
        }
        // skip past this string to avoid duplicate matches inside it
        // handled by the outer loop naturally
    }
    out
}

pub fn scan_utf16_urls(image: &[u8]) -> Vec<(usize, String)> {
    // Search for UTF-16LE "http://" or "https://" (each char = 2 bytes, little-endian)
    let ascii_utf16 = |s: &str| -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    };
    let markers: Vec<Vec<u8>> = [
        ascii_utf16("http://"),
        ascii_utf16("https://"),
    ]
    .to_vec();

    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 8 <= image.len() {
        let mut matched = None;
        for (_, m) in markers.iter().enumerate() {
            if image[i..].starts_with(m) {
                matched = Some(m.len());
                break;
            }
        }
        let Some(marker_len) = matched else {
            i += 2;
            continue;
        };
        // Expand utf16 units until a null unit or non-printable unit
        let mut end = i + marker_len;
        while end + 1 < image.len() {
            let unit = u16::from_le_bytes([image[end], image[end + 1]]);
            if unit == 0 || (unit < 0x20 && unit != 0x09) || unit == 0x7f {
                break;
            }
            end += 2;
        }
        let mut units = Vec::new();
        let mut j = i;
        while j + 1 <= end {
            units.push(u16::from_le_bytes([image[j], image[j + 1]]));
            j += 2;
        }
        let s = String::from_utf16_lossy(&units);
        if s.chars().count() >= 8 {
            out.push((i, s));
        }
        i = end;
    }
    out
}

pub fn find_urls(image: &PeImage) -> Vec<UrlEntry> {
    let mut entries = Vec::new();

    let mut ascii = scan_ascii_urls(&image.reconstructed);
    ascii.sort_by_key(|(rva, _)| *rva);
    for (rva, url) in ascii {
        if let Some((replacement, skipped, host)) = localhost_replacement(&url) {
            let byte_len = url.len();
            let fits = replacement.len() <= byte_len;
            entries.push(UrlEntry {
                rva,
                encoding: "ascii".to_string(),
                length: byte_len,
                original: url,
                replacement: if fits { replacement } else { "http://localhost".to_string() },
                host,
                skipped,
                reason: if fits { None } else { Some("replacement longer than original; truncated".to_string()) },
            });
        }
    }

    let mut utf16 = scan_utf16_urls(&image.reconstructed);
    utf16.sort_by_key(|(rva, _)| *rva);
    for (rva, url) in utf16 {
        if let Some((replacement, skipped, host)) = localhost_replacement(&url) {
            let byte_len = url.encode_utf16().count() * 2;
            let repl_bytes = replacement.encode_utf16().count() * 2;
            let fits = repl_bytes <= byte_len;
            entries.push(UrlEntry {
                rva,
                encoding: "utf16".to_string(),
                length: byte_len,
                original: url,
                replacement: if fits { replacement } else { "http://localhost".to_string() },
                host,
                skipped,
                reason: if fits { None } else { Some("replacement longer than original; truncated".to_string()) },
            });
        }
    }

    entries
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
    fn finds_ascii_urls() {
        let mut buf = vec![0u8; 256];
        let url = b"https://www.roblox.com/asset/?id=123";
        buf[32..32 + url.len()].copy_from_slice(url);
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "www.roblox.com");
        assert_eq!(found[0].replacement, "http://localhost/asset/?id=123");
        assert_eq!(found[0].rva, 32);
    }

    #[test]
    fn skips_localhost() {
        let mut buf = vec![0u8; 256];
        let url = b"http://localhost/asset/?id=123";
        buf[16..16 + url.len()].copy_from_slice(url);
        let img = fake_image(buf);
        assert_eq!(find_urls(&img).len(), 0);
    }

    #[test]
    fn handles_placeholder_host() {
        let mut buf = vec![0u8; 256];
        let url = b"https://data.%1/Data/Upload.ashx?assetid=%2";
        buf[8..8 + url.len()].copy_from_slice(url);
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].replacement,
            "http://localhost/Data/Upload.ashx?a=%1&b=%2"
        );
        assert!(!found[0].skipped);
    }

    #[test]
    fn finds_utf16_urls() {
        let mut buf = vec![0u8; 512];
        let url = "https://api.roblox.com/foo";
        let units: Vec<u16> = url.encode_utf16().collect();
        let mut pos = 64;
        for u in units {
            buf[pos] = (u & 0xff) as u8;
            buf[pos + 1] = (u >> 8) as u8;
            pos += 2;
        }
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].encoding, "utf16");
        assert_eq!(found[0].replacement, "http://localhost/foo");
    }
}

