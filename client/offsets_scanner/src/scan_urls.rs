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

// Host suffixes that are schema/documentation references, not service
// endpoints. Rewriting these corrupts XML/XMP namespaces and doc links and
// provides no offline benefit, so they are skipped.
const DENYLISTED_HOST_SUFFIXES: &[&str] = &[
    "w3.org",
    "ns.adobe.com",
    "purl.org",
    "schemas.microsoft.com",
    "webrtc.org",
    "ietf.org",
    "crbug.com",
    "chromium.org",
    "github.com",
    "curl.se",
    "creativecommons.org",
    "exif.org",
    "iptc.org",
    "xml.org",
];

fn is_denylisted_host(host: &str) -> bool {
    let h = host.to_lowercase();
    DENYLISTED_HOST_SUFFIXES.iter().any(|suffix| {
        h == *suffix || h.ends_with(&format!(".{suffix}"))
    })
}

// Printable ASCII that can appear inside a real URL string. Quotes, angle
// brackets and whitespace only appear inside XML/XMP/metadata blobs, so a
// match that hits them is a blob, not a URL string.
fn is_url_char(b: u8) -> bool {
    b >= 0x21 && b <= 0x7e && b != b'"' && b != b'\'' && b != b'<' && b != b'>'
}

const MAX_URL_BYTES: usize = 512;

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
        // Boundary check: the byte before the marker must not be a printable
        // ASCII char. This prevents matching "http://" inside a larger string
        // or inside XML/XMP attribute values like xmlns:xmp="http://ns.adobe...".
        if i > 0 {
            let prev = image[i - 1];
            if prev >= 0x21 && prev <= 0x7e {
                continue;
            }
        }
        let mut matched = None;
        for (_, m) in markers.iter().enumerate() {
            if image[i..].starts_with(m) {
                matched = Some(m.len());
                break;
            }
        }
        let Some(marker_len) = matched else { continue };
        // Expand only while the bytes could belong to a real URL string.
        // Stop at NUL, whitespace, quotes, angle brackets, control, non-ASCII
        // (all of which appear inside XML/XMP/metadata blobs, not URLs).
        let mut end = i + marker_len;
        while end < image.len() && is_url_char(image[end]) {
            end += 1;
        }
        let s = String::from_utf8_lossy(&image[i..end]).to_string();
        if s.chars().count() >= 8 && end - i <= MAX_URL_BYTES {
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
        // Boundary check: the UTF-16 unit before the marker must not be
        // printable ASCII (rejects matches inside XML/XMP blobs).
        if i >= 2 {
            let prev = u16::from_le_bytes([image[i - 2], image[i - 1]]);
            if prev >= 0x21 && prev <= 0x7e {
                i = end_after(i, marker_len);
                continue;
            }
        }
        // Expand utf16 units until a null unit, non-printable unit, or a
        // char that only appears inside metadata blobs (whitespace, quotes,
        // angle brackets).
        let mut end = i + marker_len;
        while end + 1 < image.len() {
            let unit = u16::from_le_bytes([image[end], image[end + 1]]);
            if unit == 0 || (unit < 0x20 && unit != 0x09) || unit == 0x7f {
                break;
            }
            if unit <= 0x7f {
                let b = unit as u8;
                if !is_url_char(b) {
                    break;
                }
            } else {
                break; // non-ASCII unit cannot be part of a URL string
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
        if s.chars().count() >= 8 && end - i <= MAX_URL_BYTES {
            out.push((i, s));
        }
        i = end;
    }
    out
}

fn end_after(start: usize, marker_len: usize) -> usize {
    // Fast-forward past a UTF-16 marker to avoid re-matching inside it.
    start + marker_len
}

pub fn find_urls(image: &PeImage) -> Vec<UrlEntry> {
    let mut entries = Vec::new();

    let mut ascii = scan_ascii_urls(&image.reconstructed);
    ascii.sort_by_key(|(rva, _)| *rva);
    for (rva, url) in ascii {
        if !is_clean_single_url(&url) {
            entries.push(UrlEntry {
                rva,
                encoding: "ascii".to_string(),
                length: url.len(),
                original: url,
                replacement: String::new(),
                host: String::new(),
                skipped: true,
                reason: Some("not a single clean URL (concatenated blob)".to_string()),
            });
            continue;
        }
        if let Some((replacement, skipped, host)) = localhost_replacement(&url) {
            let byte_len = url.len();
            let fits = replacement.len() <= byte_len;
            let (skipped, reason) = classify(skipped, &host, fits);
            entries.push(UrlEntry {
                rva,
                encoding: "ascii".to_string(),
                length: byte_len,
                original: url,
                replacement: if fits { replacement } else { "http://localhost".to_string() },
                host,
                skipped,
                reason,
            });
        }
    }

    let mut utf16 = scan_utf16_urls(&image.reconstructed);
    utf16.sort_by_key(|(rva, _)| *rva);
    for (rva, url) in utf16 {
        if !is_clean_single_url(&url) {
            let byte_len = url.encode_utf16().count() * 2;
            entries.push(UrlEntry {
                rva,
                encoding: "utf16".to_string(),
                length: byte_len,
                original: url,
                replacement: String::new(),
                host: String::new(),
                skipped: true,
                reason: Some("not a single clean URL (concatenated blob)".to_string()),
            });
            continue;
        }
        if let Some((replacement, skipped, host)) = localhost_replacement(&url) {
            let byte_len = url.encode_utf16().count() * 2;
            let repl_bytes = replacement.encode_utf16().count() * 2;
            let fits = repl_bytes <= byte_len;
            let (skipped, reason) = classify(skipped, &host, fits);
            entries.push(UrlEntry {
                rva,
                encoding: "utf16".to_string(),
                length: byte_len,
                original: url,
                replacement: if fits { replacement } else { "http://localhost".to_string() },
                host,
                skipped,
                reason,
            });
        }
    }

    entries
}

fn classify(skipped: bool, host: &str, fits: bool) -> (bool, Option<String>) {
    if skipped {
        return (true, Some("placeholder authority; no generic replacement".to_string()));
    }
    if is_denylisted_host(host) {
        return (true, Some(format!("non-service host '{host}' excluded")));
    }
    if !fits {
        return (true, Some("replacement longer than original".to_string()));
    }
    (false, None)
}

// A single real URL string in the binary must not contain a second "://"
// (which indicates a concatenated blob like "https://luau.orghttps://create...")
// and its authority must only contain host-legal characters.
fn is_clean_single_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or("");
    if rest.contains("://") {
        return false;
    }
    let auth_end = rest
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() {
        return false;
    }
    authority.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '%' | '_' | '[' | ']' | '@')
    })
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

    #[test]
    fn skips_xmp_namespace_blob() {
        // An XMP metadata packet embeds w3.org/ns.adobe.com namespace URLs.
        // These are not service endpoints; they must not produce a patchable
        // entry (the old scanner captured the entire blob and corrupted it).
        let mut buf = vec![0u8; 2048];
        let blob = br#"<?xpacket begin=""><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#;
        buf[64..64 + blob.len()].copy_from_slice(blob);
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert!(
            found.iter().all(|e| e.skipped),
            "XMP namespace URLs must be skipped: {:?}",
            found.iter().map(|e| (&e.host, &e.skipped)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn skips_concatenated_urls() {
        // Two URLs joined without a separator in the binary must not be
        // captured as a single blob.
        let mut buf = vec![0u8; 512];
        let blob = b"https://luau.orghttps://create.roblox.com/foo";
        buf[32..32 + blob.len()].copy_from_slice(blob);
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert!(found.iter().all(|e| e.skipped));
    }

    #[test]
    fn url_with_space_is_truncated_not_blob() {
        // A metadata string containing spaces/quotes after a URL must not
        // swallow the trailing junk.
        let mut buf = vec![0u8; 512];
        let blob = b"https://www.roblox.com/asset \"extra junk <tag>\"";
        buf[16..16 + blob.len()].copy_from_slice(blob);
        let img = fake_image(buf);
        let found = find_urls(&img);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].original, "https://www.roblox.com/asset");
        assert_eq!(found[0].replacement, "http://localhost/asset");
    }
}

