mod pe;
mod scan_patterns;
mod scan_trust;
mod scan_urls;

use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OffsetsFile {
    format_version: u32,
    module_name: String,
    source_file: String,
    source_sha256: String,
    source_size: u64,
    image_base: u64,
    urls: Vec<scan_urls::UrlEntry>,
    patterns: Vec<scan_patterns::PatternEntry>,
    security_cookie: Option<scan_trust::SecurityCookieEntry>,
    trust_strings: Vec<scan_trust::TrustStringEntry>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                i += 1;
                input = Some(PathBuf::from(&args[i]));
            }
            "--output" | "-o" => {
                i += 1;
                output = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            other => {
                if input.is_none() {
                    input = Some(PathBuf::from(other));
                } else if output.is_none() {
                    output = Some(PathBuf::from(other));
                }
            }
        }
        i += 1;
    }

    let input = input.unwrap_or_else(|| {
        eprintln!("Error: no input file. Pass RobloxStudioBeta.exe path.");
        print_usage();
        std::process::exit(1);
    });
    let output = output.unwrap_or_else(|| PathBuf::from("offsets.json"));

    let module_name = input
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "RobloxStudioBeta.exe".to_string());

    let image = match pe::load(&input) {
        Ok(img) => img,
        Err(e) => {
            eprintln!("Failed to load {}: {e}", input.display());
            std::process::exit(1);
        }
    };

    println!(
        "Loaded {} ({}) sections={} image_size=0x{:x}",
        input.display(),
        image.sha256.get(..12).unwrap_or(""),
        image.sections.len(),
        image.image_size
    );

    let urls = scan_urls::find_urls(&image);
    println!("Found {} non-localhost URL strings", urls.len());

    let mut patterns = scan_patterns::scan_patterns(&image);
    for p in &patterns {
        println!("  [{}] {} at 0x{:x}", p.kind, p.name, p.rva);
    }

    let mut trust_checks = scan_trust::find_trust_checks(&image, &patterns);
    for p in &trust_checks {
        println!("  [{}] {} at 0x{:x} ({} {})", p.kind, p.name, p.rva, p.patch_offset.unwrap_or(0), p.patch_bytes.as_ref().map(|b| format!("{b:02x?}")).unwrap_or_default());
    }
    patterns.append(&mut trust_checks);

    let security_cookie = scan_trust::find_security_cookie(&image);
    if let Some(sc) = &security_cookie {
        println!(
            "  Security cookie JZ at 0x{:x} (patch {:02x?})",
            sc.jz_rva, sc.patch_bytes
        );
    } else {
        println!("  Security cookie patch: NOT FOUND");
    }

    let trust_strings = scan_trust::find_trust_strings(&image);
    println!("Found {} trust-related strings", trust_strings.len());

    let offsets = OffsetsFile {
        format_version: 1,
        module_name,
        source_file: input.file_name().unwrap_or_default().to_string_lossy().to_string(),
        source_sha256: image.sha256.clone(),
        source_size: image.file_size,
        image_base: image.image_base,
        urls,
        patterns,
        security_cookie,
        trust_strings,
    };

    let json = serde_json::to_string_pretty(&offsets).expect("serialize offsets");
    if let Err(e) = std::fs::write(&output, &json) {
        eprintln!("Failed to write {}: {e}", output.display());
        std::process::exit(1);
    }
    println!("Wrote {} ({:.1} KB)", output.display(), json.len() as f64 / 1024.0);
}

fn print_usage() {
    println!("Usage: offsets_scanner <RobloxStudioBeta.exe> [-o offsets.json]");
    println!("       offsets_scanner --input <exe> --output <json>");
    println!("Scans the Roblox Studio binary for URL strings and trust checks that");
    println!("are not redirected to localhost, and writes them to an offsets file.");
}
