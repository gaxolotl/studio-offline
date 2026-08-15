use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: usize,
    pub virtual_size: usize,
    pub raw_pointer: usize,
    pub raw_size: usize,
    pub executable: bool,
    pub readable: bool,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    pub image_base: u64,
    pub image_size: usize,
    pub sections: Vec<SectionInfo>,
    pub reconstructed: Vec<u8>,
    pub sha256: String,
    pub file_size: u64,
}

fn section_flags(section: &SectionTable) -> (bool, bool) {
    let characteristics = section.characteristics;
    let executable = characteristics & 0x2000_0000 != 0; // IMAGE_SCN_MEM_EXECUTE
    let readable = characteristics & 0x4000_0000 != 0; // IMAGE_SCN_MEM_READ
    (executable, readable)
}

pub fn load(path: &Path) -> Result<PeImage, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    let file_size = bytes.len() as u64;
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    };

    let pe = PE::parse(&bytes).map_err(|e| format!("PE parse failed: {e}"))?;
    let image_base = pe.image_base;
    let image_size = {
        // SizeOfImage lives in the optional header; goblin gives us headers.
        // Fall back to max section VA + VS if unavailable.
        let mut size = 0usize;
        if let Some(opt) = &pe.header.optional_header {
            size = opt.windows_fields.size_of_image as usize;
        }
        if size == 0 {
            for s in &pe.sections {
                size = size.max(s.virtual_address as usize + s.virtual_size as usize);
            }
        }
        size
    };

    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let (executable, readable) = section_flags(s);
            SectionInfo {
                name: String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string(),
                virtual_address: s.virtual_address as usize,
                virtual_size: s.virtual_size as usize,
                raw_pointer: s.pointer_to_raw_data as usize,
                raw_size: s.size_of_raw_data as usize,
                executable,
                readable,
            }
        })
        .collect();

    let mut reconstructed = vec![0u8; image_size];
    for s in &sections {
        let va = s.virtual_address;
        let size = s.virtual_size.min(s.raw_size).min(image_size.saturating_sub(va));
        if va + size > reconstructed.len() {
            continue;
        }
        let raw_start = s.raw_pointer.min(bytes.len());
        let raw_len = size.min(bytes.len() - raw_start);
        reconstructed[va..va + raw_len].copy_from_slice(&bytes[raw_start..raw_start + raw_len]);
    }

    Ok(PeImage {
        image_base: image_base as u64,
        image_size,
        sections,
        reconstructed,
        sha256,
        file_size,
    })
}
