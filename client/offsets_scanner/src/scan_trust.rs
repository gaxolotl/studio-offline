use crate::pe::PeImage;
use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityCookieEntry {
    pub string_rva: usize,
    pub xref_rva: usize,
    pub jz_rva: usize,
    pub opcode_len: usize,
    pub original_opcode: Vec<u8>,
    pub patch_bytes: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustStringEntry {
    pub rva: usize,
    pub text: String,
    pub xref_rva: Option<usize>,
}

fn find_string(image: &PeImage, target: &str) -> Option<usize> {
    let buf = &image.reconstructed;
    buf.windows(target.len())
        .position(|w| w == target.as_bytes())
}

fn find_xref(image: &PeImage, target_rva: usize) -> Option<usize> {
    // target virtual address = image_base + rva
    let target_va = image.image_base as usize + target_rva;
    let buf = &image.reconstructed;
    for offset in 0..buf.len().saturating_sub(7) {
        let b1 = buf[offset];
        if (b1 == 0x48 || b1 == 0x4C) && buf[offset + 1] == 0x8D {
            let modrm = buf[offset + 2];
            if (modrm & 0xC7) == 0x05 {
                let disp = i32::from_le_bytes([
                    buf[offset + 3],
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                ]);
                let next_ip = image.image_base as usize + offset + 7;
                let target = (next_ip as isize + disp as isize) as usize;
                if target == target_va {
                    return Some(offset);
                }
            }
        }
    }
    None
}

fn find_jz_from_cmp_backwards(image: &PeImage, xref_rva: usize) -> Option<(usize, usize, Vec<u8>)> {
    let xref_va = image.image_base as usize + xref_rva;
    let buf = &image.reconstructed;
    let max_lookback = 100;
    let start_search = xref_rva.saturating_sub(max_lookback);

    for offset in (0..xref_rva - start_search).rev() {
        let current_start = start_search + offset;
        if xref_rva - current_start < 5 {
            continue;
        }

        let mut decoder = Decoder::with_ip(
            64,
            &buf[current_start..],
            (image.image_base as usize + current_start) as u64,
            DecoderOptions::NONE,
        );

        let mut instrs = Vec::new();
        let mut success = false;

        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.next_ip() as usize == xref_va {
                success = true;
                instrs.push(instr);
                break;
            }
            if (instr.ip() as usize) > xref_va {
                break;
            }
            instrs.push(instr);
        }

        if success {
            for i in (0..instrs.len()).rev() {
                let instr = instrs[i];
                match instr.code() {
                    Code::Je_rel8_64 | Code::Je_rel32_64 => {
                        if i > 0 {
                            let prev = instrs[i - 1];
                            if prev.mnemonic() == Mnemonic::Cmp {
                                let rva = instr.ip() as usize - image.image_base as usize;
                                let size = instr.len();
                                let bytes: Vec<u8> =
                                    buf[rva..rva + size].to_vec();
                                return Some((rva, size, bytes));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    None
}

pub fn find_security_cookie(image: &PeImage) -> Option<SecurityCookieEntry> {
    let s = "[FLog::StudioCookieManager] Security cookie is cached so we proceed saving now.";
    let string_rva = find_string(image, s)?;
    let xref_rva = find_xref(image, string_rva)?;
    let (jz_rva, opcode_len, opcode) = find_jz_from_cmp_backwards(image, xref_rva)?;

    // Determine patch: JZ (0x74 / 0F 84) -> JNZ (0x75 / 0F 85)
    let patch_bytes = if opcode[0] == 0x74 {
        vec![0x75]
    } else if opcode[0] == 0x0F && opcode[1] == 0x84 {
        vec![0x0F, 0x85]
    } else {
        return None;
    };

    Some(SecurityCookieEntry {
        string_rva,
        xref_rva,
        jz_rva,
        opcode_len,
        original_opcode: opcode,
        patch_bytes,
    })
}

pub fn find_trust_strings(image: &PeImage) -> Vec<TrustStringEntry> {
    let needles = [
        "Trust check failed",
        "is not trusted",
        "not trusted",
        "trusted host",
        "TRUSTED_HOSTS",
        "trust check",
        "TrustCheck",
        "url is not trusted",
    ];
    let mut out = Vec::new();
    for needle in needles {
        let mut search_from = 0usize;
        loop {
            let buf = &image.reconstructed;
            if search_from + needle.len() > buf.len() {
                break;
            }
            match buf[search_from..]
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
            {
                Some(rel) => {
                    let rva = search_from + rel;
                    out.push(TrustStringEntry {
                        rva,
                        text: needle.to_string(),
                        xref_rva: find_xref(image, rva),
                    });
                    search_from = rva + needle.len();
                }
                None => break,
            }
        }
    }
    out
}
