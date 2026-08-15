use crate::pe::PeImage;
use crate::scan_patterns::PatternEntry;
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

#[derive(Debug, Clone)]
struct TrustGate {
    call_rva: usize,
    trust_fn_rva: usize,
    test_rva: usize,
    patch_offset: usize,
    patch_bytes: Vec<u8>,
    pattern_bytes: Vec<u8>,
    pattern_mask: Vec<u8>,
}

fn jcc_info(buf: &[u8], pos: usize) -> Option<(u8, usize, isize)> {
    if pos + 1 >= buf.len() {
        return None;
    }
    match buf[pos] {
        0x74 => Some((0x74, 2, buf[pos + 1] as i8 as isize)),
        0x75 => Some((0x75, 2, buf[pos + 1] as i8 as isize)),
        0x0F => match buf[pos + 1] {
            0x84 => Some((
                0x84,
                6,
                i32::from_le_bytes([
                    buf[pos + 2],
                    buf[pos + 3],
                    buf[pos + 4],
                    buf[pos + 5],
                ]) as isize,
            )),
            0x85 => Some((
                0x85,
                6,
                i32::from_le_bytes([
                    buf[pos + 2],
                    buf[pos + 3],
                    buf[pos + 4],
                    buf[pos + 5],
                ]) as isize,
            )),
            _ => None,
        },
        _ => None,
    }
}

fn find_all_lea_xrefs(image: &PeImage, target_rva: usize) -> Vec<usize> {
    let target_va = image.image_base as usize + target_rva;
    let buf = &image.reconstructed;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 6 <= buf.len() {
        let is_rex = (0x40..=0x4F).contains(&buf[i]);
        let lea_pos = if is_rex { i + 1 } else { i };
        if lea_pos + 6 <= buf.len() && buf[lea_pos] == 0x8D && (buf[lea_pos + 1] & 0xC7) == 0x05 {
            let disp = i32::from_le_bytes([
                buf[lea_pos + 2],
                buf[lea_pos + 3],
                buf[lea_pos + 4],
                buf[lea_pos + 5],
            ]);
            let instr_len = if is_rex { 7 } else { 6 };
            let next_ip = image.image_base as usize + i + instr_len;
            let t = (next_ip as isize + disp as isize) as usize;
            if t == target_va {
                out.push(i);
            }
            i += instr_len;
        } else {
            i += 1;
        }
    }
    out
}

fn find_gate_for_xref(image: &PeImage, xref_rva: usize) -> Option<TrustGate> {
    let buf = &image.reconstructed;
    let start = xref_rva.saturating_sub(0x100);
    let mut p = start;
    while p + 12 < buf.len() && p < xref_rva {
        if buf[p] != 0xE8 {
            p += 1;
            continue;
        }
        let call_disp = i32::from_le_bytes([buf[p + 1], buf[p + 2], buf[p + 3], buf[p + 4]]);
        let call_va = image.image_base as usize + p + 5;
        let tgt_va = (call_va as isize + call_disp as isize) as usize;
        let tgt_rva = match tgt_va.checked_sub(image.image_base as usize) {
            Some(r) => r,
            None => {
                p += 1;
                continue;
            }
        };
        if tgt_va < image.image_base as usize {
            p += 1;
            continue;
        }
        if buf[p + 5] != 0x84 || buf[p + 6] != 0xC0 {
            p += 1;
            continue;
        }
        let test_rva = p + 5;
        let jcc_pos = p + 7;
        let (opc, len, disp) = match jcc_info(buf, jcc_pos) {
            Some(x) => x,
            None => {
                p += 1;
                continue;
            }
        };
        let next = jcc_pos + len;
        let jcc_target_va =
            ((image.image_base as usize + next) as isize + disp) as usize;
        let jcc_target_rva = match jcc_target_va.checked_sub(image.image_base as usize) {
            Some(r) => r,
            None => {
                p += 1;
                continue;
            }
        };
        if jcc_target_va < image.image_base as usize {
            p += 1;
            continue;
        }
        let fall = next;
        // Direction: for jne/jnz, taken = success (al != 0), so the failure
        // string must sit in the fall-through, and the jump must skip over it.
        // For je/jz, taken = failure, so the string must sit at/after the target.
        let valid = match opc {
            0x75 | 0x85 => {
                xref_rva >= fall && jcc_target_rva > xref_rva && jcc_target_rva >= fall
            }
            0x74 | 0x84 => {
                xref_rva >= jcc_target_rva
                    && jcc_target_rva >= fall
                    && jcc_target_rva > jcc_pos
            }
            _ => false,
        };
        if !valid {
            p += 1;
            continue;
        }
        let end = next;
        let pattern_bytes = buf[p..end].to_vec();
        let mut pattern_mask = vec![b'x'; pattern_bytes.len()];
        for k in 1..5 {
            pattern_mask[k] = b'?';
        }
        for k in 0..len {
            pattern_mask[jcc_pos - p + k] = match k {
                0 | 1 if opc == 0x0F => b'x',
                0 if opc == 0x74 || opc == 0x75 => b'x',
                _ => b'?',
            };
        }
        // If jcc is the near form 0F 84/85, bytes at jcc_pos and jcc_pos+1 are 'x'.
        // For short form, only the opcode byte is 'x'.
        return Some(TrustGate {
            call_rva: p,
            trust_fn_rva: tgt_rva,
            test_rva,
            patch_offset: test_rva - p,
            patch_bytes: vec![0x0C, 0x01],
            pattern_bytes,
            pattern_mask,
        });
    }
    None
}

fn find_all_direct_calls(image: &PeImage, target_rva: usize) -> Vec<usize> {
    let buf = &image.reconstructed;
    let target_va = image.image_base as usize + target_rva;
    let mut out = Vec::new();
    for i in 0..buf.len().saturating_sub(5) {
        if buf[i] == 0xE8 {
            let disp = i32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
            let call_va = image.image_base as usize + i + 5;
            if (call_va as isize + disp as isize) as usize == target_va {
                out.push(i);
            }
        }
    }
    out
}

// For a caller of a trust function that doesn't have a `test al,al` right after
// the call (e.g. `movzx ecx, al; ... test cl,cl; jne`), patch the short jne to an
// unconditional jmp so the success path is always taken.
fn find_movzx_gate_at_call(image: &PeImage, call_rva: usize) -> Option<TrustGate> {
    let buf = &image.reconstructed;
    let p = call_rva;
    if p + 6 > buf.len() {
        return None;
    }
    // `movzx <r32>, al` == 0F B6 modrm with rm == 000 (al)
    let is_movzx_al = buf[p + 5] == 0x0F && buf[p + 6] == 0xB6 && (buf[p + 7] & 0xC7) == 0xC0;
    if !is_movzx_al {
        return None;
    }
    let mut q = p + 8;
    let scan_end = (p + 8 + 0x60).min(buf.len().saturating_sub(3));
    while q < scan_end {
        // test cl,cl == 84 C9 ; short jne == 75
        if buf[q] == 0x84 && buf[q + 1] == 0xC9 && buf[q + 2] == 0x75 {
            let jcc_pos = q + 2;
            let pattern_bytes = buf[p..jcc_pos + 2].to_vec();
            let mut pattern_mask = vec![b'?'; pattern_bytes.len()];
            pattern_mask[0] = b'x';
            pattern_mask[q - p] = b'x';
            pattern_mask[q - p + 1] = b'x';
            pattern_mask[jcc_pos - p] = b'x';
            return Some(TrustGate {
                call_rva: p,
                trust_fn_rva: 0,
                test_rva: q,
                patch_offset: jcc_pos - p,
                patch_bytes: vec![0xEB],
                pattern_bytes,
                pattern_mask,
            });
        }
        q += 1;
    }
    None
}

/// Detect trust-check gates generically:
/// 1. anchor on trust-failure strings, find all xrefs, and walk back to the
///    `call <trustfn>; test al,al; jcc` gate that guards them;
/// 2. enumerate every direct caller of each discovered trust function and patch
///    its gate too (including `movzx`-style gates).
/// Each gate becomes a `bytepatch` PatternEntry that flips `test al,al`
/// (84 C0) into `or al,1` (0C 01) so the success branch is always taken.
pub fn find_trust_checks(image: &PeImage, existing: &[PatternEntry]) -> Vec<PatternEntry> {
    let needles = [
        "Trust check failed",
        "{}: Trust check failed",
        "Image Url is not trusted",
        "HttpRequest.Url is not trusted",
        "Url is not trusted",
        "url is not trusted",
        "is not trusted",
        "not trusted",
        "Not trusted",
    ];
    let buf = &image.reconstructed;
    let mut gates: Vec<TrustGate> = Vec::new();
    let mut trust_fns: Vec<usize> = Vec::new();

    for needle in needles {
        let mut search = 0usize;
        loop {
            if search + needle.len() > buf.len() {
                break;
            }
            match buf[search..]
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
            {
                Some(rel) => {
                    let str_rva = search + rel;
                    for xr in find_all_lea_xrefs(image, str_rva) {
                        if let Some(g) = find_gate_for_xref(image, xr) {
                            if !gates.iter().any(|x| x.test_rva == g.test_rva) {
                                gates.push(g.clone());
                                if !trust_fns.contains(&g.trust_fn_rva) {
                                    trust_fns.push(g.trust_fn_rva);
                                }
                            }
                        }
                    }
                    search = str_rva + needle.len();
                }
                None => break,
            }
        }
    }

    for &fn_rva in &trust_fns {
        for call_rva in find_all_direct_calls(image, fn_rva) {
            let buf = &image.reconstructed;
            if buf[call_rva + 5] == 0x84 && buf[call_rva + 6] == 0xC0 {
                let jcc_pos = call_rva + 7;
                if let Some((opc, len, _disp)) = jcc_info(buf, jcc_pos) {
                    let next = jcc_pos + len;
                    let pattern_bytes = buf[call_rva..next].to_vec();
                    let mut pattern_mask = vec![b'x'; pattern_bytes.len()];
                    for k in 1..5 {
                        pattern_mask[k] = b'?';
                    }
                    for k in 0..len {
                        pattern_mask[jcc_pos - call_rva + k] = match k {
                            0 | 1 if opc == 0x0F => b'x',
                            0 => b'x',
                            _ => b'?',
                        };
                    }
                    let test_rva = call_rva + 5;
                    if !gates.iter().any(|x| x.test_rva == test_rva) {
                        gates.push(TrustGate {
                            call_rva,
                            trust_fn_rva: fn_rva,
                            test_rva,
                            patch_offset: 5,
                            patch_bytes: vec![0x0C, 0x01],
                            pattern_bytes,
                            pattern_mask,
                        });
                    }
                }
            } else if let Some(g) = find_movzx_gate_at_call(image, call_rva) {
                if !gates.iter().any(|x| x.test_rva == g.test_rva) {
                    gates.push(g);
                }
            }
        }
    }

    let mut out: Vec<PatternEntry> = Vec::new();
    for g in gates.into_iter() {
        let covered = existing.iter().any(|e| {
            e.kind == "bytepatch"
                && e.patch_offset.map(|o| e.rva + o) == Some(g.test_rva)
        });
        if covered {
            continue;
        }
        let name = format!("TRUST_CHECK_{}", out.len());
        let desc = if g.patch_bytes == vec![0x0C, 0x01] {
            format!("trust gate: test al,al -> or al,1 (fn rva 0x{:x})", g.trust_fn_rva)
        } else {
            "trust gate (movzx): short jne -> jmp".to_string()
        };
        out.push(PatternEntry {
            name,
            rva: g.call_rva,
            kind: "bytepatch".to_string(),
            patch_offset: Some(g.patch_offset),
            patch_bytes: Some(g.patch_bytes),
            pattern_bytes: g.pattern_bytes,
            pattern_mask: g.pattern_mask,
            description: desc,
        });
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    const IMG_BASE: u64 = 0x140000000;

    fn fake_image(payload: Vec<u8>) -> PeImage {
        let len = payload.len();
        PeImage {
            image_base: IMG_BASE,
            image_size: len,
            sections: vec![],
            reconstructed: payload,
            sha256: "test".to_string(),
            file_size: len as u64,
        }
    }

    // call at 0x2000 -> trust fn at 0x1000; test al,al; jne32 to 0x2040;
    // fall-through lea loads "Trust check failed" at 0x3000.
    fn build_jne_gate() -> Vec<u8> {
        let mut buf = vec![0u8; 0x4000];
        // call 0x146ce7bdb-style: E8 disp where call_va+5+disp == 0x140001000
        buf[0x2000..0x2005].copy_from_slice(&[0xE8, 0xFB, 0xEF, 0xFF, 0xFF]);
        buf[0x2005] = 0x84;
        buf[0x2006] = 0xC0;
        // jne32: next = 0x200D, target 0x2040 => disp 0x33
        buf[0x2007..0x200D].copy_from_slice(&[0x0F, 0x85, 0x33, 0x00, 0x00, 0x00]);
        // lea rax, [rip+disp] -> 0x3000; instr at 0x200D, next_ip 0x2014, disp 0xFFC
        buf[0x200D..0x2014].copy_from_slice(&[0x48, 0x8D, 0x05, 0xEC, 0x0F, 0x00, 0x00]);
        buf[0x3000..0x3000 + 18].copy_from_slice(b"Trust check failed");
        buf
    }

    #[test]
    fn finds_jne32_gate() {
        let img = fake_image(build_jne_gate());
        let found = find_trust_checks(&img, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "TRUST_CHECK_0");
        assert_eq!(found[0].rva, 0x2000);
        assert_eq!(found[0].kind, "bytepatch");
        assert_eq!(found[0].patch_offset, Some(5));
        assert_eq!(found[0].patch_bytes, Some(vec![0x0C, 0x01]));
        // pattern starts with the call and anchors the jcc
        assert_eq!(found[0].pattern_bytes[0], 0xE8);
        assert_eq!(found[0].pattern_mask[0], b'x');
    }

    #[test]
    fn finds_je_gate() {
        let mut buf = vec![0u8; 0x4000];
        buf[0x2000..0x2005].copy_from_slice(&[0xE8, 0xFB, 0xEF, 0xFF, 0xFF]);
        buf[0x2005] = 0x84;
        buf[0x2006] = 0xC0;
        // je32: next = 0x200D, failure target 0x2030 => disp 0x23
        buf[0x2007..0x200D].copy_from_slice(&[0x0F, 0x84, 0x23, 0x00, 0x00, 0x00]);
        // success in fall-through (0x200D)
        buf[0x200D] = 0xC3; // ret
        // failure block at 0x2030: lea rax,[rip+disp] -> 0x3000, next_ip 0x2037, disp 0xFC9
        buf[0x2030..0x2037].copy_from_slice(&[0x48, 0x8D, 0x05, 0xC9, 0x0F, 0x00, 0x00]);
        buf[0x3000..0x3000 + 18].copy_from_slice(b"Trust check failed");
        let img = fake_image(buf);
        let found = find_trust_checks(&img, &[]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].patch_bytes, Some(vec![0x0C, 0x01]));
    }

    #[test]
    fn finds_movzx_gate_via_caller_enumeration() {
        let mut buf = vec![0u8; 0x5000];
        // Seed a trust fn at 0x1000 via a string-anchored jne gate (so the
        // detector learns the trust-fn address from a known trust string).
        buf[0x2000..0x2005].copy_from_slice(&[0xE8, 0xFB, 0xEF, 0xFF, 0xFF]);
        buf[0x2005] = 0x84;
        buf[0x2006] = 0xC0;
        buf[0x2007..0x200D].copy_from_slice(&[0x0F, 0x85, 0x33, 0x00, 0x00, 0x00]);
        buf[0x200D..0x2014].copy_from_slice(&[0x48, 0x8D, 0x05, 0xEC, 0x0F, 0x00, 0x00]);
        buf[0x3000..0x3000 + 18].copy_from_slice(b"Trust check failed");
        // A second caller of the same trust fn using the movzx pattern.
        // call at 0x4000 -> trust fn 0x1000; movzx ecx,al; ...; test cl,cl; jne short
        buf[0x4000..0x4005].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        {
            // disp for call at 0x4000: call_va+5 = 0x140004005, target 0x140001000 => -0x3005
            let disp = (-0x3005i32).to_le_bytes();
            buf[0x4001..0x4005].copy_from_slice(&disp);
        }
        buf[0x4005..0x4008].copy_from_slice(&[0x0F, 0xB6, 0xC8]);
        for b in buf[0x4008..0x4020].iter_mut() {
            *b = 0x90;
        }
        buf[0x4020] = 0x84;
        buf[0x4021] = 0xC9;
        buf[0x4022] = 0x75;
        buf[0x4023] = 0x30;
        let img = fake_image(buf);
        let found = find_trust_checks(&img, &[]);
        let jne_gate = found
            .iter()
            .find(|p| p.patch_bytes == Some(vec![0x0C, 0x01]) && p.rva == 0x2000);
        assert!(jne_gate.is_some());
        let movzx = found.iter().find(|p| p.patch_bytes == Some(vec![0xEB]));
        assert!(movzx.is_some(), "expected a movzx-gate patch, got {:?}", found);
        let g = movzx.unwrap();
        assert_eq!(g.rva, 0x4000);
        assert_eq!(g.patch_offset, Some(0x22));
    }

    #[test]
    fn dedupes_against_existing_bytepatch() {
        let img = fake_image(build_jne_gate());
        let existing = vec![PatternEntry {
            name: "ASYNC_TRUST_CHECK".to_string(),
            rva: 0x2000,
            kind: "bytepatch".to_string(),
            patch_offset: Some(5),
            patch_bytes: Some(vec![0x0C, 0x01]),
            pattern_bytes: vec![],
            pattern_mask: vec![],
            description: "".to_string(),
        }];
        let found = find_trust_checks(&img, &existing);
        assert_eq!(found.len(), 0);
    }
}
