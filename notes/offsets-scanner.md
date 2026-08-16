# Studio-Offline offsets scanner (`offsets_scanner`)

Generates `offsets.json` from a `RobloxStudioBeta.exe` so the injected DLL
(`client/studio_offline/src/offsets.rs`) can patch the binary without
hardcoded addresses. Each Roblox build relocates every function/string, so we
scan the binary at build time and record RVAs (relative to the module base).

## Pipeline

```
RobloxStudioBeta.exe
        |
        v
 pe.rs::load          -> PeImage { reconstructed: image, sections, image_base, sha256 }
        |
        +-- scan_urls.rs::find_urls       -> Vec<UrlEntry>          (URL string rewrites)
        +-- scan_patterns.rs::scan_patterns -> Vec<PatternEntry>    (AOB hooks/bytepatches)
        +-- scan_trust.rs::find_trust_checks -> Vec<PatternEntry>   (generic trust gates)
        +-- scan_trust.rs::find_security_cookie -> Option<SecurityCookieEntry>
        +-- scan_trust.rs::find_trust_strings -> Vec<TrustStringEntry>
        |
        v
 offsets.json  (serde, camelCase, format_version 1)
```

`pe.rs::load`:
- Parses the PE via `goblin`.
- **Reconstructs** the in-memory image (`reconstructed` = `SizeOfImage` zeros,
  then copies each section's raw bytes at its virtual address). Scanning runs
  on the reconstructed image so RVAs match what the DLL sees at runtime.
- `rva` is the offset from `image_base` (`0x140000000` typically). The DLL
  computes `base + rva` and verifies original bytes before writing.

## offsets.json entries

### `urls: Vec<UrlEntry>`
- `rva`, `encoding` (`"ascii"` | `"utf16"`), `length` (bytes), `original`,
  `replacement`, `host`, `skipped`, `reason`.
- `skipped` entries carry a reason (`placeholder authority`,
  `non-service host 'X' excluded`, `replacement longer than original`,
  `not a single clean URL (concatenated blob)`). The DLL skips them.
- Replacements are always `http://localhost...` **same length or shorter** than
  the original; the DLL NUL-pads on write.

### `patterns: Vec<PatternEntry>`
- `kind`: `"hook"` (MinHook; DLL calls `hooks::*`) or `"bytepatch"`
  (raw byte overwrite at `rva + patch_offset`).
- Includes the 3 hooks (`URL_ONCOMPONENT`, `TRUSTCHECK`, `HTTP_REQUEST_URL`),
  the hand-written bytepatches (`FETCHER_JNE_THROW`, `ASYNC_TRUST_CHECK`), and
  the scanner-generated `TRUST_CHECK_*` gates.
- The DLL re-verifies the pattern bytes still match before applying (stale
  offsets protection).

### `security_cookie: SecurityCookieEntry` (optional)
- `jz_rva`, `original_opcode`, `patch_bytes` — JZ->JNZ of the
  "Security cookie is cached" gate.

### `trust_strings`
- Informational: every "Trust check failed" / "is not trusted" style string +
  its xref (used by RE, not applied by the DLL).

## URL scanning (`scan_urls.rs`)

### Marker + expansion
- Find `http://` / `https://` in the reconstructed image (ASCII and UTF-16LE).
- Expand forward only through `is_url_char` bytes: printable ASCII except
  `"`, `'`, `<`, `>`. This stops at the whitespace/quotes/angle brackets that
  appear inside XML/XMP/metadata blobs (the old scanner swallowed the whole
  blob and corrupted it — see commit e23dcde).
- Cap at `MAX_URL_BYTES` (512).

### Boundary rule (commit f7aca42) — "string boundary OR NUL-terminated"
A marker match is accepted if **either**:
1. the byte **before** the marker is non-printable (string boundary), **or**
2. the byte **after** the captured URL is `NUL` (standalone NUL-terminated
   string constant).

This union is the fix for URLs that were *missed*: constants like
`https://devforum.roblox.com/c/platform-feedback/studio-bugs`,
`http://www.google.com/generate_204`, `https://www.roblox.com/games/` are
NUL-terminated but sit next to unrelated data whose last byte is printable
ASCII, so the old prev-byte-only rule skipped them.

Why this doesn't regress the XMP/cert cases:
- XML/XMP namespace URLs (`w3.org`, `ns.adobe.com`, …) are mid-string
  (`xmlns:x="http://…"`), preceded AND followed by quotes/brackets — neither
  boundary condition holds.
- Cert-embedded CRL URLs (`crl.comodoca.com`, `crl.comodo.net`) inside X.509
  DER data are not NUL-terminated after (they're followed by DER tag bytes),
  and are preceded by DER bytes — rejected.

### Post-filters (`find_urls`)
- `is_clean_single_url`: authority must contain only host-legal chars
  (`A-Za-z0-9 . - : % _ [ ] @`) and the string must NOT contain a second `://`
  (rejects concatenated blobs like `https://luau.orghttps://create...`).
- `localhost_replacement`: builds `http://localhost{rest}`; returns `None` for
  already-local hosts (`localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`) and for
  empty authorities. Special-case `KNOWN` table for same-length hand-crafted
  replacements (e.g. `data.%1/Data/Upload.ashx`).
- `classify`: skip if `skipped` (placeholder authority with `%`), host is in
  `DENYLISTED_HOST_SUFFIXES` (w3.org, ns.adobe.com, purl.org,
  schemas.microsoft.com, webrtc.org, ietf.org, crbug.com, chromium.org,
  github.com, curl.se, creativecommons.org, exif.org, iptc.org, xml.org), or
  the replacement doesn't fit (longer than original -> falls back to
  `http://localhost` and is skipped).
- Scanner advances `i = end` past each match so a concatenated blob's tail URL
  is never re-matched.

### v734 numbers (verified)
811 http(s):// markers, 141 unique URL strings, 131 non-localhost entries:
92 patched, 39 skipped. Previously 89 patched — the boundary fix added the 3
genuine URLs above with 0 regressions.

## Hand-written patterns (`scan_patterns.rs`)

AOB patterns ported from `client/studio_offline/src/patterns.rs`:
- `URL_ONCOMPONENT` — HttpRequest FromComponents; hooked to rewrite
  scheme/host to localhost.
- `TRUSTCHECK` — the trust-check entrypoint; hooked to trust localhost URLs.
- `HTTP_REQUEST_URL` — notTrusted hook; always returns trusted (`"1"`).
- `FETCHER_JNE_THROW` — NOP the 6-byte jne so latest-place-version falls
  through to the dispatcher (see notes/RE-latest-place-version.md).
- `ASYNC_TRUST_CHECK` — `test al,al` -> `or al,1` (0C 01) at +17 so the
  following `jne` always takes the success path. `or al,1` clears ZF (a
  `mov al,1` leaves stale flags and broke the jne — commit 7a9baa2).

## Generic trust-check detection (`scan_trust.rs`)

Instead of hand-locating every "trust check" gate per build, this finds them
algorithmically:

1. **Anchor on strings.** For each needle (`"Trust check failed"`,
   `"is not trusted"`, …) find every `lea reg,[rip+disp]` xref to it
   (`find_all_lea_xrefs`, handles REX + non-REX forms).
2. **Walk back to the gate.** `find_gate_for_xref` scans backwards up to 0x100
   bytes for the pattern `call <trustfn>; test al,al (84 C0); jcc`. It
   validates jump direction: for `jne/jnz` the failure string must be in
   fall-through; for `je/jz` it must be at/after the jump target.
3. **Enumerate every caller.** Each discovered trust function's address is
   recorded; `find_all_direct_calls` finds all `E8` callers and patches their
   gate too. Some callers use `movzx <r32>,al; ...; test cl,cl (84 C9); jne`
   instead of `test al,al` — `find_movzx_gate_at_call` patches the short jne
   to an unconditional `jmp` (`EB`).
4. **Emit bytepatches.** Each gate becomes a `TRUST_CHECK_N` `PatternEntry`
   whose patch flips `test al,al` (84 C0) into `or al,1` (0C 01) at offset 5,
   or patches the movzx jne. Gates already covered by an existing bytepatch
   (same `test_rva`) are deduped — e.g. `ASYNC_TRUST_CHECK` isn't re-added.
5. `find_security_cookie` — string-anchored: finds the "Security cookie is
   cached" string, its `lea` xref, then decodes backwards (iced-x86) to the
   first `je` preceded by `cmp`, and returns JZ->JNZ patch bytes.

On v734 this produced `TRUST_CHECK_0` (0x6ce7bdb) and `TRUST_CHECK_1`
(0x15cb82e) in addition to `ASYNC_TRUST_CHECK`.

## Consuming the file (`client/studio_offline/src/offsets.rs`)

- `offsets::load()` reads `offsets.json` next to the exe (DLL dir or cwd),
  requires `format_version == 1`.
- `offsets::apply()`:
  1. **URLs** — for each non-skipped entry, verify the original URL bytes are
     still at `base + rva` (stale-offsets guard) then
     `write_padded_ascii`/`write_padded_utf16` (NUL-padded to original length).
  2. **Patterns** — verify pattern bytes via mask; `hook` entries go through
     MinHook (`MH_CreateHook`/`MH_EnableHook` with the matching hook fn by
     name), `bytepatch` entries write `patch_bytes` at `rva + patch_offset`.
  3. **Security cookie** — verify `original_opcode` then write `patch_bytes`.
- If `offsets.json` is missing, the DLL falls back to runtime AOB scanning
  (`scanner.rs`) of the legacy `patterns.rs` constants.

## Tests

`cargo test -p offsets_scanner --target x86_64-unknown-linux-gnu`
(16 tests): URL scans (ascii/utf16/localhost/placeholder/XMP-blob/concat-blob/
cert-url/mid-string/boundary-union), pattern scans, trust gates (jne32, je,
movzx, dedup). Fake `PeImage`s are built in memory.