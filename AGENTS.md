# AGENTS.md — Studio-Offline (gaxolotl/studio-offline fork)

Session-compaction notes for working on this repo with opencode. Read this
first, then the docs in `notes/` for details.

## What this project is

**Studio-Offline** lets ROBLOX Studio run fully offline by:
1. A **MinHook DLL** (`studio_offline.dll`) injected into `RobloxStudioBeta.exe`
   that rewrites HTTP request components to `localhost`, forces the "trust
   check" to accept localhost URLs, and NOPs/patches a handful of gates.
2. A **local web server** (`studio_offline_server.exe`, Rust/axum, binds
   `127.0.0.1:80`) that answers all the rewritten API calls: assets,
   settings, telemetry, OAuth, datastores, avatar parts, uploads.
3. A **static/ dir** with preloaded asset/config JSON (baseplate, meshes,
   textures, user settings, OAuth openid).
4. An **offsets scanner** (`offsets_scanner.exe`) that generates
   `offsets.json` from a `RobloxStudioBeta.exe`, so the DLL can patch the
   binary without hardcoding addresses (each Roblox build moves everything).

Repo layout:
- `client/studio_offline/` — injected DLL (hooks.rs = MinHook callbacks,
  offsets.rs = apply patches from offsets.json, patterns.rs = AOB patterns,
  scanner.rs = runtime scan_string/aob_scan/xref helpers).
- `client/webview_who/` — small WebView2Loader shim DLL (`webview_who.dll`).
- `client/offsets_scanner/` — offline scanner tool (see notes/offsets-scanner.md).
- `server/` — the axum web server + all API routes (see notes/server-architecture.md).
- `static/` — preloaded assets/config/settings/OAuth files served by the server.
- `notes/` — RE notes, scanner/server docs, test scripts (this session's work).

## Build & deploy (CRITICAL — ALWAYS via GitHub Actions, never locally)

The local machine (ThinkPad) is not powerful enough for cargo builds.

```sh
# push a commit, then CI auto-runs build.yml on windows-latest:
git push origin <branch>            # push-triggered CI run starts
gh run list --repo gaxolotl/studio-offline --branch <branch> --limit 3
gh run watch <id> --repo gaxolotl/studio-offline --exit-status   # blocks until done
gh run download <id> --repo gaxolotl/studio-offline --dir <dest> # get artifacts
```

Artifacts from CI (release): `studio_offline.dll`, `webview_who.dll`,
`studio_offline_server.exe`, `offsets_scanner.exe`, `studio-offline-server.zip`.

Deploy targets (user's PC, Windows):
- `studio_offline_server.exe` -> `C:\Users\Georgi\Desktop\studio-offline-server\`
- `studio_offline.dll` + `webview_who.dll` -> `C:\Users\Georgi\Desktop\Roblox-Studio-v734\`
- (offsets_scanner.exe can go anywhere; run it on RobloxStudioBeta.exe)

Release assets: push via `gh release upload v1.5 <file> --repo gaxolotl/studio-offline --clobber`.

### Local-only steps (allowed on this machine)
- `cargo test -p offsets_scanner --target x86_64-unknown-linux-gnu` (unit tests)
- `cargo build -p offsets_scanner --release --target x86_64-unknown-linux-gnu`
  (Linux binary works for testing; final Windows exe comes from CI)
- Running the scanner: `target/x86_64-unknown-linux-gnu/release/offsets_scanner
  /tmp/opencode/so734/Roblox-Studio-v734/RobloxStudioBeta.exe -o /tmp/opencode/offsets.json`

## Git setup

- `origin` = https://github.com/gaxolotl/studio-offline.git (push target, hosts GH Actions)
- `upstream` = https://github.com/Roblox-Devs/studio-offline (original project, read-only)
- Working branch: `re-latest-place-version`. `main` tracks upstream's releases.
- NEVER commit secrets. `cookie.txt` (`.ROBLOSECURITY`) is required by Asset Grab
  Mode at runtime but must stay out of the repo.

## Session history / current state (2026-08-15+)

Goal for this session: find and fix ALL Roblox URLs in the binary so offline
mode redirects every service endpoint, and detect all trust-check gates
generically instead of by hand.

Completed:
- **Offsets scanner added** (commit 47f4511): PE loader + URL string scan +
  AOB pattern scan -> `offsets.json`, consumed by the DLL (offsets.rs) with
  per-entry original-byte verification before writing.
- **XMP/metadata blob corruption fixed** (e23dcde): URL capture must stop at
  whitespace/quotes/angle brackets so XML/XMP namespace URLs (w3.org, ns.adobe…)
  are not rewritten; they are denylisted anyway.
- **Generic trust-check detection** (165158c): `scan_trust.rs` finds trust
  gates by string-anchored xrefs + caller enumeration, emits `TRUST_CHECK_*`
  bytepatches (`test al,al` -> `or al,1`). 13 unit tests pass.
- **URL boundary fix** (f7aca42): old rule rejected URLs whose preceding byte
  was printable ASCII, missing standalone NUL-terminated URL constants
  (devforum/studio-bugs, google/generate_204, roblox.com/games/). New union
  rule accepts string-boundary OR NUL-terminated-after. 92 URLs patched on v734
  (was 89), 0 lost. See notes/offsets-scanner.md for the boundary rules.
- **Latest-place-version fix** (earlier commits): NOP the fetcher jne, redirect
  the `data.%1/Data/Upload.ashx` format string to localhost, server returns "1".
- **AsyncHttpQueue trust check** (53c0cfb, 7a9baa2): `test al,al` -> `or al,1`
  (mov al,1 left stale ZF, so use `or al,1` which also clears ZF).
- **Security cookie**: JZ->JNZ patch of the "Security cookie is cached" gate.
- **Avatar customization** (43d47a1): `static/avatar/` override folder + web UI
  at `/avatar` + missing noob parts (head/torso meshes, textures).
- **File-based datastores** (server): `/v2/persistence/{user}/datastores/...`
  stored under `static/datastores/{user}/{store}/{scope}/{key}.dat`.
- CI: build.yml builds the workspace, packages server zip, builds the scanner.

Verified on v734 (`/tmp/opencode/so734/.../RobloxStudioBeta.exe`):
- 811 http(s):// markers, 141 unique URL strings, scanner emits 131 non-localhost
  entries -> 92 patched / 39 skipped.

## What the user can do to help

- Install tools on their PC / provide `RobloxStudioBeta.exe` for new versions.
- Prepare test places/scripts in Studio, start/stop the server, paste console logs.
- Confirm whether patches actually work in their build (DLL console output:
  `Patched URL ...`, `Patched <name> at rva 0x...`, etc.)

## Key gotchas

- `https://H` (movabs immediate) and truncated strings like `http://catalog.`
  are false positives; skipped via length/fit checks.
- Cert-embedded CRL URLs (`crl.comodoca.com`, `crl.comodo.net`) inside X.509
  DER data must NEVER be patched (not NUL-terminated; boundary check excludes).
- Concatenated blob tails (e.g. `https://luau.orghttps://create...`) are
  rejected by `is_clean_single_url` (contains a second `://`); the scanner
  advances past each match so the tail isn't re-matched.
- Changing URL rules must keep all currently-patched URLs (89 on v734) while
  adding the new finds; diff old vs new offsets.json to verify.
- `.cargo/config.toml` must NOT be committed (broke CI paths on windows-latest).
- Only 1 dead-code warning exists (pe.rs `readable` field), no other warnings.

## Notes index

- `notes/offsets-scanner.md` — how the scanner works (URL scan rules, trust gates, patterns, offsets.json).
- `notes/server-architecture.md` — server routes, modes, datastores, avatar.
- `notes/RE-latest-place-version.md` — original RE investigation for the "latest place version" bug.
- `notes/datastore_test.luau` — Studio test script for local datastores.
- `notes/disasm.py`, `notes/xrefs.py` — capstone helpers (need `STUDIO_EXE` env var on new PCs).