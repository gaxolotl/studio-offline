# studio-offline RE notes — place 95206881 "Error fetching latest place version"

Session date: 2026-08-14. Goal: make place **95206881** open in studio-offline (Regular Mode).
Failure: `Open Place failure : DataModelLoadingFailure:Error fetching latest place version`.

---

## IMPORTANT BUILD/DEPLOY RULES (from AGENTS.md)

- **NEVER build locally** (ThinkPad too slow). Use GitHub Actions:
  - `gh workflow run build.yml --repo gaxolotl/studio-offline`
  - `gh run watch <id> --repo gaxolotl/studio-offline --exit-status`
  - `gh run download <id> --repo gaxolotl/studio-offline --dir <dest>`
  - Deploy: `studio_offline.dll` + `webview_who.dll` -> `C:\Users\Georgi\Desktop\Roblox-Studio-v734\`
    and `studio_offline_server.exe` -> `C:\Users\Georgi\Desktop\studio-offline-server\`
- Git remotes (see AGENTS.md): `origin` = https://github.com/gaxolotl/studio-offline.git
  (push target, GH Actions host); `upstream` = https://github.com/Roblox-Devs/studio-offline
  (original project, read-only).
- This session's branch: **`re-latest-place-version`** (all this analysis is committed here).
- Server binary listens on **127.0.0.1:80**; Studio is launched with `--offline` from `C:\Users\Georgi\Desktop\Roblox-Studio-v734\`.

### Working on a NEW PC (important)
- Clone/fetch this branch: `git fetch origin && git checkout re-latest-place-version`
  (or clone https://github.com/gaxolotl/studio-offline.git and checkout the branch).
- The scripts `notes/disasm.py` and `notes/xrefs.py` need **Python + `capstone`**
  (`pip install capstone`) and the analyzed exe.
- The exe is NOT in the repo (too big). Copy it from the old PC:
  `C:\Users\Georgi\AppData\Local\Temp\opencode\so734\RobloxStudioBeta.exe`
  (unmodified, v734) to the new PC, then set the env var when running the scripts:
  `$env:STUDIO_EXE="C:\path\to\RobloxStudioBeta.exe"`.
  If the v734 exe is unavailable, rebuild analysis against whatever version is in
  `C:\Users\Georgi\Desktop\Roblox-Studio-v734\RobloxStudioBeta.exe` and recompute addresses.

## The puzzle / key correction

The "latest place version" fetch makes **ZERO HTTP requests** in every run we examined
(pre-patch 09:42 run `...094159Z_Studio_21947`, post-patch 12:31 `...T123103Z_Studio_CEDEC`,
12:33 `...T123326Z_Studio_CBB74`). Evidence:

- No `/Data/Upload.ashx` (or any version URL) ever reaches the localhost server.
- Grepping all Studio logs for `external:1`, `data\.roblox\.com`, `Upload.ashx`, `assetid=`,
  `PlaceVersionCheck`, `assets/.*/versions` returns NOTHING.
- Identical fast failure (~0.16s -> 0.7s after `FetchLatestPlaceVersionNumber` telemetry)
  before and after the URL patch.

Earlier belief ("goes to real data.roblox.com (401)") is **not supported** by these logs —
treat "no HTTP request at all" as ground truth. The failure happens *before* any request is
sent, in the fetcher itself.

## Patch status (what is committed & deployed)

- Client (`client/studio_offline/src/lib.rs`, commit `60f4a88`): runtime overwrite of format
  string at file `0x929AA70` / VA `0x14929C470`:
  - old: `https://data.%1/Data/Upload.ashx?assetid=%2`  (43 bytes)
  - new: `http://localhost/Data/Upload.ashx?a=%1&b=%2` (43 bytes, same length)
  - Runtime-verified: console prints
    `Found latest-place-version URL at 0x7ff67804c470 / Patched ... -> http://localhost/...`
    computed base `0x7FF66EDB1A00` => offset `0x929AA70` correct.
- Server (`server/src/routes/assets.rs`): `/Data/Upload.ashx` returns plain-text `"1"` if
  query has assetid/assetId/a/b > 0; also `/assets/user-auth/v1/assets/{id}/versions`
  returns a JSON `{assetVersions:[{... versionNumber:1 ...}], nextPageToken:null}`.
- Note: the `/Data/Upload.ashx` handler only matters once a request actually arrives — it never does yet.

## DISASSEMBLY FINDINGS (analyzed exe: `RobloxStudioBeta.exe` v734)

Exe: `C:\Users\Georgi\AppData\Local\Temp\opencode\so734\RobloxStudioBeta.exe`
(section map & VA->file-offset mapping in `notes/disasm.py`; xref tool in `notes/xrefs.py`).
`img_base = 0x140000000`. For `.text` (va=0x1000 rawptr=0x400): `file_off = VA - 0x140000000`.

### Strings of interest
- VA `0x14929C470` (file `0x929AA70`): `https://data.%1/Data/Upload.ashx?assetid=%2` — patched.
- VA `0x14929C4A0` (file `0x929AAA0`): `Error fetching latest place version` — right after format string.
- File `0x92378EE`: `assets/user-auth/v1/assets/{}/versions` + `[FLog::PlaceVersionCheck]`
  + `did not return a table with "assetVersions"` — a DIFFERENT candidate endpoint (unverified which path uses it).

### FetchLatestPlaceVersionNumber — VA `0x14234E590` (file `0x234D990`)
Complex function; arg0=this(rbx), rdx, r8, r9d=int. Flow:
- r9d<=0 -> calls `0x142C6BED0`
- calls `0x14203E590` (string builder), `0x1414BA7B0` (lea rcx,[rsi+0x1D0]),
  `0x1449B2710`
- at `0x14234EAA8`: calls builder **`0x14234E3C0`** with
  rcx=[rsp+0x28], rdx=r13 (arg2), r8=byte [rbp+0x1A0]  <-- flag gates the format-string path
- at `0x14234EAC1`: `lea r8,[rbp-0x28]`; `mov rdx,[rbx]`; `lea rcx,[rbp+0x100]`; call **dispatcher `0x1432AC100`**
- after: `mov rsi,[rbp+0x100]`; `cmp rsi,-1`; `je 0x14234EBE4` (failure path)

### URL builder — VA `0x14234E3C0` (file `0x234D7C0`)
- `r14=rcx` (out struct), `r15=rdx` (arg2), `edi=r8b` (flag)
- rbx=[rcx]; vtable call `[rbx+0x1D0]+0x268`
- if `edi != 0`: builds URL using the format string (uses a std::format-style call with
  `edx=0x2b` (43, string length) + `lea rcx,[rip+0x6F4E015]` = format string at `0x14929C470`,
  then substitutes `%1`/`%2`). Result lands in a buffer passed to `0x144A1F110`.
- **if `edi == 0`: the entire format-string URL construction is SKIPPED** (je 0x14234E532).
  This strongly suggests the fetch may take a different path when the flag is 0 —
  i.e., the patched string may never be used at runtime. Need to know what
  byte[rbp+0x1A0] (the flag passed from FetchLatestPlaceVersionNumber) is at runtime.

### Dispatcher — VA `0x1432AC100` (partially disassembled, complete body unknown)
- rsi=rcx(out), rbx=rdx(this=arg), r13=r8(url?)
- `cmp byte ptr [rdx+0x4FA],0` ; `je 0x1432AC21A` (main path)
- On the `!=0` path it appears to build an error / write -1 to [rsi] (failure).
- Main path does double/timing math (writes doubles to `[rax+0x940..0x958]` via `0x144A0EFC0`)
  and a string move (`0x140711D60`), then calls `0x1449AA150` with various stack args —
  that call likely IS the network/version fetch. Disassembly truncated at `0x1432AC16A`
  (it was continued but the interesting dispatch site / actual HTTP layer call is unresolved).

## NEXT STEPS (for next session, on a faster PC)

1. **Finish disassembly** with `notes/disasm.py`:
   - complete dispatcher `0x1432AC100` (disasm 0x1432AC100 len 0x800) — find the real
     HTTP/socket call and what URL/endpoint it uses.
   - complete `FetchLatestPlaceVersionNumber` (0x14234E590 len 0x600) — determine what
     `byte[rbp+0x1A0]` is (the flag gating the format string), and whether the patched
     URL is ever actually constructed.
   - `notes/xrefs.py 0x14929C4A0` (slow; only run on fast PC) to find every code ref to
     the error string and learn the exact trigger condition.
2. Determine which endpoint the fetcher actually wants:
   patched `/Data/Upload.ashx` vs `/assets/user-auth/v1/assets/{id}/versions`.
3. Once the real request is found, either make the client redirect it correctly or make
   the server answer it; then **rebuild via GH Actions** and redeploy.
4. Consider instrumenting the client (an extra AOB hook / console log) to print the URL
   actually built at runtime instead of guessing from static analysis.

## Deployment & repro checklist (next session)

- Server running (PID was 6608) on 127.0.0.1:80 from `C:\Users\Georgi\Desktop\studio-offline-server\`.
- Studio runs with `--offline`; logs at `C:\Users\Georgi\AppData\Local\Roblox\logs\`
  (`0.734.0.7340915_*.log`; runs 21947=09:42 pre-patch, CEDEC=12:31, CBB74=12:33).
- Failure sequence in log: `Creating component 'Studio::LatestPlaceVersionFetcher (Key Place '<GUID>-95206881')'`
  -> telemetry `FetchLatestPlaceVersionNumber` -> `Open Place failure : DataModelLoadingFailure:Error fetching latest place version`.