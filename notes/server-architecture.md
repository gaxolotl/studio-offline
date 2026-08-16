# Studio-Offline server (`studio_offline_server.exe`)

Rust/axum HTTP server that binds `127.0.0.1:80` and answers every API call the
injected DLL redirects to localhost. Requires `./static` to exist next to the
exe. Mode selection at startup via `inquire::Select`:

- **Asset Grab Mode** — downloads real assets from Roblox for later offline
  use; requires `cookie.txt` (`.ROBLOSECURITY`) in the server directory.
  NEVER commit `cookie.txt`.
- **Regular Mode** — serves only preloaded `static/` files (offline).
- **Reflection Mode** — redirects asset requests to the appropriate local
  static/ paths without needing a login.

Entry: `server/src/main.rs`. Common plumbing: `app_state.rs` (mode),
`request_logger.rs` (non-invasive request logging), `asset_types.rs`.

## Routes (grouped)

### Assets (`routes/assets.rs`)
- `GET /v1/asset?id=...` / `GET /v1/asset/` — serve preloaded asset file from
  `static/assets/{id}` (baseplate, meshes, textures…).
- `GET /ddl/{id}` — same by path segment.
- `POST /v1/assets/batch` — batch asset metadata/location responses.
- `GET /assets/user-auth/v1/assets/{id}` (+ `/versions`) — place download /
  version list; `/versions` returns
  `{assetVersions:[{...versionNumber:1...}], nextPageToken:null}`.
- `GET /Data/Upload.ashx` — returns plain text `"1"` when the query has
  `assetid`/`assetId`/`a`/`b` > 0 (used by the latest-place-version fix).

### Uploads (`routes/upload.rs`)
- `POST /user-auth/v1/assets` — accepts multipart asset create; fake
  OperationResponse `{path, operationId, done}`.
- `GET /user-auth/v1/operations/{operation_id}` — returns `{done: true,
  response:{...assetId...}}` so Studio believes the publish completed.

### Datastores (`routes/datastores.rs`) — file-backed local DataStores
- `GET/POST/DELETE /v2/persistence/{user_id}/datastores/{*rest}`.
- File layout: `static/datastores/{user_id}/{datastore}/{scope}/{key}.dat`.
- Handles: list keys (`/objects`), increment, set/get/delete by `objectKey`.
- `notes/datastore_test.luau` exercises these from Studio.

### Avatar customization (`routes/avatar.rs`)
- `GET /avatar` (+ `/`) — web UI to override avatar parts.
- `GET /avatar/api/parts` — list parts from `static/avatar/avatar.json`.
- `POST /avatar/api/upload/{id}` — overwrite a part file.
- `POST /avatar/api/reset/{id}` — delete override, restore default.
- `GET /avatar/file/{id}` — serve override or default.
- Missing noob parts (head/torso meshes, textures) shipped in
  `static/avatar/` + `static/assets/`.

### Static / config / OAuth (`routes/static_handlers.rs`, `oauth.rs`,
    `client_settings.rs`, `universal_app_config.rs`)
- `GET /v2/logout`, `/v1/users/authenticated`,
  `/studio-user-settings/v1/user/studiodata/InstalledPluginsAsJson_V001`,
  plugin-permissions, `/headshot`, `/renders/places/default.png`,
  `/my/settings/json`, BetaFeatureInformation, user groups/roles,
  `/v1/not-approved`, `/userhub`, `/v1/user/experiences`.
- OAuth: `/.well-known/openid-configuration`, `POST /v1/token`,
  `/v1/userinfo`, `/v1/authorize` — served from `static/auth/OAuth/`.
- ClientSettings: `/v2/settings/application/PCStudioApp` ->
  `static/config/ClientSettings/PCStudioApp.json`.
- Universal app config + `GET /guac-v2/v1/bundles/studio`.

### Telemetry (`routes/telemetry.rs`)
- `GET/POST /game/validate-machine`, `GET/POST /studio/pbe`,
  `POST /v1.0/SequenceStatistics/BatchAddToSequencesV2` — all return `{}` /
  `{success:true}` stubs.

## Modes & data flow

1. DLL rewrites every outgoing URL to `http://localhost{path}`.
2. Trust-check gates are patched so localhost URLs are accepted.
3. Server answers the rewritten paths from `static/` (Regular/Reflection) or
   proxies/downloads from Roblox (Asset Grab).
4. Anything not handled returns a stub so Studio doesn't error.

## Deploy

`studio_offline_server.exe` + `static/` zip is built by CI
(`studio-offline-server.zip`) and deployed to
`C:\Users\Georgi\Desktop\studio-offline-server\`. CI always builds
`--release` on windows-latest via push-triggered `build.yml`.