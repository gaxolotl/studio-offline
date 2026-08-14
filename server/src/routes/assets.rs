use crate::app_state::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;
use tower_http::services::ServeFile;
use urlencoding::decode;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AssetQuery {
    id: String,
    #[serde(default)]
    contentRepresentationPriorityList: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct BatchError {
    code: u16,
    message: String,
    #[serde(rename = "customErrorCode")]
    custom_error_code: i32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(non_snake_case)]
struct BatchRequestEntry {
    assetId: i64,
    requestId: String,
    assetType: String,
    #[serde(default)]
    contentRepresentationPriorityList: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[allow(non_snake_case)]
struct BatchResponseEntry {
    location: Option<String>,
    requestId: String,
    isArchived: bool,
    assetTypeId: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Vec<BatchError>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contentRepresentationSpecifier: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    assetMetadatas: Option<serde_json::Value>,
    #[serde(default)]
    isRecordable: bool,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v1/asset", get(handle_asset_by_query))
        .route("/v1/asset/", get(handle_asset_by_query))
        .route("/ddl/{id}", get(handle_asset_by_path))
        .route("/v1/assets/batch", post(handle_assets_batch))
        .route("/v1/assets/batch/", post(handle_assets_batch))
        .route(
            "/assets/user-auth/v1/assets/{id}",
            get(handle_user_auth_asset),
        )
        .route(
            "/assets/user-auth/v1/assets/{id}/",
            get(handle_user_auth_asset),
        )
}

async fn handle_user_auth_asset(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if state.mode == "Reflection Mode" {
        return Redirect::temporary(&format!(
            "https://assetdelivery.roblox.com/v1/asset/?id={id}&permissionContext=ignoreUniverse&xcachesplit=0"
        ))
        .into_response();
    }

    serve_asset_logic(state, id, None, req).await
}

async fn handle_assets_batch(
    State(state): State<Arc<AppState>>,
    Json(requests): Json<Vec<BatchRequestEntry>>,
) -> Response {
    let mode = &state.mode;
    let request_map: HashMap<String, i64> = requests
        .iter()
        .map(|r| (r.requestId.clone(), r.assetId))
        .collect();

    if mode == "Asset Grab Mode" {
        let cookie_path = PathBuf::from("cookie.txt");
        if let Ok(cookie_content) = tokio::fs::read_to_string(cookie_path).await {
            let client = reqwest::Client::new();
            if let Ok(res) = client
                .post("https://assetdelivery.roblox.com/v1/assets/batch")
                .header(
                    "Cookie",
                    format!(".ROBLOSECURITY={}", cookie_content.trim()),
                )
                .header("User-Agent", "RobloxStudio/WinInet")
                .json(&requests)
                .send()
                .await
            {
                match res.status().as_u16() {
                    200 => {
                        if let Ok(mut batch_response) = res.json::<Vec<BatchResponseEntry>>().await
                        {
                            for entry in &mut batch_response {
                                if let Some(&asset_id) = request_map.get(&entry.requestId) {
                                    let file_path =
                                        PathBuf::from("static/assets").join(asset_id.to_string());
                                    if !file_path.exists() {
                                        if let Some(location) = &entry.location
                                            && let Ok(download_res) =
                                                client.get(location).send().await
                                            && download_res.status().is_success()
                                        {
                                            if let Some(parent) = file_path.parent() {
                                                let _ = tokio::fs::create_dir_all(parent).await;
                                            }
                                            if let Ok(bytes) = download_res.bytes().await
                                                && let Ok(mut file) = File::create(&file_path).await
                                            {
                                                let _ = file.write_all(&bytes).await;
                                                tracing::info!("Grabbed asset: {}", asset_id);
                                            }
                                        }
                                        let filename = if let Some(ref crs) =
                                            entry.contentRepresentationSpecifier
                                        {
                                            let crs_str = crs.to_string();
                                            let hash =
                                                format!("{:x}", md5::compute(crs_str.as_bytes()));
                                            format!("{}-{}", asset_id, hash)
                                        } else {
                                            asset_id.to_string()
                                        };
                                        entry.location =
                                            format!("http://127.0.0.1/ddl/{}", filename).into();
                                    }
                                }
                            }

                            Json(batch_response).into_response()
                        } else {
                            tracing::error!("Failed to parse batch asset response from Roblox.");
                            StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                    }
                    403 => {
                        tracing::error!(
                            "Failed to fetch batch assets: 403 Forbidden. Your .ROBLOSECURITY cookie might be expired or you don't have permission to access the asset."
                        );
                        StatusCode::FORBIDDEN.into_response()
                    }
                    429 => {
                        tracing::error!(
                            "Failed to fetch batch assets: 429 Too Many Requests. You are being rate limited."
                        );
                        StatusCode::TOO_MANY_REQUESTS.into_response()
                    }
                    status => {
                        tracing::warn!("Failed to fetch batch assets: status {}", status);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    }
                }
            } else {
                tracing::error!("Failed to send batch request to Roblox.");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        } else {
            let mut existing_assets = std::collections::HashSet::new();
            let asset_dir = PathBuf::from("static/assets");

            if let Ok(mut entries) = tokio::fs::read_dir(&asset_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Some(stem) = entry.path().file_stem() {
                        existing_assets.insert(stem.to_string_lossy().to_string());
                    }
                }
            }

            let response_entries: Vec<BatchResponseEntry> = requests
                .into_iter()
                .map(|req| {
                    let asset_id_str = req.assetId.to_string();

                    if existing_assets.contains(&asset_id_str) {
                        BatchResponseEntry {
                            location: Some(format!("http://127.0.0.1/ddl/{}", req.assetId)),
                            requestId: req.requestId,
                            isArchived: false,
                            assetTypeId: crate::asset_types::asset_type_to_id(&req.assetType)
                                .unwrap_or(1) as i64,
                            isRecordable: true,
                            errors: None,
                            contentRepresentationSpecifier: None,
                            assetMetadatas: None,
                        }
                    } else {
                        BatchResponseEntry {
                            location: None,
                            requestId: req.requestId,
                            isArchived: false,
                            assetTypeId: 0,
                            isRecordable: false,
                            errors: Some(vec![BatchError {
                                code: 404,
                                message: "Request asset was not found".to_string(),
                                custom_error_code: 14,
                            }]),
                            contentRepresentationSpecifier: None,
                            assetMetadatas: None,
                        }
                    }
                })
                .collect();

            Json(response_entries).into_response()
        }
    } else {
        tracing::error!("cookie.txt not found or unreadable. Required for Asset Grab Mode.");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

async fn handle_asset_by_query(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AssetQuery>,
    req: Request,
) -> Response {
    serve_asset_logic(
        state,
        query.id,
        query.contentRepresentationPriorityList,
        req,
    )
    .await
}

async fn handle_asset_by_path(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    serve_asset_logic(state, id, None, req).await
}

async fn serve_asset_logic(
    state: Arc<AppState>,
    id: String,
    crpl: Option<String>,
    req: Request,
) -> Response {
    let mode = &state.mode;

    let filename = if let Some(crpl_val) = crpl {
        if let Ok(decoded) = decode(&crpl_val) {
            let hash = format!("{:x}", md5::compute(decoded.as_bytes()));
            format!("{}-{}", id, hash)
        } else {
            id.clone()
        }
    } else {
        id.clone()
    };

    if mode == "Reflection Mode" {
        return Redirect::temporary(&format!(
            "https://assetdelivery.roblox.com/v1/asset/?id={id}&permissionContext=ignoreUniverse&xcachesplit=0"
        )).into_response();
    }

    let file_path = PathBuf::from("static/assets").join(&filename);

    if mode == "Asset Grab Mode" {
        let url = if let Some(crpl_val) = req.uri().query().and_then(|q| {
            q.split('&')
                .find(|p| p.starts_with("contentRepresentationPriorityList="))
                .map(|p| p.to_string())
        }) {
            format!(
                "https://assetdelivery.roblox.com/v1/asset/?id={id}&{crpl_val}&permissionContext=ignoreUniverse&xcachesplit=0"
            )
        } else {
            format!(
                "https://assetdelivery.roblox.com/v1/asset/?id={id}&permissionContext=ignoreUniverse&xcachesplit=0"
            )
        };

        let cookie_path = PathBuf::from("cookie.txt");
        if let Ok(cookie_content) = tokio::fs::read_to_string(cookie_path).await {
            let cookie = cookie_content.trim();
            let client = reqwest::Client::builder()
                .gzip(true)
                .deflate(true)
                .build()
                .unwrap_or_default();
            if let Ok(res) = client
                .get(&url)
                .header("Cookie", format!(".ROBLOSECURITY={cookie}"))
                .header("User-Agent", "RobloxStudio/WinInet")
                .send()
                .await
            {
                match res.status().as_u16() {
                    200 => {
                        if let Some(parent) = file_path.parent() {
                            let _ = tokio::fs::create_dir_all(parent).await;
                        }
                        if let Ok(bytes) = res.bytes().await
                            && let Ok(mut file) = File::create(&file_path).await
                        {
                            let _ = file.write_all(&bytes).await;
                        }
                    }
                    403 => {
                        tracing::error!(
                            "Failed to download asset {}: 403 Forbidden. Your .ROBLOSECURITY cookie might be expired or you don't have permission to access the asset.",
                            id
                        );
                    }
                    429 => {
                        tracing::error!(
                            "Failed to download asset {}: 429 Too Many Requests. You are being rate limited.",
                            id
                        );
                    }
                    status => {
                        tracing::warn!("Failed to download asset {}: status {}", id, status);
                    }
                }
            }
        } else {
            tracing::error!("cookie.txt not found or unreadable. Required for Asset Grab Mode.");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    if file_path.exists() {
        let service = ServeFile::new(file_path);
        return match service.oneshot(req).await {
            Ok(res) => res.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    }

    if let Ok(mut entries) = tokio::fs::read_dir("static/assets").await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if let Some(stem) = path.file_stem()
                && stem.to_string_lossy() == id
            {
                let service = ServeFile::new(path);
                return match service.oneshot(req).await {
                    Ok(res) => res.into_response(),
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
            }
        }
    }

    StatusCode::NOT_FOUND.into_response()
}
