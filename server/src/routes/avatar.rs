use axum::{
    Json, Router,
    extract::{Multipart, Path},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::fs;

use crate::app_state::AppState;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AvatarPart {
    pub id: String,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
struct AvatarConfig {
    parts: Vec<AvatarPart>,
}

#[derive(Serialize)]
struct PartStatus {
    #[serde(flatten)]
    part: AvatarPart,
    size: Option<u64>,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/avatar", get(avatar_ui))
        .route("/avatar/", get(avatar_ui))
        .route("/avatar/api/parts", get(list_parts))
        .route("/avatar/api/upload/{id}", post(upload_part))
        .route("/avatar/api/reset/{id}", post(reset_part))
        .route("/avatar/file/{id}", get(get_avatar_file))
}

async fn avatar_ui() -> impl IntoResponse {
    match fs::read("static/avatar/index.html").await {
        Ok(content) => Html(String::from_utf8_lossy(&content).to_string()).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            "Avatar UI not found. Reinstall Studio-Offline.",
        )
            .into_response(),
    }
}

async fn load_config() -> AvatarConfig {
    match fs::read_to_string("static/avatar/avatar.json").await {
        Ok(content) => serde_json::from_str(&content).unwrap_or(AvatarConfig { parts: vec![] }),
        Err(_) => AvatarConfig { parts: vec![] },
    }
}

async fn list_parts() -> Json<Vec<PartStatus>> {
    let config = load_config().await;
    let mut out = Vec::new();
    for part in config.parts {
        let size = fs::metadata(format!("static/avatar/{}", part.id))
            .await
            .ok()
            .map(|m| m.len());
        out.push(PartStatus { part, size });
    }
    Json(out)
}

async fn upload_part(Path(id): Path<String>, mut multipart: Multipart) -> Response {
    let mut content: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            if let Ok(bytes) = field.bytes().await {
                content = Some(bytes.to_vec());
            }
        }
    }

    let Some(content) = content else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    let file_path = format!("static/avatar/{}", id);
    if let Err(e) = fs::write(&file_path, &content).await {
        eprintln!("Failed to write avatar part {}: {}", id, e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn reset_part(Path(id): Path<String>) -> Response {
    let file_path = format!("static/avatar/{}", id);
    if fs::try_exists(&file_path).await.unwrap_or(false) {
        let _ = fs::remove_file(&file_path).await;
    }
    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

async fn get_avatar_file(Path(id): Path<String>) -> Response {
    let file_path = format!("static/avatar/{}", id);
    match fs::read(&file_path).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
