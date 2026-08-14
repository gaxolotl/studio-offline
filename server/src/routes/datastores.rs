use crate::app_state::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

#[derive(Deserialize)]
struct PersistenceQuery {
    datastore: Option<String>,
    objectKey: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "maxItemsToReturn")]
    max_items_to_return: Option<String>,
    #[serde(rename = "exclusiveStartKey")]
    exclusive_start_key: Option<String>,
    #[serde(rename = "incrementBy")]
    increment_by: Option<String>,
    #[serde(rename = "lockId")]
    lock_id: Option<String>,
    ttl: Option<String>,
    version: Option<String>,
    sortOrder: Option<String>,
    scope: Option<String>,
    #[serde(rename = "excludeDeleted")]
    exclude_deleted: Option<String>,
}

async fn read_body(req: Request) -> (String, String, HashMap<String, String>, Vec<u8>) {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let headers = req.headers().clone();
    let mut map = HashMap::new();
    for (k, v) in headers.iter() {
        if let Ok(val) = v.to_str() {
            map.insert(k.to_string(), val.to_string());
        }
    }
    let mut body = Vec::new();
    if let Ok(mut stream) = req.into_body().into_data_stream() {
        let mut buf = [0u8; 8192];
        while let Ok(Some(n)) = stream.read(&mut buf).await {
            body.extend_from_slice(&buf[..n]);
        }
    }
    (method, uri, map, body)
}

fn datastore_dir(user_id: &str, datastore: &str, scope: &str) -> std::path::PathBuf {
    let safe_scope = if scope.is_empty() || scope == "global" {
        "global".to_string()
    } else {
        scope.to_string()
    };
    std::path::PathBuf::from("static/datastores")
        .join(user_id)
        .join(datastore)
        .join(safe_scope)
}

async fn log_request(method: &str, uri: &str, headers: &HashMap<String, String>, body: &[u8]) {
    let body_preview = String::from_utf8_lossy(body).to_string();
    tracing::info!(
        ">>> DATASTORE {} {} headers={:?} body_len={} body={}",
        method,
        uri,
        headers,
        body.len(),
        body_preview
    );
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/v2/persistence/{user_id}/datastores/objects/object",
            get(handle_object).post(handle_object).delete(handle_object),
        )
        .route(
            "/v2/persistence/{user_id}/datastores/objects/object/",
            get(handle_object).post(handle_object).delete(handle_object),
        )
        .route(
            "/v2/persistence/{user_id}/datastores/objects/{*rest}",
            get(handle_object_sub).post(handle_object_sub).delete(handle_object_sub),
        )
        .route(
            "/v2/persistence/{user_id}/datastores/objects/{*rest}/",
            get(handle_object_sub).post(handle_object_sub).delete(handle_object_sub),
        )
        .route(
            "/v2/persistence/{user_id}/datastores",
            get(handle_list_datastores),
        )
        .route(
            "/v2/persistence/{user_id}/datastores/",
            get(handle_list_datastores),
        )
}

async fn handle_object(
    State(_state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Query(query): Query<PersistenceQuery>,
    req: Request,
) -> Response {
    let (method, uri, headers, body) = read_body(req).await;
    log_request(&method, &uri, &headers, &body).await;

    let datastore = query.datastore.unwrap_or_default();
    let object_key = query.objectKey.unwrap_or_default();
    let scope = query.scope.unwrap_or_default();

    let dir = datastore_dir(&user_id, &datastore, &scope);
    let file = dir.join(format!("{}.dat", object_key));

    match method.as_str() {
        "GET" => {
            if file.exists() {
                match tokio::fs::read(&file).await {
                    Ok(data) => {
                        let mut res = Response::new(Body::from(data));
                        res.headers_mut()
                            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                        res
                    }
                    Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                }
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        "POST" | "PUT" => {
            if let Some(parent) = file.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            match tokio::fs::write(&file, &body).await {
                Ok(_) => {
                    tracing::info!("SAVED datastore={} scope={} key={} len={}", datastore, scope, object_key, body.len());
                    let mut res = Response::new(Body::empty());
                    res.headers_mut()
                        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
                    res
                }
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        "DELETE" => {
            let _ = tokio::fs::remove_file(&file).await;
            Response::new(Body::empty())
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn handle_object_sub(
    State(_state): State<Arc<AppState>>,
    Path((user_id, rest)): Path<(String, String)>,
    Query(query): Query<PersistenceQuery>,
    req: Request,
) -> Response {
    let (method, uri, headers, body) = read_body(req).await;
    log_request(&method, &uri, &headers, &body).await;

    let datastore = query.datastore.unwrap_or_default();
    let object_key = query.objectKey.unwrap_or_default();
    let scope = query.scope.unwrap_or_default();
    let dir = datastore_dir(&user_id, &datastore, &scope);
    let file = dir.join(format!("{}.dat", object_key));

    // increment
    if rest.contains("increment") {
        let increment_by: i64 = query
            .increment_by
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let current: i64 = if file.exists() {
            tokio::fs::read_to_string(&file)
                .await
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0)
        } else {
            0
        };
        let new_val = current + increment_by;
        if let Some(parent) = file.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let _ = tokio::fs::write(&file, new_val.to_string()).await;
        tracing::info!(
            "INCREMENT datastore={} key={} by={} now={}",
            datastore,
            object_key,
            increment_by,
            new_val
        );
        let mut res = Response::new(Body::from(new_val.to_string()));
        res.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        return res;
    }

    // lock / unlock / locks/refresh -> no-op success
    if rest.contains("lock") {
        let mut res = Response::new(Body::from("{}"));
        res.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        return res;
    }

    // versions -> list versions; minimal: return stored value as a version
    if rest.contains("versions") {
        let body = if file.exists() {
            tokio::fs::read(&file).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let json = format!(
            "{{\"key\":\"{}\",\"value\":\"{}\",\"version\":\"0\",\"isDeleted\":false}}",
            object_key,
            String::from_utf8_lossy(&body).replace('"', "\\\"")
        );
        let mut res = Response::new(Body::from(json));
        res.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        return res;
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn handle_list_datastores(
    State(_state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
    Query(query): Query<PersistenceQuery>,
    req: Request,
) -> Response {
    let (_method, _uri, headers, _body) = read_body(req).await;
    log_request("GET", &_uri, &headers, &[]).await;

    let prefix = query.prefix.unwrap_or_default();
    let base = std::path::PathBuf::from("static/datastores").join(&user_id);

    let mut names: Vec<String> = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&base).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(&prefix) {
                    names.push(name);
                }
            }
        }
    }
    names.sort();

    let json = format!(
        "{{\"data\":[{}]}}",
        names
            .iter()
            .map(|n| format!("\"{}\"", n))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut res = Response::new(Body::from(json));
    res.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    res
}