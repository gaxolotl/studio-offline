use crate::app_state::AppState;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use futures_util::StreamExt;

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
    let mut stream = req.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(data) => body.extend_from_slice(&data),
            Err(_) => break,
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
    Router::new().route(
        "/v2/persistence/{user_id}/datastores/{*rest}",
        get(handle_datastore).post(handle_datastore).delete(handle_datastore),
    )
}

async fn handle_datastore(
    State(_state): State<Arc<AppState>>,
    Path((user_id, rest)): Path<(String, String)>,
    Query(query): Query<PersistenceQuery>,
    req: Request,
) -> Response {
    let (method, uri, headers, body) = read_body(req).await;
    log_request(&method, &uri, &headers, &body).await;

    let datastore = query.datastore.clone().unwrap_or_default();
    let object_key = query.objectKey.clone().unwrap_or_default();
    let scope = query.scope.clone().unwrap_or_default();
    let dir = datastore_dir(&user_id, &datastore, &scope);

    // listing keys: /objects
    if rest.trim_end_matches('/') == "objects" {
        return handle_list_keys(&user_id, &datastore, &scope, &query).await;
    }

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

    // versions -> minimal single version response
    if rest.contains("versions") {
        let value_body = if file.exists() {
            tokio::fs::read(&file).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let json = format!(
            "{{\"key\":\"{}\",\"value\":\"{}\",\"version\":\"0\",\"isDeleted\":false}}",
            object_key,
            String::from_utf8_lossy(&value_body).replace('"', "\\\"")
        );
        let mut res = Response::new(Body::from(json));
        res.headers_mut()
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        return res;
    }

    // objects/object -> get/set/delete single object
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

async fn handle_list_keys(
    user_id: &str,
    datastore: &str,
    scope: &str,
    query: &PersistenceQuery,
) -> Response {
    let dir = datastore_dir(user_id, datastore, scope);
    let mut keys: Vec<String> = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(stripped) = name.strip_suffix(".dat") {
                keys.push(stripped.to_string());
            }
        }
    }
    keys.sort();

    let prefix = query.prefix.clone().unwrap_or_default();
    if !prefix.is_empty() {
        keys.retain(|k| k.starts_with(&prefix));
    }

    let json = format!(
        "{{\"data\":[{}],\"nextPageCursor\":null}}",
        keys.iter()
            .map(|k| format!("\"{}\"", k))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut res = Response::new(Body::from(json));
    res.headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    res
}