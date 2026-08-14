use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::json;
use tower_http::services::ServeFile;
use crate::app_state::AppState;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v2/logout", post(logout))
        .route_service(
            "/v1/users/authenticated",
            ServeFile::new("static/user/Users/authenticated.json"),
        )
        .route(
            "/studio-user-settings/v1/user/studiodata/InstalledPluginsAsJson_V001",
            get(installed_plugins),
        )
        .route(
            "/studio-user-settings/plugin-permissions/v2/plugins",
            get(plugin_permissions),
        )
        .route_service(
            "/headshot",
            ServeFile::new("static/images/headshots/default.png"),
        )
        .route_service(
            "/renders/places/default.png",
            ServeFile::new("static/images/places/default.png"),
        )
        .route_service(
            "/my/settings/json",
            ServeFile::new("static/user/Users/mysettings.json"),
        )
        .route_service(
            "/studio-user-settings/v1/user/studiodata/BetaFeatureInformation",
            ServeFile::new("static/config/StudioUserSettings/BetaFeatureInformation.json"),
        )
        .route_service(
            "/studio-open-place/v1/openplace",
            ServeFile::new("static/config/PlaceOpen/openplace.json"),
        )
        .route(
            "/asset-permissions-api/v1/assets/check-permissions",
            post(check_permissions),
        )
        .route_service(
            "/v1/gametemplates",
            ServeFile::new("static/config/GameTemplates/content.json"),
        )
        .route_service(
            "/v1/games/icons",
            ServeFile::new("static/images/thumbnails/games.json"),
        )
        .route("/v2/users/{id}/groups/roles", get(user_groups_roles))
        .route(
            "/player-policy-service/v1/player-policy-client",
            get(player_policy),
        )
        .route("/v1/not-approved", get(not_approved))
        .route_service(
            "/v2/assets/{id}/details",
            ServeFile::new("static/user/Economy/details.json"),
        )
        .route_service("/userhub", ServeFile::new("static/userhub/index.html"))
        .route_service("/userhub/", ServeFile::new("static/userhub/index.html"))
        .route("/v1/user/experiences", get(user_experiences))
}

async fn user_experiences() -> impl IntoResponse {
    Json(json!({
        "data": [
            {
                "name": "Baseplate",
                "placeId": 1818,
                "universeId": 1,
                "thumbnailUrl": "http://localhost/renders/places/default.png"
            }
        ]
    }))
}

async fn logout() -> impl IntoResponse {
    Json(json!({}))
}
async fn installed_plugins() -> impl IntoResponse {
    Json(json!({}))
}

async fn plugin_permissions() -> impl IntoResponse {
    Json(json!({"data": []}))
}

async fn check_permissions() -> impl IntoResponse {
    Json(json!({ "results": [{ "value": { "status": "NoPermission" } }] }))
}

async fn user_groups_roles() -> impl IntoResponse {
    Json(json!({ "data": [] }))
}

async fn player_policy() -> impl IntoResponse {
    Json(json!({
        "isSubjectToChinaPolicies": false,
        "arePaidRandomItemsRestricted": false,
        "isPaidItemTradingAllowed": true,
        "areAdsAllowed": true,
        "allowedExternalLinkReferences": ["Discord", "YouTube", "Twitch", "Facebook", "X", "Guilded"],
        "isEligibleToPurchaseSubscription": true,
        "isEligibleToPurchaseCommerceProduct": true,
        "isContentSharingAllowed": true,
        "isPhotoToAvatarAllowed": false
    }))
}

async fn not_approved() -> impl IntoResponse {
    Json(json!({}))
}
