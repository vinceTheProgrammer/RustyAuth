use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse};
use axum_extra::extract::cookie::CookieJar;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::get_session_username;

pub async fn auth_proxy(
    jar: CookieJar,
    State(pool): State<Pool<SqliteConnectionManager>>,
) -> impl IntoResponse {
    if let Some(cookie) = jar.get("session") {
        let connection = match pool.get() {
            Ok(conn) => conn,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
        };

        if let Some(username) = get_session_username(&connection, cookie.value()) {
            let mut headers = HeaderMap::new();
            let parsed_username = match username.parse() {
                Ok(p_username) => p_username,
                Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR).into_response(),
            };
            headers.insert("Remote-User", parsed_username);
            return (headers, StatusCode::OK).into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
}
