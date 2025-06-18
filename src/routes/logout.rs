use axum::{extract::State, response::Redirect};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use time::Duration;

use crate::delete_session;

pub async fn logout(cookies: CookieJar, State(pool): State<Pool<SqliteConnectionManager>>) -> Redirect {
    let connection = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return Redirect::to("/"),
    };

    let session_cookie = match cookies.get("session") {
        Some(cookie) => cookie,
        None => return Redirect::to("/"),
    };

    let _ = delete_session(&connection, session_cookie.value());

    // Expire the cookie
    let _ = cookies.remove(Cookie::build(("session", "")).path("/").max_age(Duration::ZERO));

    Redirect::to("/login")
}