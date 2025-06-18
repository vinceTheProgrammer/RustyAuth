use std::collections::HashMap;

use axum_extra::extract::{cookie::Cookie, CookieJar};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use axum::{extract::{Query, State}, response::{Html, IntoResponse, Redirect}, Form};
use serde::Deserialize;

use crate::{create_session, verify_password};

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    username: String,
    password: String,
}

// attempt to login a user using a provided LoginPayload
pub async fn handle_login(jar: CookieJar, State(pool): State<Pool<SqliteConnectionManager>>, Form(payload): Form<LoginPayload>) -> Result<impl IntoResponse, impl IntoResponse> {
    let connection = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None))),
    };

    // fetch password hash from DB
    let mut statement = match connection
        .prepare("SELECT password_hash FROM users WHERE username = ?1") {
            Ok(stmt) => stmt,
            Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None))),
        };


    let stored_hash: String = match statement
        .query_row([&payload.username], |row| row.get(0)) {
            Ok(hash) => hash,
            Err(_) => return Err(Html(render_login_form(Some("Invalid username or password".to_string()), None))),
        };

    match verify_password(&payload.password, &stored_hash) {
        Ok(true) => {
            let session_id = match create_session(&connection, &payload.username) {
                Ok(id) => id,
                Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None))),
            };

            let cookie = Cookie::build(("session", session_id))
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax);

            Ok((jar.add(cookie), Redirect::to("/")).into_response())
        },
        Ok(false) => Err(Html(render_login_form(Some("Invalid username or password".to_string()), None))),
        Err(_) => Err(Html(render_login_form(Some("Internal server error".to_string()), None))),
    }
}

pub async fn login_page(Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let success_msg = match params.get("success").map(|_| {
        "<p style=\"color: green;\">Account registered successfully. You may now log in.</p>"
    }) {
        Some(str) => Some(format!("{}", str)),
        None => None,
    };

    Html(render_login_form(None, success_msg))
}


pub fn render_login_form(error: Option<String>, success: Option<String>) -> String {
    let error_html = if let Some(msg) = error {
        format!(r#"<p style="color:red;">{}</p>"#, msg)
    } else {
        "".to_string()
    };

    let success_html = if let Some(msg) = success {
        msg
    } else {
        "".to_string()
    };

    format!(
        r#"
        <html>
            <body>
                <h1>Login</h1>
                {success_html}
                {error_html}
                <form method="POST" action="/login">
                    <input name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <button type="submit">Login</button><br>
                    <a href="/register">Register</a> if you don't have an account.
                </form>
            </body>
        </html>
        "#,
        error_html = error_html,
        success_html = success_html
    ).into()
}