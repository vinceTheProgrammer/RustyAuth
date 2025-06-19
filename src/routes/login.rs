use std::collections::HashMap;

use axum_extra::extract::{cookie::Cookie, CookieJar};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use axum::{extract::{Query, State}, response::{Html, IntoResponse, Redirect}, Form};
use serde::Deserialize;

use crate::{create_session, verify_password, AppState};

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    username: String,
    password: String,
}

// attempt to login a user using a provided LoginPayload
pub async fn handle_login(jar: CookieJar, State(state): State<AppState>, Form(payload): Form<LoginPayload>) -> Result<impl IntoResponse, impl IntoResponse> {
    let pool = state.pool.clone();

    let connection = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None, &state))),
    };

    // fetch password hash from DB
    let mut statement = match connection
        .prepare("SELECT password_hash FROM users WHERE username = ?1") {
            Ok(stmt) => stmt,
            Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None, &state))),
        };


    let stored_hash: String = match statement
        .query_row([&payload.username], |row| row.get(0)) {
            Ok(hash) => hash,
            Err(_) => return Err(Html(render_login_form(Some("Invalid username or password".to_string()), None, &state))),
        };

    match verify_password(&payload.password, &stored_hash) {
        Ok(true) => {
            let session_id = match create_session(&connection, &payload.username) {
                Ok(id) => id,
                Err(_) => return Err(Html(render_login_form(Some("Internal server error".to_string()), None, &state))),
            };

            let cookie = Cookie::build(("session", session_id))
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax);

            Ok((jar.add(cookie), Redirect::to("/")).into_response())
        },
        Ok(false) => Err(Html(render_login_form(Some("Invalid username or password".to_string()), None, &state))),
        Err(_) => Err(Html(render_login_form(Some("Internal server error".to_string()), None, &state))),
    }
}

pub async fn login_page(Query(params): Query<HashMap<String, String>>, State(state): State<AppState>) -> Html<String> {
    let success_msg = match params.get("success").map(|_| {
        r#"<div class="success">Account registered successfully. You may now log in.</div>"#
    }) {
        Some(str) => Some(format!("{}", str)),
        None => None,
    };

    Html(render_login_form(None, success_msg, &state))
}


pub fn render_login_form(error: Option<String>, success: Option<String>, state: &AppState) -> String {
    let logo_html = match &state.logo_data_url {
        Some(data_url) => format!(r#"<img src="{}" alt="Logo" class="logo"/>"#, data_url),
        None => "".to_string(),
    };

    let css_block = match &state.css {
        Some(content) => format!(r#"<style>{}</style>"#, content),
        None => "".to_string(),
    };

    let site_name = match &state.site_name {
        Some(content) => content,
        None => &"".to_string(),
    };
    
    let error_html = if let Some(msg) = error {
        format!(r#"<div class="error">{}</div>"#, msg)
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
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Login</title>
            {css_block}
        </head>
        <body>
            <div class="auth-container">
                {logo}
                <h1>{site_name}</h1>
                <form method="POST" action="/login">
                    <h1>Login</h1>
                    {success_html}
                    {error_html}
                    <input type="text" name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <button type="submit">Login</button><br>
                    <a href="/register">Register</a> if you don't have an account.
                </form>
            </div>
        </body>
        </html>
        "#,
        error_html = error_html,
        success_html = success_html,
        css_block = css_block,
        logo = logo_html,
        site_name = site_name
    ).into()
}