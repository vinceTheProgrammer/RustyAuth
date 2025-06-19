
use axum::{extract::State, response::{Html, IntoResponse, Redirect}, Form};
use serde::Deserialize;

use crate::{hash_password, AppState};

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    username: String,
    password: String,
}

// attempt to register a new user using a provided RegisterPayload
pub async fn register(State(state): State<AppState>, Form(payload): Form<RegisterPayload>) -> Result<impl IntoResponse, impl IntoResponse> {
    let pool = state.pool.clone();

    let connection = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string()), &state))),
    };

    // check for duplicate username
    let mut statement = match connection
        .prepare("SELECT COUNT(*) FROM users WHERE username = ?1") {
            Ok(stmt) => stmt,
            Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string()), &state))),
        };

    let exists: i64 = match statement
        .query_row([&payload.username], |row| row.get(0)) {
            Ok(count) => count,
            Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string()), &state))),
        };
    
    // return code 409 if desired username already exists in database
    if exists > 0 {
        return Err(Html(render_register_form(Some("Username already exists".to_string()), &state)))
    }

    // hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(Html(render_register_form(Some("Internal server error".to_string()), &state)))
        }
    };

    // insert user into database
    let result = connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        (&payload.username, &password_hash),
    );

    match result {
        Ok(_) => Ok(Redirect::to("/login?success=1")),
        Err(_) => Err(Html(render_register_form(Some("Internal server error".to_string()), &state))),
    }
}

pub async fn register_page(State(state): State<AppState>) -> Html<String> {
    Html(render_register_form(None, &state))
}


pub fn render_register_form(error: Option<String>, state: &AppState) -> String {
    let css = &state.css;

    let error_html = if let Some(msg) = error {
        format!(r#"<div class="error">{}</div>"#, msg)
    } else {
        "".to_string()
    };

    format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Register</title>
            {css}
        </head>
        <body>
            <form method="POST" action="/register">
                <h1>Register</h1>
                {error_html}
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <button type="submit">Register</button><br>
                <a href="/login">Login</a> if you already have an account.
            </form>
        </body>
        </html>
        "#,
        error_html = error_html,
        css = match css {
            Some(content) => format!(r#"<style>{}</style>"#, content),
            None => "".to_string(),
        }
    ).into()
}