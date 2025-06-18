
use axum::{extract::State, response::{Html, IntoResponse, Redirect}, Form};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Deserialize;

use crate::hash_password;

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    username: String,
    password: String,
}

// attempt to register a new user using a provided RegisterPayload
pub async fn register(State(pool): State<Pool<SqliteConnectionManager>>, Form(payload): Form<RegisterPayload>) -> Result<impl IntoResponse, impl IntoResponse> {
    let connection = match pool.get() {
        Ok(conn) => conn,
        Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string())))),
    };

    // check for duplicate username
    let mut statement = match connection
        .prepare("SELECT COUNT(*) FROM users WHERE username = ?1") {
            Ok(stmt) => stmt,
            Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string())))),
        };

    let exists: i64 = match statement
        .query_row([&payload.username], |row| row.get(0)) {
            Ok(count) => count,
            Err(_) => return Err(Html(render_register_form(Some("Internal server error".to_string())))),
        };
    
    // return code 409 if desired username already exists in database
    if exists > 0 {
        return Err(Html(render_register_form(Some("Username already exists".to_string()))))
    }

    // hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => {
            return Err(Html(render_register_form(Some("Internal server error".to_string()))))
        }
    };

    // insert user into database
    let result = connection.execute(
        "INSERT INTO users (username, password_hash) VALUES (?1, ?2)",
        (&payload.username, &password_hash),
    );

    match result {
        Ok(_) => Ok(Redirect::to("/login?success=1")),
        Err(_) => Err(Html(render_register_form(Some("Internal server error".to_string())))),
    }
}

pub async fn register_page() -> Html<String> {
    Html(render_register_form(None))
}


pub fn render_register_form(error: Option<String>) -> String {
    let error_html = if let Some(msg) = error {
        format!(r#"<p style="color:red;">{}</p>"#, msg)
    } else {
        "".to_string()
    };

    format!(
        r#"
        <html>
            <body>
                <h1>Register</h1>
                {error_html}
                <form method="POST" action="/register">
                    <input name="username" placeholder="Username"><br>
                    <input type="password" name="password" placeholder="Password"><br>
                    <button type="submit">Register</button><br>
                    <a href="/login">Login</a> if you already have an account.
                </form>
            </body>
        </html>
        "#,
        error_html = error_html
    ).into()
}