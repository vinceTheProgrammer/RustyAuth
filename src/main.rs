mod routes;

use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use chrono::Utc;
use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use uuid::Uuid;
use std::{env, net::SocketAddr};
use axum::{routing::{get}, Router};

use crate::routes::{auth::auth_proxy, login::{handle_login, login_page}, logout::logout, register::{register, register_page}};

#[tokio::main]
async fn main() {
    // define path of database as user defined path or default to creating the database in the current directory
    let database_path = env::var("RUSTYAUTH_DB_PATH")
        .unwrap_or_else(|_| "./rusty_auth.db".to_string());

    // create the r2d2_sqlite connection manager for managing connections of a connection pool
    let manager = SqliteConnectionManager::file(database_path);

    // get a connection pool to get connections from when handling requests
    // TODO - check if I'm wrong in assuming that the expect message should be the same as a Connection::open expect message (i.e. it attempts to Connection::open at the time of pool creation?)
    let pool = r2d2::Pool::new(manager).expect("Failed to open database. Is RUSTYAUTH_DB_PATH a valid path that points to the .db file? Did something cause the SQLite open call to fail?");

    // define database connection by opening database path defined above
    let connection = pool.get().expect("Failed to get initial database connection for creating the users table if it does not exist");

    // create users table if it does not already exist
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        "
    ).expect("Failed to create users table");

    // define port as user defined port or default to port 9480
    let port = env::var("RUSTYAUTH_PORT")
        .unwrap_or_else(|_| "9480".to_string())
        .parse::<u16>()
        .expect("RUSTYAUTH_PORT must be a valid u16 port number");

    // define the axum Router and set each route
    let app = Router::new()
        .route("/", get(root))
        .route("/register", get(register_page).post(register)).with_state(pool.clone())
        .route("/login", get(login_page).post(handle_login)).with_state(pool.clone())
        .route("/logout", get(logout).with_state(pool.clone()))
        .route("/auth/proxy", get(auth_proxy).with_state(pool.clone()));

    // define address to bind to localhost with the port that was defined above
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    // have axum listen and serve at the address defined above
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// return simple message when getting the root route
async fn root() -> &'static str {
    "RustyAuth is alive!"
}

// take a password and return a hashed version of the password
fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?
        .to_string();

    Ok(password_hash)
}

// take a password and a hashed password and return Ok if the hashed password was created using the password
fn verify_password(password: &str, password_hash: &str) -> Result<bool, String> {
    let parsed_hash = PasswordHash::new(&password_hash)
        .map_err(|e| format!("Failed to create PasswordHash from password hash string: {}", e))?;

        let argon2 = Argon2::default();
        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false), // incorrect password
            Err(e) => Err(format!("Password verification error: {}", e)),
        }
}

fn create_session(connection: &PooledConnection<SqliteConnectionManager>, username: &str) -> Result<String, String> {
    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();

    match connection.execute(
        "INSERT INTO sessions (id, username, created_at) VALUES (?1, ?2, ?3)",
        params![session_id, username, now],
    ) {
        Ok(_) => Ok(session_id),
        Err(_) => Err("Failed to insert session".to_owned()),
    }
}

fn delete_session(connection: &PooledConnection<SqliteConnectionManager>, session_id: &str) -> Result<(), String> {
    match connection.execute(
        "DELETE FROM sessions WHERE id = ?1",
        params![session_id],
    ) {
        Ok(affected_rows) if affected_rows > 0 => Ok(()),
        Ok(_) => Err("No session found to delete".to_owned()),
        Err(_) => Err("Failed to delete session".to_owned()),
    }
}

fn get_session_username(
    connection: &PooledConnection<SqliteConnectionManager>,
    session_id: &str,
) -> Option<String> {
    connection.query_row(
        "SELECT username FROM sessions WHERE id = ?1",
        params![session_id],
        |row| row.get(0),
    ).ok()
}


