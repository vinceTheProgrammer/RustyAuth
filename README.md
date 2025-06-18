# RustyAuth - rusty_auth

Dead simple (perhaps to a fault) username + password based authentication server written in Rust. Was originally planned to be more broadly useful while remaining as minimal as possible, but I've come to realize the reason one doesn't already exist is that implementing all the different integration strategies needed for it to be broadly useful is what makes it really really really hard to stay minimal.

This auth server does however support 1 specific auth strategy that I needed for my specific use case: setting the Remote-User header.

This was a learning experience for me as I have never done anything like this before, so the code is offered as is without warranty. USE AT YOUR OWN RISK.

## Configuration
You can configure RustyAuth by setting various environemnt variables. The available configuration options are as follows:

|Variable | Description | Default|
|---------|-------------|--------|
|RUSTYAUTH_PORT|The port that RustyAuth is binded to.|9480|
|RUSTYAUTH_DB_PATH|The path of the sqlite database (will be created if does not exist at the path)|./rusty_auth.db

## Behavior

### `/login`
##### GET
Dead simple unstyled html form that sends a POST request to `/login` on submit.

##### POST
Uses the provided username and password and attempts to login the user.

If successful, creates a new session, stores it in the database, responds with a session cookie of the session_id of the session.
Redirects to `/`.

### `/register`
##### GET
Dead simple unstyled html form that sends a POST request to `/register` on submit.

##### POST
If successful, creates a new user and stores it in the database.
Redirects to `/login`.

### `/auth/proxy`
### GET
Uses session cookie to set `Remote-User` header if session_id is valid. Usually a proxy is supposed to send a request to this route before calling other requests to get an up to date `Remote-User` header (or none if the session is invalid).
