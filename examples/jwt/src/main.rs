//! Stateless JWT authentication example.
//!
//! Run with:
//!
//! ```not_rust
//! cargo run -p example-jwt
//! ```
//!
//! Then, in another terminal:
//!
//! ```not_rust
//! # Log in; the token is returned both as a Set-Cookie and in the body so API
//! # clients can grab it. `-c`/`-b` persist cookies to a jar file.
//! curl -i -c jar.txt -X POST 'http://localhost:3000/login?username=ferris&password=hunter2'
//!
//! # Browser-style: send the cookie back.
//! curl -b jar.txt http://localhost:3000/
//!
//! # API-style: pull the token out of the Set-Cookie header and send it as a
//! # Bearer header (no cookie).
//! TOKEN=$(curl -si -X POST 'http://localhost:3000/login?username=ferris&password=hunter2' \
//!   | grep -i '^set-cookie:' | sed -E 's/.*axum-login\.jwt=([^;]+).*/\1/')
//! curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/
//!
//! # Log out clears the cookie.
//! curl -i -b jar.txt http://localhost:3000/logout
//! ```

use std::collections::HashMap;

use axum::{extract::Query, http::StatusCode, response::{IntoResponse, Response}, routing::{get, post}, Json, Router};
use axum_login::{AuthUser, AuthnBackend, JwtConfig, JwtManagerLayer, UserId};
use serde::{Deserialize, Serialize};

type AuthSession = axum_login::AuthSession<Backend>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: i64,
    username: String,

    // Never serialized into the token: excluded from the claims.
    #[serde(skip)]
    password: String,
}

impl AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    fn session_auth_hash(&self) -> &[u8] {
        // Not used by the JWT path; token lifetime is bounded by `exp`.
        self.password.as_bytes()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Credentials {
    username: String,
    password: String,
}

#[derive(Clone, Default)]
struct Backend {
    users: HashMap<String, User>,
}

impl Backend {
    fn seeded() -> Self {
        let mut users = HashMap::new();
        users.insert(
            "ferris".to_string(),
            User {
                id: 1,
                username: "ferris".to_string(),
                password: "hunter2".to_string(),
            },
        );
        Self { users }
    }
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = std::convert::Infallible;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(self
            .users
            .get(&creds.username)
            .filter(|user| user.password == creds.password)
            .cloned())
    }

    async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // The stateless JWT path never calls this.
        Ok(None)
    }
}

async fn protected(auth_session: AuthSession) -> Response {
    match auth_session.user().await {
        Some(user) => format!("Logged in as {} (id {}).\n", user.username, user.id).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            "Not logged in. POST /login?username=..&password=..\n",
        )
            .into_response(),
    }
}

async fn login(auth_session: AuthSession, Json(creds): Json<Credentials>) -> Response {
    match auth_session.authenticate(creds).await {
        Ok(Some(user)) => {
            if auth_session.login(&user).await.is_err() {
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            // The middleware signs the token and sets it as a cookie on the way
            // out; API clients can read it from the Set-Cookie header.
            "logged-in\n".into_response()
        }
        Ok(None) => (StatusCode::UNAUTHORIZED, "bad credentials\n").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout(auth_session: AuthSession) -> impl IntoResponse {
    let _ = auth_session.logout().await;
    "logged-out\n"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Use a strong, secret key in production and keep it out of source control.
    let config = JwtConfig::from_secret(b"a-very-secret-key")
        // Allow the cookie over plain HTTP for this local example.
        .with_secure(false);

    let app = Router::new()
        .route("/", get(protected))
        .route("/", post(protected))
        .route("/login", post(login))
        .route("/logout", get(logout))
        .layer(JwtManagerLayer::new(Backend::seeded(), config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    println!("listening on http://localhost:3000");
    axum::serve(listener, app.into_make_service()).await.unwrap();
}
