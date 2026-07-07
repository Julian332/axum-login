//! Stateless JWT support (feature `jwt`).
//!
//! This module provides the pieces needed to authenticate requests from a JSON
//! Web Token rather than a server-side session: a [`JwtConfig`] that knows how
//! to sign and verify tokens, and token extraction that reads a cookie first
//! and falls back to an `Authorization: Bearer` header.
//!
//! Unlike the session path, the user is reconstructed directly from the token's
//! claims via [`AuthUser::from_claims`], so no backend lookup is performed per
//! request. Token lifetime is bounded by the `exp` claim.

use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::{self, header, HeaderMap, HeaderValue, Request, Response};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tower_layer::Layer;
use tower_service::Service;

use crate::{AuthSession, AuthUser, AuthnBackend};

/// The default cookie name used to carry the JWT.
pub const DEFAULT_JWT_COOKIE_NAME: &str = "axum-login.jwt";

/// Claims embedded in an issued JWT.
///
/// `sub` carries the user's ID for quick reference, while `user` carries the
/// sanitized user view produced by [`AuthUser::to_claims`] and consumed by
/// [`AuthUser::from_claims`].
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims<Id> {
    sub: Id,
    iat: u64,
    exp: u64,
    user: serde_json::Value,
}

/// Configuration for signing and verifying stateless JWTs.
///
/// Construct with [`JwtConfig::from_secret`] for symmetric (HMAC) signing, or
/// build the fields directly for asymmetric algorithms.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Key used to sign issued tokens.
    pub encoding_key: EncodingKey,

    /// Key used to verify incoming tokens.
    pub decoding_key: DecodingKey,

    /// Signing algorithm; must be consistent with the keys.
    pub algorithm: jsonwebtoken::Algorithm,

    /// Validation rules applied when decoding (e.g. `exp` checking).
    pub validation: Validation,

    /// How long an issued token remains valid.
    pub ttl: Duration,

    /// Name of the cookie carrying the token.
    pub cookie_name: String,

    /// Whether the issued cookie carries the `Secure` attribute (only sent over
    /// HTTPS). Defaults to `true`; set to `false` for local development over
    /// plain HTTP.
    pub secure: bool,
}

impl JwtConfig {
    /// Creates a config for symmetric HMAC (HS256) signing from a shared secret.
    ///
    /// Tokens default to a one-day lifetime and the
    /// [`DEFAULT_JWT_COOKIE_NAME`] cookie; adjust the fields as needed.
    pub fn from_secret(secret: &[u8]) -> Self {
        let algorithm = jsonwebtoken::Algorithm::HS256;
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            algorithm,
            validation: Validation::new(algorithm),
            ttl: Duration::from_secs(60 * 60 * 24),
            cookie_name: DEFAULT_JWT_COOKIE_NAME.to_string(),
            secure: true,
        }
    }

    /// Sets the token lifetime.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the cookie name used to carry the token.
    pub fn with_cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
        self.cookie_name = cookie_name.into();
        self
    }

    /// Sets whether the issued cookie carries the `Secure` attribute.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Builds the `Set-Cookie` header value carrying an issued token.
    fn build_set_cookie(&self, token: &str) -> String {
        let mut cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            self.cookie_name,
            token,
            self.ttl.as_secs()
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }

    /// Builds the `Set-Cookie` header value that removes the token cookie.
    fn build_clear_cookie(&self) -> String {
        let mut cookie = format!(
            "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            self.cookie_name
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }

    /// Encodes and signs a token for the given user.
    ///
    /// The user is embedded via [`AuthUser::to_claims`], which must strip
    /// sensitive fields.
    pub fn encode<User>(&self, user: &User) -> Result<String, jsonwebtoken::errors::Error>
    where
        User: AuthUser + Serialize,
    {
        let now = now_unix();
        let claims = Claims {
            sub: user.id(),
            iat: now,
            exp: now.saturating_add(self.ttl.as_secs()),
            user: user.to_claims(),
        };
        jsonwebtoken::encode(&Header::new(self.algorithm), &claims, &self.encoding_key)
    }

    /// Verifies a token and reconstructs the user from its claims.
    ///
    /// Returns `None` when the token fails verification (bad signature, expired,
    /// wrong algorithm) or when the embedded claims cannot be turned back into a
    /// user via [`AuthUser::from_claims`].
    pub fn decode<User>(&self, token: &str) -> Option<User>
    where
        User: AuthUser + for<'de> Deserialize<'de>,
    {
        let data =
            jsonwebtoken::decode::<Claims<User::Id>>(token, &self.decoding_key, &self.validation)
                .ok()?;
        User::from_claims(&data.claims.user)
    }
}

/// Extracts a JWT from a request's headers.
///
/// Resolution order matches the intended usage: the cookie named `cookie_name`
/// takes precedence, and an `Authorization: Bearer <token>` header is used as a
/// fallback (e.g. for non-browser API clients).
pub(crate) fn extract_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    if let Some(token) = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name.trim() == cookie_name).then(|| value.trim().to_owned())
        })
    {
        return Some(token);
    }

    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token.trim().to_owned())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A cookie action deferred until the response is available.
///
/// [`AuthSession::login`](crate::AuthSession::login) and
/// [`logout`](crate::AuthSession::logout) record one of these; the
/// [`JwtManager`] applies it as a `Set-Cookie` header after the handler runs.
#[derive(Debug, Clone)]
pub(crate) enum PendingCookie {
    /// Issue a fresh token for the currently authenticated user.
    Issue,

    /// Remove the token cookie.
    Clear,
}

/// A middleware that authenticates requests from a JWT and provides an
/// [`AuthSession`] as a request extension.
///
/// The token is read from the configured cookie first, falling back to an
/// `Authorization: Bearer` header. The user is reconstructed from the token's
/// claims without a backend lookup. Any token issued or cleared during the
/// request (via [`AuthSession::login`]/[`logout`](AuthSession::logout)) is
/// written as a `Set-Cookie` header on the response.
#[derive(Debug, Clone)]
pub struct JwtManager<S, Backend: AuthnBackend> {
    inner: S,
    backend: Backend,
    config: Arc<JwtConfig>,
}

impl<ReqBody, ResBody, S, Backend> Service<Request<ReqBody>> for JwtManager<S, Backend>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send,
    Backend: AuthnBackend + 'static,
    Backend::User: Serialize + for<'de> Deserialize<'de>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let backend = self.backend.clone();
        let config = self.config.clone();

        // Only use the ready service; see the note in `service::AuthManager`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let user = extract_token(req.headers(), &config.cookie_name)
                .and_then(|token| config.decode::<Backend::User>(&token));

            if let Some(ref user) = user {
                tracing::Span::current().record("user.id", user.id().to_string());
            }

            let auth_session = AuthSession::from_jwt(backend, user);
            let handle = auth_session.clone();
            req.extensions_mut().insert(auth_session);

            let mut res = inner.call(req).await?;

            if let Some(pending) = handle.take_pending_cookie().await {
                let cookie = match pending {
                    PendingCookie::Issue => match handle.user().await {
                        Some(user) => match config.encode(&user) {
                            Ok(token) => Some(config.build_set_cookie(&token)),
                            Err(err) => {
                                tracing::error!(err = %err, "could not encode jwt");
                                None
                            }
                        },
                        None => None,
                    },
                    PendingCookie::Clear => Some(config.build_clear_cookie()),
                };

                if let Some(cookie) = cookie {
                    match HeaderValue::from_str(&cookie) {
                        Ok(value) => {
                            res.headers_mut().append(http::header::SET_COOKIE, value);
                        }
                        Err(err) => {
                            tracing::error!(err = %err, "could not build Set-Cookie header");
                        }
                    }
                }
            }

            Ok(res)
        })
    }
}

/// A layer for providing [`AuthSession`] backed by stateless JWTs.
///
/// ```rust,no_run
/// # use std::collections::HashMap;
/// # use axum_login::{AuthUser, AuthnBackend, JwtConfig, UserId};
/// # use serde::{Deserialize, Serialize};
/// # #[derive(Debug, Clone, Serialize, Deserialize)]
/// # struct User { id: i64 }
/// # impl AuthUser for User {
/// #     type Id = i64;
/// #     fn id(&self) -> i64 { self.id }
/// #     fn session_auth_hash(&self) -> &[u8] { &[] }
/// # }
/// # #[derive(Clone)]
/// # struct Backend;
/// # impl AuthnBackend for Backend {
/// #     type User = User;
/// #     type Credentials = ();
/// #     type Error = std::convert::Infallible;
/// #     async fn authenticate(&self, _: ()) -> Result<Option<User>, Self::Error> { Ok(None) }
/// #     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<User>, Self::Error> { Ok(None) }
/// # }
/// use axum_login::JwtManagerLayer;
///
/// let config = JwtConfig::from_secret(b"a-very-secret-key");
/// let jwt_layer = JwtManagerLayer::new(Backend, config);
/// ```
#[derive(Debug, Clone)]
pub struct JwtManagerLayer<Backend: AuthnBackend> {
    backend: Backend,
    config: Arc<JwtConfig>,
}

impl<Backend: AuthnBackend> JwtManagerLayer<Backend> {
    /// Creates a new [`JwtManagerLayer`] from a backend and JWT configuration.
    pub fn new(backend: Backend, config: JwtConfig) -> Self {
        Self {
            backend,
            config: Arc::new(config),
        }
    }
}

impl<S, Backend: AuthnBackend> Layer<S> for JwtManagerLayer<Backend> {
    type Service = JwtManager<S, Backend>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtManager {
            inner,
            backend: self.backend.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct User {
        id: i64,
        name: String,
        #[serde(skip)]
        pw_hash: Vec<u8>, // Sensitive: never lands in claims.
    }

    impl AuthUser for User {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &self.pw_hash
        }
    }

    fn config() -> JwtConfig {
        JwtConfig::from_secret(b"test-secret")
    }

    #[test]
    fn encode_decode_round_trip() {
        let cfg = config();
        let user = User {
            id: 42,
            name: "alice".to_string(),
            pw_hash: vec![1, 2, 3],
        };

        let token = cfg.encode(&user).unwrap();
        let decoded: User = cfg.decode(&token).unwrap();

        assert_eq!(decoded.id, 42);
        assert_eq!(decoded.name, "alice");
        // Sensitive field was skipped and comes back as default.
        assert!(decoded.pw_hash.is_empty());
    }

    #[test]
    fn decode_rejects_tampered_token() {
        let cfg = config();
        let user = User {
            id: 42,
            name: "alice".to_string(),
            pw_hash: vec![],
        };

        let mut token = cfg.encode(&user).unwrap();
        token.push('x'); // Corrupt the signature segment.

        assert!(cfg.decode::<User>(&token).is_none());
    }

    #[test]
    fn decode_rejects_wrong_secret() {
        let user = User {
            id: 42,
            name: "alice".to_string(),
            pw_hash: vec![],
        };
        let token = config().encode(&user).unwrap();

        let other = JwtConfig::from_secret(b"different-secret");
        assert!(other.decode::<User>(&token).is_none());
    }

    #[test]
    fn extract_prefers_cookie_over_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; axum-login.jwt=cookie-token; foo=bar"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );

        assert_eq!(
            extract_token(&headers, DEFAULT_JWT_COOKIE_NAME).as_deref(),
            Some("cookie-token")
        );
    }

    #[test]
    fn extract_falls_back_to_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-token"),
        );

        assert_eq!(
            extract_token(&headers, DEFAULT_JWT_COOKIE_NAME).as_deref(),
            Some("header-token")
        );
    }

    #[test]
    fn extract_returns_none_when_absent() {
        let headers = HeaderMap::new();
        assert!(extract_token(&headers, DEFAULT_JWT_COOKIE_NAME).is_none());
    }
}

#[cfg(test)]
mod middleware_tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{
        body::Body,
        http::{header, Request, Response, StatusCode},
        routing::get,
        Router,
    };
    use serde::{Deserialize, Serialize};
    use tower::ServiceExt;

    use super::*;
    use crate::{AuthSession, AuthnBackend, UserId};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct User {
        id: i64,
        name: String,
    }

    impl AuthUser for User {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Clone)]
    struct Backend {
        get_user_calls: Arc<AtomicUsize>,
    }

    impl AuthnBackend for Backend {
        type User = User;
        type Credentials = ();
        type Error = std::convert::Infallible;

        async fn authenticate(&self, _: ()) -> Result<Option<User>, Self::Error> {
            Ok(Some(User {
                id: 1,
                name: "alice".to_string(),
            }))
        }

        async fn get_user(&self, _: &UserId<Self>) -> Result<Option<User>, Self::Error> {
            // The JWT path must never call this; count invocations to prove it.
            self.get_user_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    fn app(backend: Backend) -> Router {
        let config = JwtConfig::from_secret(b"test-secret").with_secure(false);
        Router::new()
            .route(
                "/whoami",
                get(|auth: AuthSession<Backend>| async move {
                    auth.user().await.map(|u| u.name).unwrap_or("anon".into())
                }),
            )
            .route(
                "/login",
                get(|auth: AuthSession<Backend>| async move {
                    let user = auth.authenticate(()).await.unwrap().unwrap();
                    auth.login(&user).await.unwrap();
                    "ok"
                }),
            )
            .route(
                "/logout",
                get(|auth: AuthSession<Backend>| async move {
                    auth.logout().await.unwrap();
                    "bye"
                }),
            )
            .layer(JwtManagerLayer::new(backend, config))
    }

    fn set_cookie(res: &Response<Body>) -> Option<String> {
        res.headers()
            .get(header::SET_COOKIE)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
    }

    fn token_from_set_cookie(set_cookie: &str) -> String {
        set_cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, value)| value.to_string())
            .expect("cookie value")
    }

    async fn body_string(res: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn login_issues_cookie_and_authenticates_without_backend_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let backend = Backend {
            get_user_calls: calls.clone(),
        };
        let app = app(backend);

        // Anonymous request.
        let res = app
            .clone()
            .oneshot(Request::builder().uri("/whoami").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(body_string(res).await, "anon");

        // Log in: response carries the token cookie.
        let res = app
            .clone()
            .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let cookie = set_cookie(&res).expect("login should set a cookie");
        assert!(cookie.starts_with("axum-login.jwt="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(!cookie.contains("Secure")); // with_secure(false)
        let token = token_from_set_cookie(&cookie);

        // Authenticated request via cookie.
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, format!("axum-login.jwt={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(res).await, "alice");

        // The stateless path must not have touched the backend.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn bearer_header_is_accepted_as_fallback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = app(Backend {
            get_user_calls: calls.clone(),
        });

        let res = app
            .clone()
            .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let token = token_from_set_cookie(&set_cookie(&res).unwrap());

        // No cookie; only an Authorization header.
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body_string(res).await, "alice");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn logout_clears_the_cookie() {
        let app = app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });

        let res = app
            .oneshot(Request::builder().uri("/logout").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let cookie = set_cookie(&res).expect("logout should set an expiring cookie");
        assert!(cookie.starts_with("axum-login.jwt="));
        assert!(cookie.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn tampered_cookie_is_rejected() {
        let app = app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, "axum-login.jwt=not-a-valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_string(res).await, "anon");
    }
}
