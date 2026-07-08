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

/// The default cookie name used to carry the access JWT.
pub const DEFAULT_JWT_COOKIE_NAME: &str = "auth.access";

/// The default cookie name used to carry the refresh JWT.
pub const DEFAULT_REFRESH_COOKIE_NAME: &str = "auth.refresh";

/// Distinguishes an access token (authenticates requests) from a refresh token
/// (only ever exchanged for a new access token). The `typ` claim prevents one
/// from being used in place of the other.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TokenKind {
    Access,
    Refresh,
}

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
    typ: TokenKind,
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

    /// How long an issued access token remains valid.
    pub ttl: Duration,

    /// Name of the cookie carrying the access token.
    pub cookie_name: String,

    /// `Path` attribute of the access token cookie. Defaults to `/`.
    pub path: String,

    /// Whether the issued cookie carries the `Secure` attribute (only sent over
    /// HTTPS). Defaults to `true`; set to `false` for local development over
    /// plain HTTP.
    pub secure: bool,

    /// Whether to transparently re-issue the token cookie when an incoming
    /// token has reached the last third of its lifetime. Defaults to `true`.
    ///
    /// This keeps active sessions alive without a re-login while letting idle
    /// tokens expire. The threshold is computed from the token's own `iat`/`exp`
    /// claims, not [`ttl`](Self::ttl).
    pub sliding_refresh: bool,

    /// Whether the refresh-token mechanism is enabled. Defaults to `false`.
    ///
    /// When enabled, [`login`](crate::AuthSession::login) additionally issues a
    /// long-lived refresh token in its own cookie ([`refresh_cookie_name`], on
    /// [`refresh_path`]). A request that carries a valid refresh token but no
    /// valid access token is authenticated from the refresh token and gets a
    /// fresh access cookie. Scope the refresh cookie with [`refresh_path`] so
    /// browsers only send it to your refresh endpoint.
    ///
    /// [`refresh_cookie_name`]: Self::refresh_cookie_name
    /// [`refresh_path`]: Self::refresh_path
    pub refresh_enabled: bool,

    /// How long an issued refresh token remains valid. Defaults to 7 days.
    pub refresh_ttl: Duration,

    /// Name of the cookie carrying the refresh token.
    pub refresh_cookie_name: String,

    /// `Path` attribute of the refresh token cookie. Defaults to `/`; set this
    /// to your refresh endpoint (e.g. `/auth/refresh`) so the refresh cookie is
    /// only sent there.
    pub refresh_path: String,
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
            path: "/".to_string(),
            secure: true,
            sliding_refresh: true,
            refresh_enabled: false,
            refresh_ttl: Duration::from_secs(60 * 60 * 24 * 7),
            refresh_cookie_name: DEFAULT_REFRESH_COOKIE_NAME.to_string(),
            refresh_path: "/auth/refresh".to_string(),
        }
    }

    /// Sets the token lifetime.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the cookie name used to carry the access token.
    pub fn with_cookie_name(mut self, cookie_name: impl Into<String>) -> Self {
        self.cookie_name = cookie_name.into();
        self
    }

    /// Sets the `Path` attribute of the access token cookie.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Sets whether the issued cookie carries the `Secure` attribute.
    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Sets whether the token cookie is transparently re-issued once an incoming
    /// token enters the last third of its lifetime.
    pub fn with_sliding_refresh(mut self, sliding_refresh: bool) -> Self {
        self.sliding_refresh = sliding_refresh;
        self
    }

    /// Enables (or disables) the refresh-token mechanism.
    pub fn with_refresh_enabled(mut self, enabled: bool) -> Self {
        self.refresh_enabled = enabled;
        self
    }

    /// Sets the refresh token lifetime.
    pub fn with_refresh_ttl(mut self, refresh_ttl: Duration) -> Self {
        self.refresh_ttl = refresh_ttl;
        self
    }

    /// Sets the cookie name used to carry the refresh token.
    pub fn with_refresh_cookie_name(mut self, name: impl Into<String>) -> Self {
        self.refresh_cookie_name = name.into();
        self
    }

    /// Sets the `Path` attribute of the refresh token cookie (e.g.
    /// `/auth/refresh`) so browsers only send it to your refresh endpoint.
    pub fn with_refresh_path(mut self, path: impl Into<String>) -> Self {
        self.refresh_path = path.into();
        self
    }

    /// Returns `true` when sliding refresh is enabled and a token with the given
    /// `iat`/`exp` claims has ≤ 1/3 of its lifetime remaining.
    fn should_refresh(&self, iat: u64, exp: u64) -> bool {
        if !self.sliding_refresh || exp <= iat {
            return false;
        }
        let now = now_unix();
        if now >= exp {
            return false; // Already expired; `decode` would have rejected it.
        }
        let lifetime = exp - iat;
        let remaining = exp - now;
        // remaining <= lifetime / 3, done in integers to avoid rounding.
        remaining.saturating_mul(3) <= lifetime
    }

    /// Builds a `Set-Cookie` header value.
    fn build_cookie(&self, name: &str, path: &str, value: &str, max_age: u64) -> String {
        let mut cookie =
            format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax; Max-Age={max_age}");
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie
    }

    /// `Set-Cookie` carrying a freshly issued access token.
    fn access_set_cookie(&self, token: &str) -> String {
        self.build_cookie(&self.cookie_name, &self.path, token, self.ttl.as_secs())
    }

    /// `Set-Cookie` that removes the access token cookie.
    fn access_clear_cookie(&self) -> String {
        self.build_cookie(&self.cookie_name, &self.path, "", 0)
    }

    /// `Set-Cookie` carrying a freshly issued refresh token.
    fn refresh_set_cookie(&self, token: &str) -> String {
        self.build_cookie(
            &self.refresh_cookie_name,
            &self.refresh_path,
            token,
            self.refresh_ttl.as_secs(),
        )
    }

    /// `Set-Cookie` that removes the refresh token cookie.
    fn refresh_clear_cookie(&self) -> String {
        self.build_cookie(&self.refresh_cookie_name, &self.refresh_path, "", 0)
    }

    /// Encodes and signs a token for the given user.
    ///
    /// The user is embedded via [`AuthUser::to_claims`], which must strip
    /// sensitive fields.
    pub fn encode<User>(&self, user: &User) -> Result<String, jsonwebtoken::errors::Error>
    where
        User: AuthUser + Serialize,
    {
        self.encode_kind(user, TokenKind::Access, self.ttl)
    }

    /// Signs a refresh token for the given user.
    fn encode_refresh<User>(&self, user: &User) -> Result<String, jsonwebtoken::errors::Error>
    where
        User: AuthUser + Serialize,
    {
        self.encode_kind(user, TokenKind::Refresh, self.refresh_ttl)
    }

    fn encode_kind<User>(
        &self,
        user: &User,
        typ: TokenKind,
        ttl: Duration,
    ) -> Result<String, jsonwebtoken::errors::Error>
    where
        User: AuthUser + Serialize,
    {
        let now = now_unix();
        let claims = Claims {
            sub: user.id(),
            iat: now,
            exp: now.saturating_add(ttl.as_secs()),
            typ,
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
        self.decode_kind(token, TokenKind::Access)
            .map(|(user, _, _)| user)
    }

    /// Decodes a token, verifying it is of the expected [`TokenKind`], and
    /// returns the reconstructed user plus its `iat` and `exp` claims (for
    /// sliding-refresh decisions).
    fn decode_kind<User>(&self, token: &str, expected: TokenKind) -> Option<(User, u64, u64)>
    where
        User: AuthUser + for<'de> Deserialize<'de>,
    {
        let data =
            match jsonwebtoken::decode::<Claims<User::Id>>(token, &self.decoding_key, &self.validation) {
                Ok(data) => data,
                Err(err) => {
                    // Routine for expired/tampered/foreign tokens; log at debug
                    // so it's diagnosable without being noisy.
                    tracing::debug!(err = %err, "jwt verification failed");
                    return None;
                }
            };
        if data.claims.typ != expected {
            tracing::debug!(?expected, got = ?data.claims.typ, "jwt has unexpected token kind");
            return None;
        }
        let user = User::from_claims(&data.claims.user)?;
        Some((user, data.claims.iat, data.claims.exp))
    }
}

/// Extracts a JWT from a request's headers.
///
/// Resolution order matches the intended usage: the cookie named `cookie_name`
/// takes precedence, and an `Authorization: Bearer <token>` header is used as a
/// fallback (e.g. for non-browser API clients).
pub(crate) fn extract_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    extract_cookie(headers, cookie_name).or_else(|| {
        headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|token| token.trim().to_owned())
    })
}

/// Reads a named cookie's value from the request headers.
fn extract_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name.trim() == cookie_name).then(|| value.trim().to_owned())
        })
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Signs a fresh access token for the session's current user and returns its
/// `Set-Cookie` value, or `None` if there is no user or signing fails.
async fn issue_access_cookie<Backend>(
    session: &AuthSession<Backend>,
    config: &JwtConfig,
) -> Option<String>
where
    Backend: AuthnBackend,
    Backend::User: Serialize,
{
    let user = session.user().await?;
    match config.encode(&user) {
        Ok(token) => Some(config.access_set_cookie(&token)),
        Err(err) => {
            tracing::error!(err = %err, "could not encode access jwt");
            None
        }
    }
}

/// Signs a fresh refresh token for the session's current user and returns its
/// `Set-Cookie` value, or `None` if there is no user or signing fails.
async fn issue_refresh_cookie<Backend>(
    session: &AuthSession<Backend>,
    config: &JwtConfig,
) -> Option<String>
where
    Backend: AuthnBackend,
    Backend::User: Serialize,
{
    let user = session.user().await?;
    match config.encode_refresh(&user) {
        Ok(token) => Some(config.refresh_set_cookie(&token)),
        Err(err) => {
            tracing::error!(err = %err, "could not encode refresh jwt");
            None
        }
    }
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
            // Access token: cookie first, then Bearer. Slide if in last third.
            let mut reissue_access = false;
            let access_user =
                extract_token(req.headers(), &config.cookie_name).and_then(|token| {
                    config
                        .decode_kind::<Backend::User>(&token, TokenKind::Access)
                        .map(|(user, iat, exp)| {
                            reissue_access = config.should_refresh(iat, exp);
                            user
                        })
                });

            // Refresh token: only when enabled and its cookie was actually sent
            // (its `Path` scopes it to the refresh endpoint). Slide if in last
            // third.
            let mut reissue_refresh = false;
            let refresh_user = if config.refresh_enabled {
                extract_cookie(req.headers(), &config.refresh_cookie_name).and_then(|token| {
                    config
                        .decode_kind::<Backend::User>(&token, TokenKind::Refresh)
                        .map(|(user, iat, exp)| {
                            reissue_refresh = config.should_refresh(iat, exp);
                            user
                        })
                })
            } else {
                None
            };

            // Authenticate from the access token; otherwise fall back to a valid
            // refresh token, which also mints a fresh access cookie.
            let user = match access_user {
                Some(user) => Some(user),
                None => {
                    if refresh_user.is_some() {
                        reissue_access = true;
                    }
                    refresh_user
                }
            };

            if let Some(ref user) = user {
                tracing::Span::current().record("user.id", user.id().to_string());
            }

            let auth_session = AuthSession::from_jwt(backend, user);
            let handle = auth_session.clone();
            req.extensions_mut().insert(auth_session);

            let mut res = inner.call(req).await?;

            // An explicit login/logout during the request wins over sliding
            // refresh and refresh-token minting.
            let mut cookies: Vec<String> = Vec::new();
            match handle.take_pending_cookie().await {
                Some(PendingCookie::Clear) => {
                    cookies.push(config.access_clear_cookie());
                    if config.refresh_enabled {
                        cookies.push(config.refresh_clear_cookie());
                    }
                }
                Some(PendingCookie::Issue) => {
                    if let Some(cookie) = issue_access_cookie(&handle, &config).await {
                        cookies.push(cookie);
                    }
                    if config.refresh_enabled {
                        if let Some(cookie) = issue_refresh_cookie(&handle, &config).await {
                            cookies.push(cookie);
                        }
                    }
                }
                None => {
                    if reissue_access {
                        if let Some(cookie) = issue_access_cookie(&handle, &config).await {
                            cookies.push(cookie);
                        }
                    }
                    if reissue_refresh {
                        if let Some(cookie) = issue_refresh_cookie(&handle, &config).await {
                            cookies.push(cookie);
                        }
                    }
                }
            }

            for cookie in cookies {
                match HeaderValue::from_str(&cookie) {
                    Ok(value) => {
                        res.headers_mut().append(http::header::SET_COOKIE, value);
                    }
                    Err(err) => {
                        tracing::error!(err = %err, "could not build Set-Cookie header");
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

    #[test]
    fn should_refresh_only_in_last_third() {
        let cfg = config();
        let now = now_unix();

        // Lifetime 90s: refresh once remaining <= 30s (last third).
        assert!(cfg.should_refresh(now - 60, now + 30)); // remaining 30 == 1/3
        assert!(cfg.should_refresh(now - 80, now + 10)); // remaining 10
        assert!(!cfg.should_refresh(now - 45, now + 45)); // remaining 45 > 1/3
        assert!(!cfg.should_refresh(now, now + 90)); // fresh
    }

    #[test]
    fn should_refresh_respects_toggle_and_bad_bounds() {
        let now = now_unix();
        // Disabled.
        assert!(!config()
            .with_sliding_refresh(false)
            .should_refresh(now - 60, now + 30));
        // Degenerate exp <= iat.
        assert!(!config().should_refresh(now, now));
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

    /// All `Set-Cookie` header values on the response.
    fn set_cookies(res: &Response<Body>) -> Vec<String> {
        res.headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .collect()
    }

    /// The `Set-Cookie` value whose cookie name matches `name`, if any.
    fn find_set_cookie(res: &Response<Body>, name: &str) -> Option<String> {
        set_cookies(res)
            .into_iter()
            .find(|c| c.starts_with(&format!("{name}=")))
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

    // Signs a token with explicit iat/exp/kind so refresh behavior is
    // deterministic.
    fn craft_token(iat: u64, exp: u64, typ: TokenKind) -> String {
        let config = JwtConfig::from_secret(b"test-secret");
        let claims = Claims {
            sub: 1i64,
            iat,
            exp,
            typ,
            user: serde_json::to_value(User {
                id: 1,
                name: "alice".to_string(),
            })
            .unwrap(),
        };
        jsonwebtoken::encode(&Header::new(config.algorithm), &claims, &config.encoding_key).unwrap()
    }

    async fn whoami_with_cookie(app: Router, token: &str) -> Response<Body> {
        app.oneshot(
            Request::builder()
                .uri("/whoami")
                .header(header::COOKIE, format!("axum-login.jwt={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn sliding_refresh_reissues_cookie_in_last_third() {
        let app = app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // Lifetime 1000s, only 100s remaining → within the last third.
        let token = craft_token(now - 900, now + 100, TokenKind::Access);

        let res = whoami_with_cookie(app, &token).await;
        let cookie = set_cookie(&res).expect("token in last third should be re-issued");
        assert!(cookie.starts_with("axum-login.jwt="));
        assert!(cookie.contains("Max-Age="));
        assert!(!cookie.contains("Max-Age=0")); // a real token, not a clear
        assert_eq!(body_string(res).await, "alice");
    }

    #[tokio::test]
    async fn fresh_token_is_not_reissued() {
        let app = app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // Full lifetime remaining → no refresh.
        let token = craft_token(now, now + 1000, TokenKind::Access);

        let res = whoami_with_cookie(app, &token).await;
        assert!(
            set_cookie(&res).is_none(),
            "a fresh token must not be re-issued"
        );
    }

    // --- Refresh token mechanism ---

    const REFRESH_COOKIE: &str = "axum-login.refresh";

    fn refresh_app(backend: Backend) -> Router {
        let config = JwtConfig::from_secret(b"test-secret")
            .with_secure(false)
            .with_refresh_enabled(true)
            .with_refresh_cookie_name(REFRESH_COOKIE)
            .with_refresh_path("/auth/refresh")
            .with_refresh_ttl(std::time::Duration::from_secs(1000));
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
            .layer(JwtManagerLayer::new(backend, config))
    }

    fn craft_refresh_token(iat: u64, exp: u64) -> String {
        // The refresh cookie must be signed with the refresh ttl-independent
        // craft, using the Refresh kind.
        let config = JwtConfig::from_secret(b"test-secret");
        let claims = Claims {
            sub: 1i64,
            iat,
            exp,
            typ: TokenKind::Refresh,
            user: serde_json::to_value(User {
                id: 1,
                name: "alice".to_string(),
            })
            .unwrap(),
        };
        jsonwebtoken::encode(&Header::new(config.algorithm), &claims, &config.encoding_key).unwrap()
    }

    #[tokio::test]
    async fn login_issues_both_access_and_refresh_cookies() {
        let app = refresh_app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });

        let res = app
            .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let access = find_set_cookie(&res, DEFAULT_JWT_COOKIE_NAME).expect("access cookie");
        let refresh = find_set_cookie(&res, REFRESH_COOKIE).expect("refresh cookie");
        assert!(access.contains("Path=/;"));
        assert!(refresh.contains("Path=/auth/refresh;"));
    }

    #[tokio::test]
    async fn valid_refresh_token_mints_new_access_cookie() {
        let app = refresh_app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // Fresh refresh token (not in last third): should authenticate and mint
        // an access cookie, but not re-issue the refresh cookie.
        let refresh = craft_refresh_token(now, now + 1000);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, format!("{REFRESH_COOKIE}={refresh}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            find_set_cookie(&res, DEFAULT_JWT_COOKIE_NAME).is_some(),
            "a valid refresh token should mint a fresh access cookie"
        );
        assert!(
            find_set_cookie(&res, REFRESH_COOKIE).is_none(),
            "a fresh refresh token should not be rotated"
        );
        assert_eq!(body_string(res).await, "alice");
    }

    #[tokio::test]
    async fn refresh_token_slides_in_last_third() {
        let app = refresh_app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // Refresh token in its last third → re-issued (rotated) alongside access.
        let refresh = craft_refresh_token(now - 900, now + 100);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, format!("{REFRESH_COOKIE}={refresh}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let rotated = find_set_cookie(&res, REFRESH_COOKIE).expect("refresh should slide");
        assert!(rotated.contains("Path=/auth/refresh;"));
        assert!(!rotated.contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn refresh_token_is_rejected_as_access_token() {
        let app = refresh_app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // A Refresh-kind token presented in the access cookie must not
        // authenticate (typ mismatch).
        let refresh = craft_refresh_token(now, now + 1000);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, format!("{DEFAULT_JWT_COOKIE_NAME}={refresh}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(body_string(res).await, "anon");
    }

    #[tokio::test]
    async fn access_token_is_rejected_as_refresh_token() {
        let app = refresh_app(Backend {
            get_user_calls: Arc::new(AtomicUsize::new(0)),
        });
        let now = now_unix();
        // An Access-kind token presented in the refresh cookie must not be
        // accepted for minting.
        let access = craft_token(now, now + 1000, TokenKind::Access);

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/whoami")
                    .header(header::COOKIE, format!("{REFRESH_COOKIE}={access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(find_set_cookie(&res, DEFAULT_JWT_COOKIE_NAME).is_none());
        assert_eq!(body_string(res).await, "anon");
    }
}
