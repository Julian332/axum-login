use std::{fmt::Debug, sync::Arc};
use aide::OperationIo;
#[cfg(feature = "session")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "session")]
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
#[cfg(feature = "session")]
use tower_sessions::{session, Session};

#[cfg(feature = "session")]
use crate::backend::UserId;
use crate::{backend::AuthUser, AuthnBackend};

#[cfg(not(any(feature = "session", feature = "jwt")))]
compile_error!("axum-login requires at least one of the `session` or `jwt` features");

/// An error type which maps session and backend errors.
#[derive(thiserror::Error)]
pub enum Error<Backend: AuthnBackend> {
    /// A mapping to `tower_sessions::session::Error'.
    #[cfg(feature = "session")]
    #[error(transparent)]
    Session(session::Error),

    /// A mapping to `Backend::Error`.
    #[error(transparent)]
    Backend(Backend::Error),

    /// A mapping to a JWT encoding/decoding error.
    #[cfg(feature = "jwt")]
    #[error(transparent)]
    Jwt(jsonwebtoken::errors::Error),
}

impl<Backend: AuthnBackend> Debug for Error<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "session")]
            Error::Session(err) => write!(f, "{err:?}")?,
            Error::Backend(err) => write!(f, "{err:?}")?,
            #[cfg(feature = "jwt")]
            Error::Jwt(err) => write!(f, "{err:?}")?,
        };

        Ok(())
    }
}

#[cfg(feature = "session")]
impl<Backend: AuthnBackend> From<session::Error> for Error<Backend> {
    fn from(value: session::Error) -> Self {
        Self::Session(value)
    }
}

#[cfg(feature = "session")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Data<UserId> {
    user_id: Option<UserId>,
    auth_hash: Option<Vec<u8>>,
}

#[cfg(feature = "session")]
impl<UserId: Clone> Default for Data<UserId> {
    fn default() -> Self {
        Self {
            user_id: None,
            auth_hash: None,
        }
    }
}

/// The source backing an [`AuthSession`].
///
/// The session path stores identity server-side (via `tower-sessions`) and
/// verifies it against the backend on each request. The stateless JWT path
/// (feature `jwt`) reconstructs the user from the token's claims and never
/// touches the backend per request.
#[derive(Debug, Clone)]
enum Inner<Backend: AuthnBackend> {
    #[cfg(feature = "session")]
    Session {
        session: Session,
        user: Option<Backend::User>,
        data: Data<UserId<Backend>>,
        data_key: &'static str,
    },

    #[cfg(feature = "jwt")]
    Jwt {
        user: Option<Backend::User>,
        pending: Option<crate::jwt::PendingCookie>,
    },
}

impl<Backend: AuthnBackend> Inner<Backend> {
    fn user(&self) -> Option<Backend::User> {
        match self {
            #[cfg(feature = "session")]
            Inner::Session { user, .. } => user.clone(),
            #[cfg(feature = "jwt")]
            Inner::Jwt { user, .. } => user.clone(),
        }
    }
}

/// A specialized session for identification, authentication, and authorization
/// of users associated with a backend.
///
/// The session is generic over some backend which implements [`AuthnBackend`].
/// The backend may also implement [`AuthzBackend`](crate::AuthzBackend),
/// in which case it will also supply authorization methods.
///
/// Methods for authenticating the session and logging a user in are provided.
///
/// Generally this session will be used in the context of some authentication
/// workflow, for example via a frontend login form. There a user would provide
/// their credentials, such as username and password, and via the backend
/// the session would authenticate those credentials.
///
/// Once the supplied credentials have been authenticated, a user will be
/// returned. In the case the credentials are invalid, no user will be returned.
/// When we do have a user, it's then possible to set the state of the session
/// so that the user is logged in.
#[derive(Debug, Clone, OperationIo)]
pub struct AuthSession<Backend: AuthnBackend> {
    backend: Backend,
    inner: Arc<Mutex<Inner<Backend>>>,
}

impl<Backend: AuthnBackend> AuthSession<Backend> {
    /// Returns the backend associated wih his auth session.
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Returns the user that's authenicated to this session otherwise `None`.
    pub async fn user(&self) -> Option<Backend::User> {
        self.inner.lock().await.user()
    }

    /// Verifies the provided credentials via the backend returning the
    /// authenticated user if valid and otherwise `None`.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn authenticate(
        &self,
        creds: Backend::Credentials,
    ) -> Result<Option<Backend::User>, Error<Backend>> {
        let result = self
            .backend
            .authenticate(creds)
            .await
            .map_err(Error::Backend);

        if let Ok(Some(ref user)) = result {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        result
    }

    /// Updates the session such that the user is logged in.
    ///
    /// In the JWT path (feature `jwt`) this marks the session for a token to be
    /// issued; the token is signed and written as a cookie by the JWT
    /// middleware once the handler returns.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id = user.id().to_string()), ret, err)]
    pub async fn login(&self, user: &Backend::User) -> Result<(), Error<Backend>> {
        let mut inner = self.inner.lock().await;
        match &mut *inner {
            #[cfg(feature = "session")]
            Inner::Session {
                session,
                user: current,
                data,
                data_key,
            } => {
                *current = Some(user.clone());

                if data.auth_hash.is_none() {
                    session.cycle_id().await?; // Session-fixation mitigation.
                }

                data.user_id = Some(user.id());
                data.auth_hash = Some(user.session_auth_hash().to_owned());

                session.insert(data_key, data.clone()).await?;
            }

            #[cfg(feature = "jwt")]
            Inner::Jwt {
                user: current,
                pending,
            } => {
                *current = Some(user.clone());
                *pending = Some(crate::jwt::PendingCookie::Issue);
            }
        }

        Ok(())
    }

    /// Updates the session such that the user is logged out.
    ///
    /// In the JWT path (feature `jwt`) this marks the token cookie for removal;
    /// the expiring cookie is written by the JWT middleware once the handler
    /// returns.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn logout(&self) -> Result<Option<Backend::User>, Error<Backend>> {
        let mut inner = self.inner.lock().await;
        let user = match &mut *inner {
            #[cfg(feature = "session")]
            Inner::Session { session, user, .. } => {
                let user = user.take();
                session.flush().await?;
                user
            }

            #[cfg(feature = "jwt")]
            Inner::Jwt { user, pending } => {
                let user = user.take();
                *pending = Some(crate::jwt::PendingCookie::Clear);
                user
            }
        };

        if let Some(ref user) = user {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        Ok(user)
    }

    /// Builds a stateless auth session from a user already decoded from a JWT.
    ///
    /// No backend lookup is performed; the user is taken verbatim from the
    /// token's claims.
    #[cfg(feature = "jwt")]
    pub(crate) fn from_jwt(backend: Backend, user: Option<Backend::User>) -> Self {
        Self {
            backend,
            inner: Arc::new(Mutex::new(Inner::Jwt {
                user,
                pending: None,
            })),
        }
    }

    /// Takes any pending cookie action recorded by [`login`](Self::login) or
    /// [`logout`](Self::logout) in the JWT path, clearing it.
    #[cfg(feature = "jwt")]
    pub(crate) async fn take_pending_cookie(&self) -> Option<crate::jwt::PendingCookie> {
        match &mut *self.inner.lock().await {
            Inner::Jwt { pending, .. } => pending.take(),
            #[cfg(feature = "session")]
            _ => None,
        }
    }

    #[cfg(feature = "session")]
    pub(crate) async fn from_session(
        session: Session,
        backend: Backend,
        data_key: &'static str,
    ) -> Result<Self, Error<Backend>> {
        let mut data: Data<_> = session.get(data_key).await?.unwrap_or_default();

        let mut user = if let Some(ref user_id) = data.user_id {
            backend.get_user(user_id).await.map_err(Error::Backend)?
        } else {
            None
        };

        if let Some(ref authed_user) = user {
            let session_auth_hash = authed_user.session_auth_hash();
            let session_verified = data
                .auth_hash
                .as_ref()
                .is_some_and(|auth_hash| auth_hash.ct_eq(session_auth_hash).into());
            if !session_verified {
                user = None;
                data = Data::default();
                session.flush().await?;
            }
        }

        let inner = Arc::new(Mutex::new(Inner::Session {
            user,
            session,
            data,
            data_key,
        }));

        Ok(Self { backend, inner })
    }
}

#[cfg(all(test, feature = "session"))]
mod tests {
    use std::sync::Arc;

    use mockall::{predicate::*, *};
    use tower_sessions::MemoryStore;

    use super::*;

    mock! {
        #[derive(Debug)]
        Backend {}

        impl Clone for Backend {
            fn clone(&self) -> Self;
        }

        impl AuthnBackend for Backend {
            type User = MockUser;
            type Credentials = MockCredentials;
            type Error = MockError;

            async fn authenticate(&self, creds: MockCredentials) -> Result<Option<MockUser>, MockError>;
            async fn get_user(&self, user_id: &i64) -> Result<Option<MockUser>, MockError>;

        }
    }

    #[derive(Debug, Clone)]
    struct MockUser {
        id: i64,
        auth_hash: Vec<u8>,
    }

    impl AuthUser for MockUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &self.auth_hash
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockCredentials;

    #[derive(Debug)]
    struct MockError;

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Mock error")
        }
    }

    impl std::error::Error for MockError {}

    #[tokio::test]
    async fn test_authenticate() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };
        let creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(creds.clone()))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());

        let session = Session::new(None, store, None);
        let inner = Inner::Session {
            user: None,
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };

        let result = auth_session.authenticate(creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_authenticate_bad_credentials() {
        let mut mock_backend = MockBackend::default();
        let bad_creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(bad_creds.clone()))
            .times(1)
            .returning(|_| Ok(None));

        let store = Arc::new(MemoryStore::default());

        let session = Session::new(None, store, None);
        let inner = Inner::Session {
            user: None,
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };
        let result = auth_session.authenticate(bad_creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_login() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        let original_session_id = session.id();
        let inner = Inner::Session {
            user: None,
            session: session.clone(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };

        auth_session.login(&mock_user).await.unwrap();
        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);

        // Simulate request persisting session.
        session.save().await.unwrap();

        // We were provided no session initially.
        assert!(original_session_id.is_none());

        // We have a session ID after saving.
        assert!(session.id().is_some());
    }

    #[tokio::test]
    async fn test_logout() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store, None);
        let inner = Inner::Session {
            user: Some(mock_user),
            session,
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Arc::new(Mutex::new(inner)),
        };
        let logged_out_user = auth_session.logout().await.unwrap();
        assert!(logged_out_user.is_some());
        assert_eq!(logged_out_user.unwrap().id(), 42);
        assert!(auth_session.user().await.is_none());
    }

    #[tokio::test]
    async fn test_from_session() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store.clone(), None);
        let data_key = "auth_data";

        // Simulate a user being logged in
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![1, 2, 3, 4]),
        };
        session.insert(data_key, &data).await.unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);
    }

    #[tokio::test]
    async fn test_from_session_bad_auth_hash() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let store = Arc::new(MemoryStore::default());
        let session = Session::new(None, store.clone(), None);
        let data_key = "auth_data";

        // Try to use a malformed auth hash.
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![4, 3, 2, 1]),
        };
        session.insert(data_key, &data).await.unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_none());
    }
}
