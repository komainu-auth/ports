use std::fmt;

use komainu_domain::{
    entity::Entity,
    user::UserId,
    value_object::{ValueObject, ValueObjectError},
};

/// Validation errors for [`SessionId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionIdError {
    /// The session ID is empty or contains only whitespace.
    Empty,
}

impl ValueObjectError for SessionIdError {}

impl std::fmt::Display for SessionIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionIdError::Empty => write!(f, "session_id must not be empty"),
        }
    }
}

impl std::error::Error for SessionIdError {}

/// Value object that uniquely identifies a session.
///
/// Empty strings and whitespace-only values are rejected at construction time.
/// Leading and trailing whitespace is trimmed automatically.
///
/// # Example
///
/// ```rust,ignore
/// use komainu_ports::driven::SessionId;
/// use komainu_domain::value_object::ValueObject;
///
/// let id = SessionId::new("sess-abc123".to_string()).unwrap();
/// assert_eq!(id.value(), "sess-abc123");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(String);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl ValueObject for SessionId {
    type Value = String;
    type Error = SessionIdError;

    fn new(value: Self::Value) -> Result<Self, Self::Error> {
        Self::is_valid(&value)?;
        Ok(Self(value.trim().to_string()))
    }

    fn value(&self) -> &Self::Value {
        &self.0
    }

    fn set_value(&mut self, value: Self::Value) -> Result<(), Self::Error> {
        Self::is_valid(&value)?;
        self.0 = value.trim().to_string();
        Ok(())
    }

    fn is_valid(value: &Self::Value) -> Result<(), Self::Error> {
        if value.trim().is_empty() {
            return Err(SessionIdError::Empty);
        }
        Ok(())
    }
}

/// Entity that holds the state of a session.
///
/// Tracks login status and consent status independently. In OAuth 2.0 authorization
/// flows, user login and scope consent may occur in separate steps, so each flag is
/// managed on its own.
///
/// # Entity identity
///
/// [`Entity::id`] returns a [`SessionId`].
///
/// # Fields
///
/// - `session_id` — ID that uniquely identifies the session
/// - `user_id` — ID of the resource owner associated with the session
/// - `logged_in` — Whether the user is logged in for this session
/// - `consented` — Whether the user has completed consent to the requested scopes
///
/// [`Entity::id`]: komainu_domain::entity::Entity::id
#[derive(Debug, Clone)]
pub struct SessionRecord {
    session_id: SessionId,
    user_id: UserId,
    logged_in: bool,
    consented: bool,
}

impl SessionRecord {
    /// Creates a new [`SessionRecord`].
    pub fn new(session_id: SessionId, user_id: UserId, logged_in: bool, consented: bool) -> Self {
        Self {
            session_id,
            user_id,
            logged_in,
            consented,
        }
    }

    /// Returns the [`SessionId`] for this session.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the [`UserId`] of the user associated with this session.
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns `true` if the user is logged in for this session.
    pub fn logged_in(&self) -> bool {
        self.logged_in
    }

    /// Returns `true` if the user has completed consent to the requested scopes.
    pub fn consented(&self) -> bool {
        self.consented
    }

    /// Records a successful login, setting `logged_in` to `true`.
    pub fn log_in_success(&mut self) {
        self.logged_in = true;
    }

    /// Records successful scope consent, setting `consented` to `true`.
    pub fn consent_success(&mut self) {
        self.consented = true;
    }
}

impl Entity for SessionRecord {
    type Id = SessionId;

    fn id(&self) -> &Self::Id {
        &self.session_id
    }
}

/// Errors returned when calling methods on [`SessionStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStoreError {
    /// No session exists for the given session ID.
    NotFound,
    /// Session creation failed.
    CreateFailed,
    /// Session deletion failed.
    DeleteFailed,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionStoreError::CreateFailed => write!(f, "create session failed"),
            SessionStoreError::DeleteFailed => write!(f, "delete session failed"),
            SessionStoreError::NotFound => write!(f, "session not found"),
            SessionStoreError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for SessionStoreError {}

/// Store port that abstracts creation, retrieval, update, and deletion of sessions.
///
/// Used for session management of authenticated users (maintaining login state).
/// Manages the mapping between session IDs and [`SessionRecord`] values, enabling
/// browser sessions and cookie-based authentication flows.
///
/// Because sessions track login state (`logged_in`) and consent state (`consented`)
/// independently, call [`update`] to persist changes when these states change during
/// an OAuth 2.0 authorization flow.
///
/// Concrete storage backends (Redis, in-memory, relational databases, and so on)
/// are implemented in the infrastructure layer.
///
/// # Methods
///
/// - [`create`] — Create a session for a user ID and return a new session ID.
/// - [`find`] — Return the [`SessionRecord`] for a session ID.
/// - [`update`] — Update session state (login and consent flags).
/// - [`delete`] — Delete a session (used on logout).
///
/// [`create`]: SessionStore::create
/// [`find`]: SessionStore::find
/// [`update`]: SessionStore::update
/// [`delete`]: SessionStore::delete
#[async_trait::async_trait]
pub trait SessionStore {
    /// Creates a new session for the given user ID and returns the session ID.
    ///
    /// The format of generated session IDs (UUID, random strings, and so on) is left
    /// to the implementation.
    ///
    /// # Errors
    ///
    /// - [`SessionStoreError::CreateFailed`] — Writing to storage failed.
    /// - [`SessionStoreError::UnknownError`] — An unexpected error occurred.
    async fn create(&self, user_id: &UserId) -> Result<SessionId, SessionStoreError>;

    /// Retrieves the [`SessionRecord`] for the given session ID.
    ///
    /// Used to validate the session on each request and to check the user's
    /// authentication and consent status.
    ///
    /// # Errors
    ///
    /// - [`SessionStoreError::NotFound`] — No matching session exists, or it has expired.
    /// - [`SessionStoreError::UnknownError`] — An unexpected error occurred.
    async fn find(&self, session_id: &SessionId) -> Result<SessionRecord, SessionStoreError>;

    /// Persists the state of a [`SessionRecord`] to storage.
    ///
    /// Call this method after a successful login ([`SessionRecord::log_in_success`])
    /// or consent completion ([`SessionRecord::consent_success`]) to persist the
    /// updated state.
    ///
    /// # Errors
    ///
    /// - [`SessionStoreError::NotFound`] — The session to update does not exist.
    /// - [`SessionStoreError::UnknownError`] — An unexpected error occurred.
    async fn update(&self, record: &SessionRecord) -> Result<(), SessionStoreError>;

    /// Deletes a session.
    ///
    /// Used on logout or when invalidating a session.
    ///
    /// # Errors
    ///
    /// - [`SessionStoreError::DeleteFailed`] — Deletion from storage failed.
    /// - [`SessionStoreError::UnknownError`] — An unexpected error occurred.
    async fn delete(&self, session_id: &SessionId) -> Result<(), SessionStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use komainu_domain::value_object::ValueObject;

    // ---- SessionId ----

    #[test]
    fn session_id_valid_value_succeeds() {
        let id = SessionId::new("sess-abc".to_string()).unwrap();
        assert_eq!(id.value(), "sess-abc");
    }

    #[test]
    fn session_id_empty_string_fails() {
        assert_eq!(SessionId::new("".to_string()), Err(SessionIdError::Empty));
    }

    #[test]
    fn session_id_whitespace_only_fails() {
        assert_eq!(
            SessionId::new("   ".to_string()),
            Err(SessionIdError::Empty)
        );
    }

    #[test]
    fn session_id_surrounding_whitespace_is_trimmed() {
        let id = SessionId::new("  sess-1  ".to_string()).unwrap();
        assert_eq!(id.value(), "sess-1");
    }

    #[test]
    fn session_id_set_value_updates_on_success() {
        let mut id = SessionId::new("old".to_string()).unwrap();
        id.set_value("new".to_string()).unwrap();
        assert_eq!(id.value(), "new");
    }

    #[test]
    fn session_id_set_value_rejects_invalid_and_keeps_old() {
        let mut id = SessionId::new("old".to_string()).unwrap();
        assert_eq!(id.set_value("".to_string()), Err(SessionIdError::Empty));
        assert_eq!(id.value(), "old");
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::new("sess-xyz".to_string()).unwrap();
        assert_eq!(id.to_string(), "sess-xyz");
    }

    #[test]
    fn session_id_equal_values_are_equal() {
        let a = SessionId::new("s".to_string()).unwrap();
        let b = SessionId::new("s".to_string()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn session_id_error_display() {
        assert_eq!(
            SessionIdError::Empty.to_string(),
            "session_id must not be empty"
        );
    }

    #[test]
    fn session_id_error_implements_std_error() {
        let err: &dyn std::error::Error = &SessionIdError::Empty;
        assert_eq!(err.to_string(), "session_id must not be empty");
    }

    // ---- SessionStoreError ----

    #[test]
    fn not_found_display() {
        assert_eq!(SessionStoreError::NotFound.to_string(), "session not found");
    }

    #[test]
    fn create_failed_display() {
        assert_eq!(
            SessionStoreError::CreateFailed.to_string(),
            "create session failed"
        );
    }

    #[test]
    fn delete_failed_display() {
        assert_eq!(
            SessionStoreError::DeleteFailed.to_string(),
            "delete session failed"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            SessionStoreError::UnknownError("redis timeout".to_string()).to_string(),
            "unknown error: redis timeout"
        );
    }

    #[test]
    fn store_error_variants_are_equal_by_value() {
        assert_eq!(SessionStoreError::NotFound, SessionStoreError::NotFound);
        assert_ne!(SessionStoreError::NotFound, SessionStoreError::CreateFailed);
        assert_eq!(
            SessionStoreError::UnknownError("a".to_string()),
            SessionStoreError::UnknownError("a".to_string())
        );
    }

    #[test]
    fn store_error_implements_std_error() {
        let err: &dyn std::error::Error = &SessionStoreError::CreateFailed;
        assert_eq!(err.to_string(), "create session failed");
    }

    #[test]
    fn store_error_is_cloneable() {
        let original = SessionStoreError::DeleteFailed;
        assert_eq!(original.clone(), original);
    }

    // ---- SessionRecord ----

    fn sample_session_id() -> SessionId {
        SessionId::new("sess-1".to_string()).unwrap()
    }
    fn sample_user_id() -> UserId {
        UserId::new("user-1".to_string()).unwrap()
    }

    #[test]
    fn session_record_getters_return_constructor_values() {
        let record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        assert_eq!(record.session_id(), &sample_session_id());
        assert_eq!(record.user_id(), &sample_user_id());
        assert!(!record.logged_in());
        assert!(!record.consented());
    }

    #[test]
    fn log_in_success_sets_logged_in_to_true() {
        let mut record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        assert!(!record.logged_in());
        record.log_in_success();
        assert!(record.logged_in());
    }

    #[test]
    fn consent_success_sets_consented_to_true() {
        let mut record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        assert!(!record.consented());
        record.consent_success();
        assert!(record.consented());
    }

    #[test]
    fn log_in_success_does_not_affect_consented() {
        let mut record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        record.log_in_success();
        assert!(!record.consented());
    }

    #[test]
    fn consent_success_does_not_affect_logged_in() {
        let mut record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        record.consent_success();
        assert!(!record.logged_in());
    }

    #[test]
    fn session_record_id_is_session_id() {
        use komainu_domain::entity::Entity;
        let record = SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
        assert_eq!(record.id(), &sample_session_id());
    }

    // ---- SessionStore trait ----

    #[test]
    fn trait_create_returns_session_id() {
        struct FixedStore;

        #[async_trait::async_trait]
        impl SessionStore for FixedStore {
            async fn create(&self, _user_id: &UserId) -> Result<SessionId, SessionStoreError> {
                Ok(SessionId::new("new-session".to_string()).unwrap())
            }
            async fn find(
                &self,
                _session_id: &SessionId,
            ) -> Result<SessionRecord, SessionStoreError> {
                Err(SessionStoreError::NotFound)
            }
            async fn update(&self, _record: &SessionRecord) -> Result<(), SessionStoreError> {
                Ok(())
            }
            async fn delete(&self, _session_id: &SessionId) -> Result<(), SessionStoreError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = FixedStore;
            let user_id = UserId::new("user-1".to_string()).unwrap();
            let session_id = store.create(&user_id).await.unwrap();
            assert_eq!(session_id.value(), "new-session");
        });
    }

    #[test]
    fn trait_find_returns_session_record() {
        struct FixedStore;

        #[async_trait::async_trait]
        impl SessionStore for FixedStore {
            async fn create(&self, _user_id: &UserId) -> Result<SessionId, SessionStoreError> {
                Err(SessionStoreError::CreateFailed)
            }
            async fn find(
                &self,
                session_id: &SessionId,
            ) -> Result<SessionRecord, SessionStoreError> {
                Ok(SessionRecord::new(
                    session_id.clone(),
                    UserId::new("user-1".to_string()).unwrap(),
                    true,
                    false,
                ))
            }
            async fn update(&self, _record: &SessionRecord) -> Result<(), SessionStoreError> {
                Ok(())
            }
            async fn delete(&self, _session_id: &SessionId) -> Result<(), SessionStoreError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = FixedStore;
            let session_id = SessionId::new("sess-abc".to_string()).unwrap();
            let record = store.find(&session_id).await.unwrap();
            assert_eq!(record.session_id(), &session_id);
            assert_eq!(record.user_id().value(), "user-1");
            assert!(record.logged_in());
            assert!(!record.consented());
        });
    }

    #[test]
    fn trait_find_returns_not_found() {
        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl SessionStore for AlwaysNotFound {
            async fn create(&self, _user_id: &UserId) -> Result<SessionId, SessionStoreError> {
                Err(SessionStoreError::CreateFailed)
            }
            async fn find(
                &self,
                _session_id: &SessionId,
            ) -> Result<SessionRecord, SessionStoreError> {
                Err(SessionStoreError::NotFound)
            }
            async fn update(&self, _record: &SessionRecord) -> Result<(), SessionStoreError> {
                Err(SessionStoreError::NotFound)
            }
            async fn delete(&self, _session_id: &SessionId) -> Result<(), SessionStoreError> {
                Err(SessionStoreError::DeleteFailed)
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = AlwaysNotFound;
            let session_id = SessionId::new("unknown-sess".to_string()).unwrap();
            let result = store.find(&session_id).await;
            assert_eq!(result.unwrap_err(), SessionStoreError::NotFound);
        });
    }

    #[test]
    fn trait_update_returns_ok() {
        struct AlwaysOk;

        #[async_trait::async_trait]
        impl SessionStore for AlwaysOk {
            async fn create(&self, _user_id: &UserId) -> Result<SessionId, SessionStoreError> {
                Err(SessionStoreError::CreateFailed)
            }
            async fn find(
                &self,
                _session_id: &SessionId,
            ) -> Result<SessionRecord, SessionStoreError> {
                Err(SessionStoreError::NotFound)
            }
            async fn update(&self, _record: &SessionRecord) -> Result<(), SessionStoreError> {
                Ok(())
            }
            async fn delete(&self, _session_id: &SessionId) -> Result<(), SessionStoreError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = AlwaysOk;
            let mut record =
                SessionRecord::new(sample_session_id(), sample_user_id(), false, false);
            record.log_in_success();
            assert!(store.update(&record).await.is_ok());
        });
    }

    #[test]
    fn trait_delete_returns_ok() {
        struct AlwaysOk;

        #[async_trait::async_trait]
        impl SessionStore for AlwaysOk {
            async fn create(&self, _user_id: &UserId) -> Result<SessionId, SessionStoreError> {
                Err(SessionStoreError::CreateFailed)
            }
            async fn find(
                &self,
                _session_id: &SessionId,
            ) -> Result<SessionRecord, SessionStoreError> {
                Err(SessionStoreError::NotFound)
            }
            async fn update(&self, _record: &SessionRecord) -> Result<(), SessionStoreError> {
                Ok(())
            }
            async fn delete(&self, _session_id: &SessionId) -> Result<(), SessionStoreError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let store = AlwaysOk;
            let session_id = SessionId::new("sess-to-delete".to_string()).unwrap();
            assert!(store.delete(&session_id).await.is_ok());
        });
    }
}
