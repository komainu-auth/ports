use std::fmt;

use komainu_domain::code::{AuthorizationCode, AuthorizationCodeRecord};

/// Errors returned when calling methods on [`AuthorizationCodeRepository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationCodeRepositoryError {
    /// The given authorization code does not exist.
    NotFound,
    /// An authorization code with the same value already exists.
    AlreadyExists,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for AuthorizationCodeRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizationCodeRepositoryError::NotFound => write!(f, "authorization code not found"),
            AuthorizationCodeRepositoryError::AlreadyExists => {
                write!(f, "authorization code already exists")
            }
            AuthorizationCodeRepositoryError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for AuthorizationCodeRepositoryError {}

/// Repository port that abstracts issuance and consumption of authorization codes.
///
/// Used by the authorization code grant (RFC 6749 Section 4.1).
/// The application layer persists and consumes authorization codes through this trait.
///
/// # Code consumption (one-time use)
///
/// [`consume`] is responsible for retrieving a code and invalidating it (deleting it or
/// marking it as used) at the same time. This prevents authorization code replay attacks.
///
/// # Methods
///
/// - [`consume`] — Look up a code and invalidate it at the same time.
/// - [`save`] — Persist a new code record.
///
/// [`consume`]: AuthorizationCodeRepository::consume
/// [`save`]: AuthorizationCodeRepository::save
#[async_trait::async_trait]
pub trait AuthorizationCodeRepository {
    /// Consume an authorization code (retrieve and invalidate it).
    ///
    /// If the code is valid, returns the corresponding [`AuthorizationCodeRecord`] and
    /// deletes the record from storage or marks it as used.
    ///
    /// # Errors
    ///
    /// - [`AuthorizationCodeRepositoryError::NotFound`] — No matching code exists, or it was already consumed.
    /// - [`AuthorizationCodeRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn consume(
        &self,
        code: &AuthorizationCode,
    ) -> Result<AuthorizationCodeRecord, AuthorizationCodeRepositoryError>;

    /// Persist an [`AuthorizationCodeRecord`].
    ///
    /// # Errors
    ///
    /// - [`AuthorizationCodeRepositoryError::AlreadyExists`] — A record for the same code already exists.
    /// - [`AuthorizationCodeRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn save(
        &self,
        record: &AuthorizationCodeRecord,
    ) -> Result<(), AuthorizationCodeRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        assert_eq!(
            AuthorizationCodeRepositoryError::NotFound.to_string(),
            "authorization code not found"
        );
    }

    #[test]
    fn already_exists_display() {
        assert_eq!(
            AuthorizationCodeRepositoryError::AlreadyExists.to_string(),
            "authorization code already exists"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            AuthorizationCodeRepositoryError::UnknownError("timeout".to_string()).to_string(),
            "unknown error: timeout"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            AuthorizationCodeRepositoryError::NotFound,
            AuthorizationCodeRepositoryError::NotFound
        );
        assert_ne!(
            AuthorizationCodeRepositoryError::NotFound,
            AuthorizationCodeRepositoryError::AlreadyExists
        );
        assert_eq!(
            AuthorizationCodeRepositoryError::UnknownError("a".to_string()),
            AuthorizationCodeRepositoryError::UnknownError("a".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error = &AuthorizationCodeRepositoryError::AlreadyExists;
        assert_eq!(err.to_string(), "authorization code already exists");
    }

    #[test]
    fn error_is_cloneable() {
        let original = AuthorizationCodeRepositoryError::NotFound;
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn trait_consume_returns_not_found() {
        use komainu_domain::value_object::SecretValueObject;

        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl AuthorizationCodeRepository for AlwaysNotFound {
            async fn consume(
                &self,
                _code: &AuthorizationCode,
            ) -> Result<AuthorizationCodeRecord, AuthorizationCodeRepositoryError> {
                Err(AuthorizationCodeRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &AuthorizationCodeRecord,
            ) -> Result<(), AuthorizationCodeRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysNotFound;
            let code = AuthorizationCode::new("code-abc".to_string()).unwrap();
            let result = repo.consume(&code).await;
            assert_eq!(
                result.unwrap_err(),
                AuthorizationCodeRepositoryError::NotFound
            );
        });
    }

    #[test]
    fn trait_save_returns_ok() {
        use komainu_domain::{
            RedirectUri, Scope,
            client::ClientId,
            user::UserId,
            value_object::{SecretValueObject, ValueObject},
        };
        use std::time::{Duration, SystemTime};

        struct AlwaysOk;

        #[async_trait::async_trait]
        impl AuthorizationCodeRepository for AlwaysOk {
            async fn consume(
                &self,
                _code: &AuthorizationCode,
            ) -> Result<AuthorizationCodeRecord, AuthorizationCodeRepositoryError> {
                Err(AuthorizationCodeRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &AuthorizationCodeRecord,
            ) -> Result<(), AuthorizationCodeRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysOk;
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
            let record = AuthorizationCodeRecord::new(
                AuthorizationCode::new("code-xyz".to_string()).unwrap(),
                ClientId::new("client-1".to_string()).unwrap(),
                UserId::new("user-1".to_string()).unwrap(),
                RedirectUri::new("https://example.com/cb".to_string()).unwrap(),
                Scope::new("read".to_string()).unwrap(),
                now,
                now + Duration::from_secs(600),
            );
            assert!(repo.save(&record).await.is_ok());
        });
    }
}
