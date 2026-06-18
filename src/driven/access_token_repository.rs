use std::fmt;

use komainu_domain::token::{AccessToken, AccessTokenRecord};

/// Errors returned when calling methods on [`AccessTokenRepository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessTokenRepositoryError {
    /// The given access token does not exist.
    NotFound,
    /// An access token with the same value already exists.
    AlreadyExists,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for AccessTokenRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessTokenRepositoryError::NotFound => write!(f, "access token not found"),
            AccessTokenRepositoryError::AlreadyExists => write!(f, "access token already exists"),
            AccessTokenRepositoryError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for AccessTokenRepositoryError {}

/// Repository port that abstracts persistence and lookup of access tokens.
///
/// The application layer reads and writes access tokens through this trait.
/// Concrete storage backends (RDB, KVS, and so on) are implemented in the infrastructure layer.
///
/// # Methods
///
/// - [`find_by_token`] — Look up a record by token value. Returns
///   [`AccessTokenRepositoryError::NotFound`] if it does not exist.
/// - [`save`] — Persist a new record. Returns
///   [`AccessTokenRepositoryError::AlreadyExists`] if the same token already exists.
///
/// [`find_by_token`]: AccessTokenRepository::find_by_token
/// [`save`]: AccessTokenRepository::save
#[async_trait::async_trait]
pub trait AccessTokenRepository {
    /// Look up an [`AccessTokenRecord`] by token value.
    ///
    /// # Errors
    ///
    /// - [`AccessTokenRepositoryError::NotFound`] — No matching record exists.
    /// - [`AccessTokenRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn find_by_token(
        &self,
        access_token: &AccessToken,
    ) -> Result<AccessTokenRecord, AccessTokenRepositoryError>;

    /// Persist an [`AccessTokenRecord`].
    ///
    /// # Errors
    ///
    /// - [`AccessTokenRepositoryError::AlreadyExists`] — A record for the same token already exists.
    /// - [`AccessTokenRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn save(&self, record: &AccessTokenRecord) -> Result<(), AccessTokenRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        assert_eq!(
            AccessTokenRepositoryError::NotFound.to_string(),
            "access token not found"
        );
    }

    #[test]
    fn already_exists_display() {
        assert_eq!(
            AccessTokenRepositoryError::AlreadyExists.to_string(),
            "access token already exists"
        );
    }

    #[test]
    fn unknown_error_display() {
        let msg = "db connection failed".to_string();
        assert_eq!(
            AccessTokenRepositoryError::UnknownError(msg).to_string(),
            "unknown error: db connection failed"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            AccessTokenRepositoryError::NotFound,
            AccessTokenRepositoryError::NotFound
        );
        assert_eq!(
            AccessTokenRepositoryError::AlreadyExists,
            AccessTokenRepositoryError::AlreadyExists
        );
        assert_eq!(
            AccessTokenRepositoryError::UnknownError("x".to_string()),
            AccessTokenRepositoryError::UnknownError("x".to_string())
        );
        assert_ne!(
            AccessTokenRepositoryError::NotFound,
            AccessTokenRepositoryError::AlreadyExists
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error = &AccessTokenRepositoryError::NotFound;
        assert_eq!(err.to_string(), "access token not found");
    }

    #[test]
    fn error_is_cloneable() {
        let original = AccessTokenRepositoryError::UnknownError("err".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn trait_object_find_by_token_returns_not_found() {
        use komainu_domain::value_object::SecretValueObject;

        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl AccessTokenRepository for AlwaysNotFound {
            async fn find_by_token(
                &self,
                _access_token: &AccessToken,
            ) -> Result<AccessTokenRecord, AccessTokenRepositoryError> {
                Err(AccessTokenRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &AccessTokenRecord,
            ) -> Result<(), AccessTokenRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysNotFound;
            let token = AccessToken::new("tok".to_string()).unwrap();
            let result = repo.find_by_token(&token).await;
            assert_eq!(result.unwrap_err(), AccessTokenRepositoryError::NotFound);
        });
    }

    #[test]
    fn trait_object_save_returns_ok() {
        use komainu_domain::{
            Scope,
            client::ClientId,
            token::{AccessToken, AccessTokenRecord},
            value_object::{SecretValueObject, ValueObject},
        };
        use std::time::{Duration, SystemTime};

        struct InMemory;

        #[async_trait::async_trait]
        impl AccessTokenRepository for InMemory {
            async fn find_by_token(
                &self,
                _access_token: &AccessToken,
            ) -> Result<AccessTokenRecord, AccessTokenRepositoryError> {
                Err(AccessTokenRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &AccessTokenRecord,
            ) -> Result<(), AccessTokenRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = InMemory;
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
            let expires = now + Duration::from_secs(3600);
            let record = AccessTokenRecord::new(
                AccessToken::new("tok".to_string()).unwrap(),
                ClientId::new("client-1".to_string()).unwrap(),
                None,
                Scope::new("read".to_string()).unwrap(),
                now,
                expires,
            );
            assert!(repo.save(&record).await.is_ok());
        });
    }
}
