use std::fmt;

use komainu_domain::token::{RefreshToken, RefreshTokenRecord};

/// Errors returned when calling methods on [`RefreshTokenRepository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshTokenRepositoryError {
    /// The given refresh token does not exist.
    NotFound,
    /// A refresh token with the same value already exists.
    AlreadyExists,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for RefreshTokenRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshTokenRepositoryError::NotFound => write!(f, "refresh token not found"),
            RefreshTokenRepositoryError::AlreadyExists => write!(f, "refresh token already exists"),
            RefreshTokenRepositoryError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for RefreshTokenRepositoryError {}

/// Repository port that abstracts persistence and consumption of refresh tokens.
///
/// Used by the refresh token grant (RFC 6749 Section 6).
/// The application layer persists and consumes refresh tokens through this trait.
///
/// # Token consumption (rotation)
///
/// [`consume`] is responsible for retrieving a token and invalidating it at the same time.
/// Refresh token rotation (RFC 6819) makes it possible to detect reuse of consumed tokens.
///
/// # Methods
///
/// - [`consume`] — Look up a token and invalidate it at the same time.
/// - [`save`] — Persist a new token record.
///
/// [`consume`]: RefreshTokenRepository::consume
/// [`save`]: RefreshTokenRepository::save
#[async_trait::async_trait]
pub trait RefreshTokenRepository {
    /// Consume a refresh token (retrieve and invalidate it).
    ///
    /// If the token is valid, returns the corresponding [`RefreshTokenRecord`] and
    /// deletes the record from storage or marks it as used.
    ///
    /// # Errors
    ///
    /// - [`RefreshTokenRepositoryError::NotFound`] — No matching token exists, or it was already consumed.
    /// - [`RefreshTokenRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn consume(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<RefreshTokenRecord, RefreshTokenRepositoryError>;

    /// Persist a [`RefreshTokenRecord`].
    ///
    /// # Errors
    ///
    /// - [`RefreshTokenRepositoryError::AlreadyExists`] — A record for the same token already exists.
    /// - [`RefreshTokenRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn save(&self, record: &RefreshTokenRecord) -> Result<(), RefreshTokenRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        assert_eq!(
            RefreshTokenRepositoryError::NotFound.to_string(),
            "refresh token not found"
        );
    }

    #[test]
    fn already_exists_display() {
        assert_eq!(
            RefreshTokenRepositoryError::AlreadyExists.to_string(),
            "refresh token already exists"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            RefreshTokenRepositoryError::UnknownError("network".to_string()).to_string(),
            "unknown error: network"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            RefreshTokenRepositoryError::NotFound,
            RefreshTokenRepositoryError::NotFound
        );
        assert_ne!(
            RefreshTokenRepositoryError::NotFound,
            RefreshTokenRepositoryError::AlreadyExists
        );
        assert_eq!(
            RefreshTokenRepositoryError::UnknownError("e".to_string()),
            RefreshTokenRepositoryError::UnknownError("e".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error = &RefreshTokenRepositoryError::AlreadyExists;
        assert_eq!(err.to_string(), "refresh token already exists");
    }

    #[test]
    fn error_is_cloneable() {
        let original = RefreshTokenRepositoryError::NotFound;
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn trait_consume_returns_not_found() {
        use komainu_domain::value_object::SecretValueObject;

        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl RefreshTokenRepository for AlwaysNotFound {
            async fn consume(
                &self,
                _refresh_token: &RefreshToken,
            ) -> Result<RefreshTokenRecord, RefreshTokenRepositoryError> {
                Err(RefreshTokenRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &RefreshTokenRecord,
            ) -> Result<(), RefreshTokenRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysNotFound;
            let token = RefreshToken::new("refresh-tok".to_string()).unwrap();
            let result = repo.consume(&token).await;
            assert_eq!(result.unwrap_err(), RefreshTokenRepositoryError::NotFound);
        });
    }

    #[test]
    fn trait_save_returns_ok() {
        use komainu_domain::{
            Scope,
            client::ClientId,
            value_object::{SecretValueObject, ValueObject},
        };
        use std::time::{Duration, SystemTime};

        struct AlwaysOk;

        #[async_trait::async_trait]
        impl RefreshTokenRepository for AlwaysOk {
            async fn consume(
                &self,
                _refresh_token: &RefreshToken,
            ) -> Result<RefreshTokenRecord, RefreshTokenRepositoryError> {
                Err(RefreshTokenRepositoryError::NotFound)
            }
            async fn save(
                &self,
                _record: &RefreshTokenRecord,
            ) -> Result<(), RefreshTokenRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysOk;
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
            let record = RefreshTokenRecord::new(
                RefreshToken::new("refresh-tok".to_string()).unwrap(),
                ClientId::new("client-1".to_string()).unwrap(),
                None,
                Scope::new("read".to_string()).unwrap(),
                now,
                now + Duration::from_secs(86400),
            );
            assert!(repo.save(&record).await.is_ok());
        });
    }
}
