use std::fmt;

use komainu_domain::client::{ClientId, OAuthClient};

/// Errors returned when calling methods on [`ClientRepository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRepositoryError {
    /// No client exists with the given `client_id`.
    NotFound,
    /// A client with the same `client_id` already exists.
    AlreadyExists,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for ClientRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientRepositoryError::NotFound => write!(f, "client not found"),
            ClientRepositoryError::AlreadyExists => write!(f, "client already exists"),
            ClientRepositoryError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for ClientRepositoryError {}

/// Repository port that abstracts persistence and lookup of OAuth clients.
///
/// The application layer reads and writes [`OAuthClient`] values through this trait.
/// Used for client registration, client authentication, and validation during token issuance.
///
/// # Methods
///
/// - [`find_by_id`] — Look up an [`OAuthClient`] by `client_id`.
/// - [`save`] — Persist an [`OAuthClient`].
///
/// [`find_by_id`]: ClientRepository::find_by_id
/// [`save`]: ClientRepository::save
#[async_trait::async_trait]
pub trait ClientRepository {
    /// Look up an [`OAuthClient`] by `client_id`.
    ///
    /// # Errors
    ///
    /// - [`ClientRepositoryError::NotFound`] — No matching client exists.
    /// - [`ClientRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn find_by_id(&self, client_id: &ClientId) -> Result<OAuthClient, ClientRepositoryError>;

    /// Persist an [`OAuthClient`].
    ///
    /// # Errors
    ///
    /// - [`ClientRepositoryError::AlreadyExists`] — A client with the same `client_id` already exists.
    /// - [`ClientRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn save(&self, client: &OAuthClient) -> Result<(), ClientRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        assert_eq!(
            ClientRepositoryError::NotFound.to_string(),
            "client not found"
        );
    }

    #[test]
    fn already_exists_display() {
        assert_eq!(
            ClientRepositoryError::AlreadyExists.to_string(),
            "client already exists"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            ClientRepositoryError::UnknownError("io error".to_string()).to_string(),
            "unknown error: io error"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            ClientRepositoryError::NotFound,
            ClientRepositoryError::NotFound
        );
        assert_ne!(
            ClientRepositoryError::NotFound,
            ClientRepositoryError::AlreadyExists
        );
        assert_eq!(
            ClientRepositoryError::UnknownError("x".to_string()),
            ClientRepositoryError::UnknownError("x".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error = &ClientRepositoryError::NotFound;
        assert_eq!(err.to_string(), "client not found");
    }

    #[test]
    fn error_is_cloneable() {
        let original = ClientRepositoryError::AlreadyExists;
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn trait_find_by_id_returns_not_found() {
        use komainu_domain::value_object::ValueObject;

        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl ClientRepository for AlwaysNotFound {
            async fn find_by_id(
                &self,
                _client_id: &ClientId,
            ) -> Result<OAuthClient, ClientRepositoryError> {
                Err(ClientRepositoryError::NotFound)
            }
            async fn save(&self, _client: &OAuthClient) -> Result<(), ClientRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysNotFound;
            let id = ClientId::new("client-1".to_string()).unwrap();
            let result = repo.find_by_id(&id).await;
            assert_eq!(result.unwrap_err(), ClientRepositoryError::NotFound);
        });
    }

    #[test]
    fn trait_save_returns_ok() {
        use komainu_domain::client::{ClientSecret, ClientTokenTtl, ClientType};
        use komainu_domain::value_object::{SecretValueObject, ValueObject};

        struct AlwaysOk;

        #[async_trait::async_trait]
        impl ClientRepository for AlwaysOk {
            async fn find_by_id(
                &self,
                _client_id: &ClientId,
            ) -> Result<OAuthClient, ClientRepositoryError> {
                Err(ClientRepositoryError::NotFound)
            }
            async fn save(&self, _client: &OAuthClient) -> Result<(), ClientRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysOk;
            let client = OAuthClient::new(
                ClientId::new("client-1".to_string()).unwrap(),
                Some(ClientSecret::new("secret".to_string()).unwrap()),
                ClientType::Confidential,
                ClientTokenTtl::new(None, None, None),
            )
            .unwrap();
            assert!(repo.save(&client).await.is_ok());
        });
    }
}
