use komainu_domain::user::{Password, User, UserName};
use std::fmt;

/// Errors returned when calling methods on [`ResourceOwnerAuthenticator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceOwnerAuthenticatorError {
    /// Authentication failed because the username or password was incorrect.
    ///
    /// For security reasons, the error does not indicate which one was wrong.
    AuthenticateError,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for ResourceOwnerAuthenticatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceOwnerAuthenticatorError::AuthenticateError => {
                write!(f, "user not authenticated")
            }
            ResourceOwnerAuthenticatorError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for ResourceOwnerAuthenticatorError {}

/// Port that abstracts password authentication for resource owners (end users).
///
/// Used by the password grant (RFC 6749 Section 4.3).
/// Username and password validation logic is delegated to the implementation
/// (infrastructure layer), so it can support hash verification, external LDAP
/// integration, MFA, and other authentication backends.
///
/// # Security considerations
///
/// [`AuthenticateError`] does not distinguish whether the username or password was wrong.
/// This prevents user enumeration attacks.
///
/// # Methods
///
/// - [`authenticate_with_password`] — Authenticate with a username and password; returns a [`User`] on success.
///
/// [`AuthenticateError`]: ResourceOwnerAuthenticatorError::AuthenticateError
/// [`authenticate_with_password`]: ResourceOwnerAuthenticator::authenticate_with_password
#[async_trait::async_trait]
pub trait ResourceOwnerAuthenticator {
    /// Authenticate a resource owner with a username and password.
    ///
    /// Returns the corresponding [`User`] on success.
    ///
    /// # Errors
    ///
    /// - [`ResourceOwnerAuthenticatorError::AuthenticateError`] — The username or password was incorrect.
    /// - [`ResourceOwnerAuthenticatorError::UnknownError`] — An unexpected error occurred in the authentication backend.
    async fn authenticate_with_password(
        &self,
        user_name: &UserName,
        password: &Password,
    ) -> Result<User, ResourceOwnerAuthenticatorError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_error_display() {
        assert_eq!(
            ResourceOwnerAuthenticatorError::AuthenticateError.to_string(),
            "user not authenticated"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            ResourceOwnerAuthenticatorError::UnknownError("ldap down".to_string()).to_string(),
            "unknown error: ldap down"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            ResourceOwnerAuthenticatorError::AuthenticateError,
            ResourceOwnerAuthenticatorError::AuthenticateError
        );
        assert_ne!(
            ResourceOwnerAuthenticatorError::AuthenticateError,
            ResourceOwnerAuthenticatorError::UnknownError("x".to_string())
        );
        assert_eq!(
            ResourceOwnerAuthenticatorError::UnknownError("y".to_string()),
            ResourceOwnerAuthenticatorError::UnknownError("y".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error =
            &ResourceOwnerAuthenticatorError::AuthenticateError;
        assert_eq!(err.to_string(), "user not authenticated");
    }

    #[test]
    fn error_is_cloneable() {
        let original = ResourceOwnerAuthenticatorError::AuthenticateError;
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn trait_returns_authenticate_error_on_wrong_password() {
        use komainu_domain::value_object::{SecretValueObject, ValueObject};

        struct AlwaysFail;

        #[async_trait::async_trait]
        impl ResourceOwnerAuthenticator for AlwaysFail {
            async fn authenticate_with_password(
                &self,
                _user_name: &UserName,
                _password: &Password,
            ) -> Result<User, ResourceOwnerAuthenticatorError> {
                Err(ResourceOwnerAuthenticatorError::AuthenticateError)
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let auth = AlwaysFail;
            let user_name = UserName::new("alice".to_string()).unwrap();
            let password = Password::new("wrong-password".to_string()).unwrap();
            let result = auth.authenticate_with_password(&user_name, &password).await;
            assert_eq!(
                result.unwrap_err(),
                ResourceOwnerAuthenticatorError::AuthenticateError
            );
        });
    }

    #[test]
    fn trait_returns_user_on_success() {
        use komainu_domain::{
            user::{UserId, User},
            value_object::{SecretValueObject, ValueObject},
        };

        struct AlwaysOk;

        #[async_trait::async_trait]
        impl ResourceOwnerAuthenticator for AlwaysOk {
            async fn authenticate_with_password(
                &self,
                user_name: &UserName,
                _password: &Password,
            ) -> Result<User, ResourceOwnerAuthenticatorError> {
                Ok(User::new(
                    UserId::new("user-1".to_string()).unwrap(),
                    user_name.clone(),
                    None,
                ))
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let auth = AlwaysOk;
            let user_name = UserName::new("alice".to_string()).unwrap();
            let password = Password::new("correct-password".to_string()).unwrap();
            let user = auth
                .authenticate_with_password(&user_name, &password)
                .await
                .unwrap();
            assert_eq!(user.user_name().value(), "alice");
        });
    }
}
