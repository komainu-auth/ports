use std::fmt;

use komainu_domain::{
    code::AuthorizationCode,
    token::{AccessToken, RefreshToken},
};

/// Errors returned when calling methods on [`TokenGenerator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenGeneratorError {
    /// An unexpected error, such as a random number generator failure. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for TokenGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenGeneratorError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for TokenGeneratorError {}

/// Port that abstracts generation of tokens and authorization codes.
///
/// The application layer generates authorization codes, access tokens, and
/// refresh tokens through this trait.
/// Concrete generation algorithms (UUID, CSPRNG, JWT, and so on) are implemented
/// in the infrastructure layer.
///
/// # Testability
///
/// During tests, swap in an implementation that returns predictable fixed values
/// to stabilize assertions that depend on token values.
///
/// # Methods
///
/// - [`generate_code`] — Generate an authorization code.
/// - [`generate_access_token`] — Generate an access token.
/// - [`generate_refresh_token`] — Generate a refresh token.
///
/// [`generate_code`]: TokenGenerator::generate_code
/// [`generate_access_token`]: TokenGenerator::generate_access_token
/// [`generate_refresh_token`]: TokenGenerator::generate_refresh_token
pub trait TokenGenerator {
    /// Generate and return an authorization code ([`AuthorizationCode`]).
    ///
    /// # Errors
    ///
    /// - [`TokenGeneratorError::UnknownError`] — Random number generation or a similar step failed.
    fn generate_code(&self) -> Result<AuthorizationCode, TokenGeneratorError>;

    /// Generate and return an access token ([`AccessToken`]).
    ///
    /// # Errors
    ///
    /// - [`TokenGeneratorError::UnknownError`] — Random number generation or a similar step failed.
    fn generate_access_token(&self) -> Result<AccessToken, TokenGeneratorError>;

    /// Generate and return a refresh token ([`RefreshToken`]).
    ///
    /// # Errors
    ///
    /// - [`TokenGeneratorError::UnknownError`] — Random number generation or a similar step failed.
    fn generate_refresh_token(&self) -> Result<RefreshToken, TokenGeneratorError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use komainu_domain::value_object::SecretValueObject;

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            TokenGeneratorError::UnknownError("rng failed".to_string()).to_string(),
            "unknown error: rng failed"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            TokenGeneratorError::UnknownError("a".to_string()),
            TokenGeneratorError::UnknownError("a".to_string())
        );
        assert_ne!(
            TokenGeneratorError::UnknownError("a".to_string()),
            TokenGeneratorError::UnknownError("b".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error =
            &TokenGeneratorError::UnknownError("oops".to_string());
        assert_eq!(err.to_string(), "unknown error: oops");
    }

    #[test]
    fn error_is_cloneable() {
        let original = TokenGeneratorError::UnknownError("err".to_string());
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn generate_code_returns_fixed_value() {
        struct FixedGenerator;

        impl TokenGenerator for FixedGenerator {
            fn generate_code(&self) -> Result<AuthorizationCode, TokenGeneratorError> {
                Ok(AuthorizationCode::new("fixed-code".to_string()).unwrap())
            }
            fn generate_access_token(&self) -> Result<AccessToken, TokenGeneratorError> {
                Ok(AccessToken::new("fixed-access".to_string()).unwrap())
            }
            fn generate_refresh_token(&self) -> Result<RefreshToken, TokenGeneratorError> {
                Ok(RefreshToken::new("fixed-refresh".to_string()).unwrap())
            }
        }

        let generator = FixedGenerator;
        let code = generator.generate_code().unwrap();
        assert_eq!(code.expose_secret(), "fixed-code");
    }

    #[test]
    fn generate_access_token_returns_fixed_value() {
        struct FixedGenerator;

        impl TokenGenerator for FixedGenerator {
            fn generate_code(&self) -> Result<AuthorizationCode, TokenGeneratorError> {
                Ok(AuthorizationCode::new("fixed-code".to_string()).unwrap())
            }
            fn generate_access_token(&self) -> Result<AccessToken, TokenGeneratorError> {
                Ok(AccessToken::new("fixed-access".to_string()).unwrap())
            }
            fn generate_refresh_token(&self) -> Result<RefreshToken, TokenGeneratorError> {
                Ok(RefreshToken::new("fixed-refresh".to_string()).unwrap())
            }
        }

        let generator = FixedGenerator;
        let token = generator.generate_access_token().unwrap();
        assert_eq!(token.expose_secret(), "fixed-access");
    }

    #[test]
    fn generate_refresh_token_returns_fixed_value() {
        struct FixedGenerator;

        impl TokenGenerator for FixedGenerator {
            fn generate_code(&self) -> Result<AuthorizationCode, TokenGeneratorError> {
                Ok(AuthorizationCode::new("fixed-code".to_string()).unwrap())
            }
            fn generate_access_token(&self) -> Result<AccessToken, TokenGeneratorError> {
                Ok(AccessToken::new("fixed-access".to_string()).unwrap())
            }
            fn generate_refresh_token(&self) -> Result<RefreshToken, TokenGeneratorError> {
                Ok(RefreshToken::new("fixed-refresh".to_string()).unwrap())
            }
        }

        let generator = FixedGenerator;
        let token = generator.generate_refresh_token().unwrap();
        assert_eq!(token.expose_secret(), "fixed-refresh");
    }

    #[test]
    fn generate_code_returns_error_on_failure() {
        struct AlwaysFail;

        impl TokenGenerator for AlwaysFail {
            fn generate_code(&self) -> Result<AuthorizationCode, TokenGeneratorError> {
                Err(TokenGeneratorError::UnknownError("rng unavailable".to_string()))
            }
            fn generate_access_token(&self) -> Result<AccessToken, TokenGeneratorError> {
                Err(TokenGeneratorError::UnknownError("rng unavailable".to_string()))
            }
            fn generate_refresh_token(&self) -> Result<RefreshToken, TokenGeneratorError> {
                Err(TokenGeneratorError::UnknownError("rng unavailable".to_string()))
            }
        }

        let generator = AlwaysFail;
        assert_eq!(
            generator.generate_code().unwrap_err(),
            TokenGeneratorError::UnknownError("rng unavailable".to_string())
        );
        assert_eq!(
            generator.generate_access_token().unwrap_err(),
            TokenGeneratorError::UnknownError("rng unavailable".to_string())
        );
        assert_eq!(
            generator.generate_refresh_token().unwrap_err(),
            TokenGeneratorError::UnknownError("rng unavailable".to_string())
        );
    }
}
