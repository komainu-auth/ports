use komainu_domain::{
    client::{ClientId, ClientSecret},
    error::OAuthError,
    request::TokenRequest,
    token::IssuedToken,
};

/// Client authentication credentials accompanying a token endpoint request.
///
/// Supports the client authentication methods defined in RFC 6749 Section 2.3.
/// The authentication method is determined before accepting the request and passed
/// to the application layer as part of [`TokenIncome`].
///
/// # Variants
///
/// | Variant | Authentication method | RFC reference |
/// |---|---|---|
/// | [`Basic`] | HTTP Basic authentication header (`Authorization: Basic ...`) | RFC 6749 Section 2.3.1 |
/// | [`Post`] | Request body parameters (`client_id` / `client_secret`) | RFC 6749 Section 2.3.1 |
/// | [`None`] | No authentication (public client or no credentials) | RFC 6749 Section 2.1 |
///
/// [`Basic`]: TokenRequestCredential::Basic
/// [`Post`]: TokenRequestCredential::Post
/// [`None`]: TokenRequestCredential::None
#[derive(Debug, Clone)]
pub enum TokenRequestCredential {
    /// Client authentication via HTTP Basic authentication.
    Basic {
        client_id: ClientId,
        client_secret: ClientSecret,
    },
    /// Client authentication via request body parameters.
    Post {
        client_id: ClientId,
        client_secret: ClientSecret,
    },
    /// No credentials. Used for public clients or flows that do not require authentication.
    None,
}

/// Input object bundling a request to the token endpoint (RFC 6749 Section 3.2).
///
/// `request` is a [`TokenRequest`] built from the request body, and `credential`
/// is the client authentication information accompanying the request.
/// Extracting client authentication is the responsibility of the infrastructure
/// layer; the application layer receives this object and performs authentication
/// and token issuance.
///
/// # Fields
///
/// - `request` — Token request parameters (`grant_type`, and so on)
/// - `credential` — Client authentication information (Basic, Post, or None)
#[derive(Debug, Clone)]
pub struct TokenIncome {
    request: TokenRequest,
    credential: TokenRequestCredential,
}

impl TokenIncome {
    /// Creates a [`TokenIncome`] from a token request and client authentication credentials.
    pub fn new(request: TokenRequest, credential: TokenRequestCredential) -> Self {
        Self {
            request,
            credential,
        }
    }

    /// Returns a reference to the token request.
    pub fn request(&self) -> &TokenRequest {
        &self.request
    }

    /// Returns a reference to the client authentication credentials.
    pub fn credential(&self) -> &TokenRequestCredential {
        &self.credential
    }
}

/// Driving port abstracting token endpoint request handling.
///
/// The infrastructure layer (web framework handlers, and so on) delegates
/// token issuance to the application layer through this trait.
///
/// # Processing flow
///
/// 1. Authenticate the client (validate [`TokenRequestCredential`])
/// 2. Validate and process according to grant type
///    - `authorization_code` — Validate and consume authorization code, issue tokens
///    - `password` — Authenticate user, issue tokens
///    - `client_credentials` — Issue tokens for the client only
///    - `refresh_token` — Consume refresh token and issue new tokens
/// 3. Return [`IssuedToken`]
///
/// # Errors
///
/// OAuth errors encountered during processing are returned as [`OAuthError`].
/// Common error codes:
///
/// - `invalid_client` — Client authentication failed
/// - `invalid_grant` — Authorization code or refresh token is invalid or expired
/// - `unsupported_grant_type` — Unsupported grant type
/// - `invalid_scope` — Invalid scope
///
/// # Methods
///
/// - [`process`] — Process a token request and return [`IssuedToken`] on success.
///
/// [`process`]: TokenService::process
#[async_trait::async_trait]
pub trait TokenService {
    /// Processes a token request and returns [`IssuedToken`] on success.
    ///
    /// # Errors
    ///
    /// - [`OAuthError`] — Client authentication failure, invalid grant, unsupported grant type, and so on
    async fn process(&self, income: TokenIncome) -> Result<IssuedToken, OAuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use komainu_domain::{
        GrantType, Scope,
        error::OAuthErrorCode,
        token::{AccessToken, RefreshToken, TokenType},
        user::UserName,
        value_object::{SecretValueObject, ValueObject},
    };
    use std::time::Duration;

    fn client_id() -> ClientId {
        ClientId::new("client-1".to_string()).unwrap()
    }
    fn client_secret() -> ClientSecret {
        ClientSecret::new("secret-value".to_string()).unwrap()
    }
    fn issued_token() -> IssuedToken {
        IssuedToken::new(
            AccessToken::new("at-value".to_string()).unwrap(),
            TokenType::Bearer,
            Duration::from_secs(3600),
            Some(RefreshToken::new("rt-value".to_string()).unwrap()),
            Some(Scope::new("read".to_string()).unwrap()),
        )
    }

    // ---- TokenRequestCredential ----

    #[test]
    fn basic_credential_holds_client_id_and_secret() {
        let cred = TokenRequestCredential::Basic {
            client_id: client_id(),
            client_secret: client_secret(),
        };
        if let TokenRequestCredential::Basic {
            client_id: id,
            client_secret: secret,
        } = cred
        {
            assert_eq!(id.value(), "client-1");
            assert_eq!(secret.expose_secret(), "secret-value");
        } else {
            panic!("expected Basic variant");
        }
    }

    #[test]
    fn post_credential_holds_client_id_and_secret() {
        let cred = TokenRequestCredential::Post {
            client_id: client_id(),
            client_secret: client_secret(),
        };
        if let TokenRequestCredential::Post {
            client_id: id,
            client_secret: secret,
        } = cred
        {
            assert_eq!(id.value(), "client-1");
            assert_eq!(secret.expose_secret(), "secret-value");
        } else {
            panic!("expected Post variant");
        }
    }

    #[test]
    fn none_credential_is_unit_like() {
        let cred = TokenRequestCredential::None;
        assert!(matches!(cred, TokenRequestCredential::None));
    }

    // ---- TokenIncome ----

    #[test]
    fn income_getters_return_constructor_values_for_password_grant() {
        let request = TokenRequest::new_password(
            UserName::new("alice".to_string()).unwrap(),
            "pw".to_string(),
            None,
        );
        let credential = TokenRequestCredential::None;
        let income = TokenIncome::new(request, credential);

        assert_eq!(income.request().grant_type(), &GrantType::Password);
        assert!(matches!(income.credential(), TokenRequestCredential::None));
    }

    #[test]
    fn income_getters_return_constructor_values_for_client_credentials_grant() {
        let request = TokenRequest::new_client_credentials(None);
        let credential = TokenRequestCredential::Basic {
            client_id: client_id(),
            client_secret: client_secret(),
        };
        let income = TokenIncome::new(request, credential);

        assert_eq!(
            income.request().grant_type(),
            &GrantType::ClientCredentials
        );
        assert!(matches!(
            income.credential(),
            TokenRequestCredential::Basic { .. }
        ));
    }

    // ---- TokenService trait ----

    #[test]
    fn service_returns_issued_token_on_success() {
        struct AlwaysOkService;

        #[async_trait::async_trait]
        impl TokenService for AlwaysOkService {
            async fn process(&self, _income: TokenIncome) -> Result<IssuedToken, OAuthError> {
                Ok(issued_token())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = AlwaysOkService;
            let request = TokenRequest::new_client_credentials(None);
            let income = TokenIncome::new(request, TokenRequestCredential::None);
            let token = svc.process(income).await.unwrap();
            assert_eq!(token.access_token().expose_secret(), "at-value");
            assert_eq!(token.token_type(), &TokenType::Bearer);
            assert_eq!(token.expires_in(), &Duration::from_secs(3600));
            assert_eq!(
                token.refresh_token().unwrap().expose_secret(),
                "rt-value"
            );
            assert_eq!(token.scope().unwrap().value(), "read");
        });
    }

    #[test]
    fn service_returns_invalid_client_error_on_auth_failure() {
        struct InvalidClientService;

        #[async_trait::async_trait]
        impl TokenService for InvalidClientService {
            async fn process(&self, _income: TokenIncome) -> Result<IssuedToken, OAuthError> {
                Err(OAuthError::new(OAuthErrorCode::InvalidClient, None, None))
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = InvalidClientService;
            let request = TokenRequest::new_client_credentials(None);
            let income = TokenIncome::new(request, TokenRequestCredential::None);
            let err = svc.process(income).await.unwrap_err();
            assert_eq!(err.error(), &OAuthErrorCode::InvalidClient);
        });
    }

    #[test]
    fn service_returns_invalid_grant_error_for_expired_code() {
        struct ExpiredCodeService;

        #[async_trait::async_trait]
        impl TokenService for ExpiredCodeService {
            async fn process(&self, _income: TokenIncome) -> Result<IssuedToken, OAuthError> {
                Err(OAuthError::new(
                    OAuthErrorCode::InvalidGrant,
                    Some("authorization code expired".to_string()),
                    None,
                ))
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = ExpiredCodeService;
            let request = TokenRequest::new_authorization_code(
                komainu_domain::code::AuthorizationCode::new("expired-code".to_string()).unwrap(),
                None,
                None,
            );
            let income = TokenIncome::new(request, TokenRequestCredential::None);
            let err = svc.process(income).await.unwrap_err();
            assert_eq!(err.error(), &OAuthErrorCode::InvalidGrant);
            assert_eq!(
                err.error_description(),
                Some(&"authorization code expired".to_string())
            );
        });
    }

    #[test]
    fn service_returns_unsupported_grant_type_error() {
        struct UnsupportedService;

        #[async_trait::async_trait]
        impl TokenService for UnsupportedService {
            async fn process(&self, _income: TokenIncome) -> Result<IssuedToken, OAuthError> {
                Err(OAuthError::new(
                    OAuthErrorCode::UnsupportedGrantType,
                    None,
                    None,
                ))
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = UnsupportedService;
            let request = TokenRequest::new_password(
                UserName::new("alice".to_string()).unwrap(),
                "pw".to_string(),
                None,
            );
            let income = TokenIncome::new(request, TokenRequestCredential::None);
            let err = svc.process(income).await.unwrap_err();
            assert_eq!(err.error(), &OAuthErrorCode::UnsupportedGrantType);
        });
    }
}
