use komainu_domain::{Scope, error::OAuthError, request::AuthorizationRequest};

use crate::driven::SessionId;

/// Input object bundling a request to the authorization endpoint (RFC 6749 Section 3.1).
///
/// `request` is an [`AuthorizationRequest`] built from query parameters, and
/// `session_id` indicates whether the requesting browser already has an existing
/// session. It is `None` when no session exists.
///
/// # Fields
///
/// - `request` — Authorization request parameters (`response_type`, `client_id`, and so on)
/// - `session_id` — Existing session ID for the requester (`None` when not logged in)
#[derive(Debug, Clone)]
pub struct AuthorizationIncome {
    request: AuthorizationRequest,
    session_id: Option<SessionId>,
}

impl AuthorizationIncome {
    /// Creates an [`AuthorizationIncome`] from an authorization request and session ID.
    pub fn new(request: AuthorizationRequest, session_id: Option<SessionId>) -> Self {
        Self {
            request,
            session_id,
        }
    }

    /// Returns a reference to the authorization request.
    pub fn request(&self) -> &AuthorizationRequest {
        &self.request
    }

    /// Returns a reference to the session ID, or `None` when no session exists.
    pub fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }
}

/// Outcome of authorization endpoint processing.
///
/// Returned by [`AuthorizationService::process`]; the infrastructure layer
/// (controller) generates a response based on this value.
///
/// # Variants
///
/// | Variant | Situation | Example infrastructure response |
/// |---|---|---|
/// | [`Redirect`] | Authentication and consent complete; return an authorization code via redirect | 302 redirect |
/// | [`LoginRequired`] | No session, or login is required | Redirect to login page |
/// | [`ConsentRequired`] | Logged in but consent screen is required | Show consent screen |
/// | [`ErrorRedirect`] | Return an error via redirect URI query parameters (RFC 6749 Section 4.1.2.1) | 302 redirect |
/// | [`ErrorPage`] | Critical error that cannot be redirected (invalid `redirect_uri`, and so on) | Show error page |
///
/// [`Redirect`]: AuthorizationOutcome::Redirect
/// [`LoginRequired`]: AuthorizationOutcome::LoginRequired
/// [`ConsentRequired`]: AuthorizationOutcome::ConsentRequired
/// [`ErrorRedirect`]: AuthorizationOutcome::ErrorRedirect
/// [`ErrorPage`]: AuthorizationOutcome::ErrorPage
#[derive(Debug, Clone)]
pub enum AuthorizationOutcome {
    /// Return an authorization code or token via redirect. `url` is the full redirect URI.
    Redirect { url: String },
    /// User login is required. Redirect to the login screen.
    LoginRequired,
    /// Logged in but consent for scopes is required. `scopes` lists the scopes to request consent for.
    ConsentRequired { scopes: Vec<Scope> },
    /// Redirect with error information in query parameters. `url` is the full redirect URI.
    ErrorRedirect { url: String },
    /// Critical error that cannot be sent to a redirect target. Display `error` as a page.
    ErrorPage { error: OAuthError },
}

/// Driving port abstracting authorization endpoint request handling.
///
/// The infrastructure layer (web framework handlers, and so on) delegates
/// authorization processing to the application layer through this trait.
///
/// # Processing flow
///
/// 1. Check session → return [`AuthorizationOutcome::LoginRequired`] if no session
/// 2. Validate client → return [`AuthorizationOutcome::ErrorPage`] for invalid clients
/// 3. Check login → return [`AuthorizationOutcome::LoginRequired`] if not logged in
/// 4. Check consent → return [`AuthorizationOutcome::ConsentRequired`] if consent is needed
/// 5. Issue authorization code → return redirect URI via [`AuthorizationOutcome::Redirect`]
///
/// # Methods
///
/// - [`process`] — Process an authorization request and return the outcome.
///
/// [`process`]: AuthorizationService::process
#[async_trait::async_trait]
pub trait AuthorizationService {
    /// Processes an authorization request and returns an [`AuthorizationOutcome`].
    async fn process(&self, income: AuthorizationIncome) -> AuthorizationOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;
    use komainu_domain::{
        ResponseType,
        client::ClientId,
        error::OAuthErrorCode,
        value_object::ValueObject,
    };

    fn client_id() -> ClientId {
        ClientId::new("client-1".to_string()).unwrap()
    }
    fn session_id() -> SessionId {
        SessionId::new("sess-abc".to_string()).unwrap()
    }
    fn auth_request() -> AuthorizationRequest {
        AuthorizationRequest::new(ResponseType::Code, client_id(), None, None, None)
    }

    // ---- AuthorizationIncome ----

    #[test]
    fn income_getters_return_constructor_values() {
        let income = AuthorizationIncome::new(auth_request(), Some(session_id()));
        assert_eq!(income.request().client_id(), &client_id());
        assert_eq!(income.session_id(), Some(&session_id()));
    }

    #[test]
    fn income_session_id_can_be_absent() {
        let income = AuthorizationIncome::new(auth_request(), None);
        assert!(income.session_id().is_none());
    }

    // ---- AuthorizationOutcome ----

    #[test]
    fn redirect_variant_holds_url() {
        let outcome = AuthorizationOutcome::Redirect {
            url: "https://example.com/cb?code=abc".to_string(),
        };
        if let AuthorizationOutcome::Redirect { url } = outcome {
            assert_eq!(url, "https://example.com/cb?code=abc");
        } else {
            panic!("expected Redirect variant");
        }
    }

    #[test]
    fn login_required_variant_is_unit_like() {
        let outcome = AuthorizationOutcome::LoginRequired;
        assert!(matches!(outcome, AuthorizationOutcome::LoginRequired));
    }

    #[test]
    fn consent_required_variant_holds_scopes() {
        let scopes = vec![
            Scope::new("read".to_string()).unwrap(),
            Scope::new("write".to_string()).unwrap(),
        ];
        let outcome = AuthorizationOutcome::ConsentRequired {
            scopes: scopes.clone(),
        };
        if let AuthorizationOutcome::ConsentRequired { scopes: s } = outcome {
            assert_eq!(s.len(), 2);
            assert_eq!(s[0].value(), "read");
            assert_eq!(s[1].value(), "write");
        } else {
            panic!("expected ConsentRequired variant");
        }
    }

    #[test]
    fn error_redirect_variant_holds_url() {
        let outcome = AuthorizationOutcome::ErrorRedirect {
            url: "https://example.com/cb?error=access_denied".to_string(),
        };
        if let AuthorizationOutcome::ErrorRedirect { url } = outcome {
            assert!(url.contains("access_denied"));
        } else {
            panic!("expected ErrorRedirect variant");
        }
    }

    #[test]
    fn error_page_variant_holds_oauth_error() {
        let error = OAuthError::new(OAuthErrorCode::InvalidRequest, None, None);
        let outcome = AuthorizationOutcome::ErrorPage {
            error: error.clone(),
        };
        if let AuthorizationOutcome::ErrorPage { error: e } = outcome {
            assert_eq!(e.error(), &OAuthErrorCode::InvalidRequest);
        } else {
            panic!("expected ErrorPage variant");
        }
    }

    // ---- AuthorizationService trait ----

    #[test]
    fn service_returns_login_required_when_no_session() {
        struct RequireLoginService;

        #[async_trait::async_trait]
        impl AuthorizationService for RequireLoginService {
            async fn process(&self, income: AuthorizationIncome) -> AuthorizationOutcome {
                if income.session_id().is_none() {
                    AuthorizationOutcome::LoginRequired
                } else {
                    AuthorizationOutcome::Redirect {
                        url: "https://example.com/cb?code=xyz".to_string(),
                    }
                }
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = RequireLoginService;
            let income = AuthorizationIncome::new(auth_request(), None);
            let outcome = svc.process(income).await;
            assert!(matches!(outcome, AuthorizationOutcome::LoginRequired));
        });
    }

    #[test]
    fn service_returns_redirect_when_session_present() {
        struct AlwaysRedirectService;

        #[async_trait::async_trait]
        impl AuthorizationService for AlwaysRedirectService {
            async fn process(&self, _income: AuthorizationIncome) -> AuthorizationOutcome {
                AuthorizationOutcome::Redirect {
                    url: "https://example.com/cb?code=code-123".to_string(),
                }
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = AlwaysRedirectService;
            let income = AuthorizationIncome::new(auth_request(), Some(session_id()));
            let outcome = svc.process(income).await;
            if let AuthorizationOutcome::Redirect { url } = outcome {
                assert!(url.contains("code=code-123"));
            } else {
                panic!("expected Redirect variant");
            }
        });
    }

    #[test]
    fn service_returns_error_page_on_invalid_request() {
        struct AlwaysErrorService;

        #[async_trait::async_trait]
        impl AuthorizationService for AlwaysErrorService {
            async fn process(&self, _income: AuthorizationIncome) -> AuthorizationOutcome {
                AuthorizationOutcome::ErrorPage {
                    error: OAuthError::new(OAuthErrorCode::InvalidRequest, None, None),
                }
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let svc = AlwaysErrorService;
            let income = AuthorizationIncome::new(auth_request(), None);
            let outcome = svc.process(income).await;
            if let AuthorizationOutcome::ErrorPage { error } = outcome {
                assert_eq!(error.error(), &OAuthErrorCode::InvalidRequest);
            } else {
                panic!("expected ErrorPage variant");
            }
        });
    }
}
