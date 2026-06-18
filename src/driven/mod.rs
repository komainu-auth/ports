//! # Driven ports (secondary ports)
//!
//! Defines the traits used by the application core to access external resources
//! (databases, caches, external authentication services, and so on).
//!
//! These correspond to the driven side (right side) of hexagonal architecture.
//! The application layer depends on these traits to stay decoupled from concrete
//! infrastructure implementations.
//!
//! ## Included ports
//!
//! | Module | Trait | Role |
//! |---|---|---|
//! | `access_token_repository` | [`AccessTokenRepository`] | Persist and look up access tokens |
//! | `authorization_code_repository` | [`AuthorizationCodeRepository`] | Issue and consume authorization codes |
//! | `client_repository` | [`ClientRepository`] | Persist and look up OAuth clients |
//! | `clock` | [`Clock`] | Obtain the current time and compute expirations |
//! | `refresh_token_repository` | [`RefreshTokenRepository`] | Persist and consume refresh tokens |
//! | `resource_owner_authenticator` | [`ResourceOwnerAuthenticator`] | Authenticate resource owners by password |
//! | `session_store` | [`SessionStore`] | Create, look up, and delete sessions |
//! | `token_generator` | [`TokenGenerator`] | Generate tokens and codes |
//! | `user_repository` | [`UserRepository`] | Persist and look up users |

mod access_token_repository;
mod authorization_code_repository;
mod client_repository;
mod clock;
mod refresh_token_repository;
mod resource_owner_authenticator;
mod session_store;
mod token_generator;
mod user_repository;

pub use access_token_repository::*;
pub use authorization_code_repository::*;
pub use client_repository::*;
pub use clock::*;
pub use refresh_token_repository::*;
pub use resource_owner_authenticator::*;
pub use session_store::*;
pub use token_generator::*;
pub use user_repository::*;
