//! # Driving ports (primary ports)
//!
//! Defines the traits used when external actors (HTTP requests, CLI, and so on)
//! invoke the application core.
//!
//! These correspond to the driving side (left side) of hexagonal architecture.
//! The infrastructure layer (web frameworks, controllers, and so on) calls into
//! the application layer through these traits.
//!
//! ## Included ports
//!
//! | Module | Trait | Role |
//! |---|---|---|
//! | `authorization` | [`AuthorizationService`] | Handle authorization endpoint requests |
//! | `token` | [`TokenService`] | Handle token endpoint requests |
//!
//! [`AuthorizationService`]: authorization::AuthorizationService
//! [`TokenService`]: token::TokenService

pub mod authorization;
pub mod token;
