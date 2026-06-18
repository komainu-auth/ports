use std::fmt;

use komainu_domain::user::{User, UserName};

/// Errors returned when calling methods on [`UserRepository`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserRepositoryError {
    /// No user exists with the given username.
    NotFound,
    /// A user with the same username already exists.
    AlreadyExists,
    /// An unexpected error other than those above. See the message for details.
    UnknownError(String),
}

impl std::fmt::Display for UserRepositoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRepositoryError::NotFound => write!(f, "user not found"),
            UserRepositoryError::AlreadyExists => write!(f, "user already exists"),
            UserRepositoryError::UnknownError(s) => write!(f, "unknown error: {s}"),
        }
    }
}

impl std::error::Error for UserRepositoryError {}

/// Repository port that abstracts persistence and lookup of users (resource owners).
///
/// The application layer reads and writes users through this trait.
/// Used for user registration, password authentication, profile updates, and similar flows.
///
/// # Methods
///
/// - [`find_by_username`] — Look up a [`User`] by username.
/// - [`save`] — Persist a [`User`] (used for both registration and updates).
///
/// [`find_by_username`]: UserRepository::find_by_username
/// [`save`]: UserRepository::save
#[async_trait::async_trait]
pub trait UserRepository {
    /// Look up a [`User`] by username.
    ///
    /// Used for user lookup in the password grant, among other flows.
    ///
    /// # Errors
    ///
    /// - [`UserRepositoryError::NotFound`] — No matching user exists.
    /// - [`UserRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn find_by_username(&self, user_name: &UserName) -> Result<User, UserRepositoryError>;

    /// Persist a [`User`].
    ///
    /// Used for new user registration and for updating usernames and password hashes.
    ///
    /// # Errors
    ///
    /// - [`UserRepositoryError::AlreadyExists`] — A user with the same username already exists.
    /// - [`UserRepositoryError::UnknownError`] — An unexpected error occurred in the storage layer.
    async fn save(&self, user: &User) -> Result<(), UserRepositoryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_found_display() {
        assert_eq!(UserRepositoryError::NotFound.to_string(), "user not found");
    }

    #[test]
    fn already_exists_display() {
        assert_eq!(
            UserRepositoryError::AlreadyExists.to_string(),
            "user already exists"
        );
    }

    #[test]
    fn unknown_error_display() {
        assert_eq!(
            UserRepositoryError::UnknownError("db error".to_string()).to_string(),
            "unknown error: db error"
        );
    }

    #[test]
    fn error_variants_are_equal_by_value() {
        assert_eq!(
            UserRepositoryError::NotFound,
            UserRepositoryError::NotFound
        );
        assert_ne!(
            UserRepositoryError::NotFound,
            UserRepositoryError::AlreadyExists
        );
        assert_eq!(
            UserRepositoryError::UnknownError("e".to_string()),
            UserRepositoryError::UnknownError("e".to_string())
        );
    }

    #[test]
    fn error_implements_std_error() {
        let err: &dyn std::error::Error = &UserRepositoryError::NotFound;
        assert_eq!(err.to_string(), "user not found");
    }

    #[test]
    fn error_is_cloneable() {
        let original = UserRepositoryError::AlreadyExists;
        assert_eq!(original.clone(), original);
    }

    #[test]
    fn trait_find_by_username_returns_not_found() {
        use komainu_domain::value_object::ValueObject;

        struct AlwaysNotFound;

        #[async_trait::async_trait]
        impl UserRepository for AlwaysNotFound {
            async fn find_by_username(
                &self,
                _user_name: &UserName,
            ) -> Result<User, UserRepositoryError> {
                Err(UserRepositoryError::NotFound)
            }
            async fn save(&self, _user: &User) -> Result<(), UserRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysNotFound;
            let name = UserName::new("alice".to_string()).unwrap();
            let result = repo.find_by_username(&name).await;
            assert_eq!(result.unwrap_err(), UserRepositoryError::NotFound);
        });
    }

    #[test]
    fn trait_save_returns_ok() {
        use komainu_domain::{
            user::UserId,
            value_object::ValueObject,
        };

        struct AlwaysOk;

        #[async_trait::async_trait]
        impl UserRepository for AlwaysOk {
            async fn find_by_username(
                &self,
                _user_name: &UserName,
            ) -> Result<User, UserRepositoryError> {
                Err(UserRepositoryError::NotFound)
            }
            async fn save(&self, _user: &User) -> Result<(), UserRepositoryError> {
                Ok(())
            }
        }

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let repo = AlwaysOk;
            let user = User::new(
                UserId::new("user-1".to_string()).unwrap(),
                UserName::new("alice".to_string()).unwrap(),
                None,
            );
            assert!(repo.save(&user).await.is_ok());
        });
    }
}
