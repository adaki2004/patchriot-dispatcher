//! One approved homepage and its declared script origins. Collection never runs
//! JavaScript, follows redirects, accepts credentials or grants agents networking.
//! Callers must approve authority and bound admission before calling `collect`.

mod collector;
mod scope;

pub use collector::{CollectionError, collect};
pub use scope::normalize_scope;
