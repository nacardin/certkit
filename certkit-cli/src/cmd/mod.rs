//! Subcommand implementations.
//!
//! Each submodule defines one subcommand's options struct (`#[derive(Args)]`)
//! and an `execute(&self) -> Result<()>` method holding that command's logic.
//! [`crate::Command`] wraps these options structs and dispatches to `execute`.

pub mod inspect;
pub mod issue;
pub mod keygen;
pub mod self_signed;
