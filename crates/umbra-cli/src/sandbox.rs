//! Process sandboxing for the Linux client (TODO A.4, ADR-007):
//! Landlock LSM with a zero-access filesystem ruleset.

use landlock::{ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr};

use crate::cli::CliError;

/// Restricts the process to **zero filesystem access** (CLIENT_SECURITY:
/// "Landlock zero file system access"; ADR-007).
///
/// All filesystem `AccessFs` rights are handled but no `path_beneath` rule
/// is added, so every path becomes inaccessible. Already-open file
/// descriptors (stdin/stdout/TTY) keep working: Landlock restricts new
/// path operations only.
///
/// Fail-closed by design: `CompatLevel::HardRequirement` makes the ruleset
/// error out unless the running kernel enforces the full request — an
/// old kernel degrades the CLI to refusing to start rather than running
/// with a weaker sandbox.
///
/// # Errors
///
/// Returns [`CliError::Sandbox`] if the ruleset cannot be created or is
/// not fully enforced by the kernel.
pub fn restrict_filesystem() -> Result<landlock::RestrictionStatus, CliError> {
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V5))?
        .create()?
        .restrict_self()?;
    Ok(status)
}
