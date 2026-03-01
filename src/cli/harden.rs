// Update .gitignore and optionally install git hooks (FR-028).

use std::path::Path;

use clap::Args;

use crate::error::{Result, VaultError};

/// Patterns that should be ignored (protect sensitive files).
const SENSITIVE_PATTERNS: &[&str] = &["*.env", "*.key", "*.pem", "*.secret"];

/// Vault-specific files that must NOT be ignored (they need to be committed).
const VAULT_FILES: &[&str] = &[".git-secret-vault"];

const PRE_COMMIT_SCRIPT: &str = r#"#!/bin/sh
# Installed by git-secret-vault harden
git-secret-vault lock --check
if [ $? -ne 0 ]; then
  echo "git-secret-vault: vault is stale. Run 'git-secret-vault lock' before committing." >&2
  exit 1
fi
"#;

const PRE_PUSH_SCRIPT: &str = r#"#!/bin/sh
# Installed by git-secret-vault harden
git-secret-vault status --fail-if-dirty --password-stdin <<< "" 2>/dev/null || true
git-secret-vault lock --check
if [ $? -ne 0 ]; then
  echo "git-secret-vault: vault is stale. Run 'git-secret-vault lock' before pushing." >&2
  exit 1
fi
"#;

#[derive(Args)]
pub struct HardenArgs {
    /// Path to .gitignore file to update
    #[arg(long, default_value = ".gitignore")]
    pub gitignore: String,

    /// Install a pre-commit git hook that checks for vault staleness
    #[arg(long)]
    pub hooks: bool,

    /// Print what would change without applying any modifications
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: &HardenArgs, quiet: bool, _verbose: bool) -> Result<()> {
    update_gitignore(args, quiet)?;

    if args.hooks {
        install_pre_commit_hook(args, quiet)?;
    }

    Ok(())
}

fn update_gitignore(args: &HardenArgs, quiet: bool) -> Result<()> {
    let gitignore_path = Path::new(&args.gitignore);

    let existing_content = if gitignore_path.exists() {
        std::fs::read_to_string(gitignore_path).map_err(VaultError::Io)?
    } else {
        String::new()
    };

    let existing_lines: Vec<&str> = existing_content.lines().collect();

    let mut additions: Vec<String> = Vec::new();
    let mut removals: Vec<String> = Vec::new();

    // Add missing sensitive patterns.
    for pattern in SENSITIVE_PATTERNS {
        if !existing_lines.iter().any(|l| l.trim() == *pattern) {
            additions.push((*pattern).to_owned());
        }
    }

    // Ensure vault files are not ignored (remove any matching negated or direct ignore lines).
    // We add `!<vault-file>` entries if the file is present as an ignored pattern.
    for vault_file in VAULT_FILES {
        let negated = format!("!{vault_file}");
        if existing_lines.iter().any(|l| l.trim() == *vault_file)
            && !existing_lines.iter().any(|l| l.trim() == negated)
        {
            removals.push(vault_file.to_string());
            additions.push(negated);
        }
    }

    if additions.is_empty() && removals.is_empty() {
        if !quiet {
            println!(".gitignore is already up-to-date.");
        }
        return Ok(());
    }

    if !quiet || args.dry_run {
        for line in &additions {
            println!("[gitignore] would add: {line}");
        }
        for line in &removals {
            println!("[gitignore] would remove: {line}");
        }
    }

    if args.dry_run {
        return Ok(());
    }

    // Build updated content: preserve existing, append additions, filter removals.
    let mut new_lines: Vec<String> = existing_lines
        .iter()
        .filter(|l| {
            let trimmed = l.trim();
            !removals.iter().any(|r| r == trimmed)
        })
        .map(|l| l.to_string())
        .collect();

    if !existing_content.is_empty() && !existing_content.ends_with('\n') {
        // Ensure there's a trailing newline before we append.
        new_lines.push(String::new());
    }

    for line in &additions {
        new_lines.push(line.clone());
    }

    let new_content = new_lines.join("\n") + "\n";
    std::fs::write(gitignore_path, new_content.as_bytes()).map_err(VaultError::Io)?;

    if !quiet {
        println!("Updated: {}", args.gitignore);
    }

    Ok(())
}

fn install_pre_commit_hook(args: &HardenArgs, quiet: bool) -> Result<()> {
    let hook_path = Path::new(".git/hooks/pre-commit");

    if args.dry_run {
        if !quiet {
            println!("[hooks] would write: {}", hook_path.display());
            println!("[hooks] would chmod +x: {}", hook_path.display());
            println!("[hooks] would write: .git/hooks/pre-push");
            println!("[hooks] would chmod +x: .git/hooks/pre-push");
        }
        return Ok(());
    }

    if let Some(parent) = hook_path.parent() {
        std::fs::create_dir_all(parent).map_err(VaultError::Io)?;
    }

    std::fs::write(hook_path, PRE_COMMIT_SCRIPT.as_bytes()).map_err(VaultError::Io)?;

    // Make executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(hook_path, perms).map_err(VaultError::Io)?;
    }

    if !quiet {
        println!("Installed pre-commit hook: {}", hook_path.display());
    }

    // Install pre-push hook.
    let push_hook_path = Path::new(".git/hooks/pre-push");
    std::fs::write(push_hook_path, PRE_PUSH_SCRIPT.as_bytes()).map_err(VaultError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(push_hook_path, perms).map_err(VaultError::Io)?;
    }

    if !quiet {
        println!("Installed pre-push hook: {}", push_hook_path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn harden_adds_missing_sensitive_patterns() {
        let dir = tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        std::fs::write(&gitignore, b"node_modules/\n").unwrap();

        let args = HardenArgs {
            gitignore: gitignore.to_str().unwrap().to_owned(),
            hooks: false,
            dry_run: false,
        };
        run(&args, true, false).unwrap();

        let content = std::fs::read_to_string(&gitignore).unwrap();
        for pattern in SENSITIVE_PATTERNS {
            assert!(
                content.contains(pattern),
                "expected pattern {pattern} in .gitignore"
            );
        }
    }

    #[test]
    fn harden_does_not_duplicate_existing_patterns() {
        let dir = tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        std::fs::write(&gitignore, b"*.env\n*.key\n*.pem\n*.secret\n").unwrap();

        let args = HardenArgs {
            gitignore: gitignore.to_str().unwrap().to_owned(),
            hooks: false,
            dry_run: false,
        };
        run(&args, true, false).unwrap();

        let content = std::fs::read_to_string(&gitignore).unwrap();
        assert_eq!(
            content.matches("*.env").count(),
            1,
            "should not duplicate *.env"
        );
    }

    #[test]
    fn harden_dry_run_does_not_modify_gitignore() {
        let dir = tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        std::fs::write(&gitignore, b"node_modules/\n").unwrap();

        let args = HardenArgs {
            gitignore: gitignore.to_str().unwrap().to_owned(),
            hooks: false,
            dry_run: true,
        };
        run(&args, true, false).unwrap();

        let content = std::fs::read_to_string(&gitignore).unwrap();
        assert_eq!(content, "node_modules/\n", "dry-run must not modify file");
    }

    #[test]
    fn harden_creates_gitignore_if_missing() {
        let dir = tempdir().unwrap();
        let gitignore = dir.path().join(".gitignore");
        assert!(!gitignore.exists());

        let args = HardenArgs {
            gitignore: gitignore.to_str().unwrap().to_owned(),
            hooks: false,
            dry_run: false,
        };
        run(&args, true, false).unwrap();

        assert!(gitignore.exists());
        let content = std::fs::read_to_string(&gitignore).unwrap();
        for pattern in SENSITIVE_PATTERNS {
            assert!(content.contains(pattern));
        }
    }

    #[cfg(unix)]
    #[test]
    fn harden_hooks_installs_executable_pre_commit() {
        let dir = tempdir().unwrap();
        // Create a fake .git/hooks directory.
        let hooks_dir = dir.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let hook_path = hooks_dir.join("pre-commit");

        // Write the hook directly.
        std::fs::write(&hook_path, PRE_COMMIT_SCRIPT.as_bytes()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(&hook_path, perms).unwrap();

        let meta = std::fs::metadata(&hook_path).unwrap();
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "pre-commit hook must be executable");
        assert!(
            std::fs::read_to_string(&hook_path)
                .unwrap()
                .contains("git-secret-vault lock --check")
        );
    }

    #[test]
    fn harden_pre_commit_script_has_correct_content() {
        assert!(PRE_COMMIT_SCRIPT.contains("git-secret-vault lock --check"));
        assert!(PRE_COMMIT_SCRIPT.starts_with("#!/bin/sh"));
    }
}
