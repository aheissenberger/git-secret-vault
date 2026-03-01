//! MCP server exposing vault operations as tools (NFR-017).

use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    tool, tool_handler, tool_router,
    transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Parameters for the vault_lock tool.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct LockParams {
    /// File paths to lock into the vault.
    pub files: Vec<String>,
}

/// MCP server that exposes vault operations as tools.
#[derive(Clone)]
pub struct VaultServer {
    vault: String,
    index: String,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl VaultServer {
    fn new(vault: impl Into<String>, index: impl Into<String>) -> Self {
        Self {
            vault: vault.into(),
            index: index.into(),
            tool_router: Self::tool_router(),
        }
    }

    /// List all entries tracked in the vault.
    #[tool(description = "List all entries tracked in the encrypted vault")]
    async fn vault_status(&self) -> Result<CallToolResult, McpError> {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "status",
                "--vault",
                &self.vault,
                "--index",
                &self.index,
                "--json",
            ])
            .output()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Lock (encrypt) files into the vault.
    #[tool(
        description = "Lock (encrypt) one or more files into the vault. Requires password via VAULT_PASSWORD env var."
    )]
    async fn vault_lock(
        &self,
        Parameters(params): Parameters<LockParams>,
    ) -> Result<CallToolResult, McpError> {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["lock", "--vault", &self.vault, "--index", &self.index]);
        let count = params.files.len();
        for f in &params.files {
            cmd.arg(f);
        }
        let output = cmd
            .output()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let text = if output.status.success() {
            format!("Locked {count} file(s).")
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        };
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Unlock (decrypt) vault entries to plaintext files.
    #[tool(
        description = "Unlock (decrypt) all vault entries to plaintext. Requires VAULT_PASSWORD env var."
    )]
    async fn vault_unlock(&self) -> Result<CallToolResult, McpError> {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "unlock",
                "--vault",
                &self.vault,
                "--index",
                &self.index,
                "--force",
            ])
            .output()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let text = if output.status.success() {
            "Vault unlocked successfully.".to_owned()
        } else {
            String::from_utf8_lossy(&output.stderr).into_owned()
        };
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    /// Run vault integrity check.
    #[tool(description = "Verify vault integrity — checks all entries match stored hashes")]
    async fn vault_verify(&self) -> Result<CallToolResult, McpError> {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "verify",
                "--vault",
                &self.vault,
                "--index",
                &self.index,
                "--json",
            ])
            .output()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[tool_handler]
impl ServerHandler for VaultServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: "git-secret-vault".to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                ..Default::default()
            },
            instructions: Some(
                "Encrypted secret vault stored in git. Use VAULT_PASSWORD env var for authentication.".to_owned(),
            ),
        }
    }
}

/// Start the MCP server on stdio.
pub async fn run_mcp_server(vault: &str, index: &str) -> crate::error::Result<()> {
    let server = VaultServer::new(vault, index);
    let service = server
        .serve(stdio())
        .await
        .map_err(|e| crate::error::VaultError::Other(e.to_string()))?;
    service
        .waiting()
        .await
        .map_err(|e| crate::error::VaultError::Other(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_server_constructs() {
        let s = VaultServer::new("vault.zip", ".index.json");
        assert_eq!(s.vault, "vault.zip");
        assert_eq!(s.index, ".index.json");
    }
}
