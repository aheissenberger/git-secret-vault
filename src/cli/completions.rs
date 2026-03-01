use clap::Args;
use clap_complete::Shell;

use crate::cli::Cli;
use crate::error::Result;

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: Shell,
}

pub fn run(args: &CompletionsArgs) -> Result<()> {
    use clap::CommandFactory;
    let mut cmd = Cli::command();
    clap_complete::generate(
        args.shell,
        &mut cmd,
        "git-secret-vault",
        &mut std::io::stdout(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn completions_run_does_not_panic() {
        use crate::cli::Cli;
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let mut out = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut cmd,
            "git-secret-vault",
            &mut out,
        );
        assert!(!out.is_empty());
    }
}
