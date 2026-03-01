class GitSecretVault < Formula
  desc "Encrypted secret vault stored in git using AES-256 ZIP archives"
  homepage "https://github.com/aheissenberger/git-secret-vault"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/aheissenberger/git-secret-vault/releases/download/v#{version}/git-secret-vault-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_MACOS"
    end
    on_intel do
      url "https://github.com/aheissenberger/git-secret-vault/releases/download/v#{version}/git-secret-vault-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_MACOS"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/aheissenberger/git-secret-vault/releases/download/v#{version}/git-secret-vault-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_X86_64_LINUX"
    end
  end

  def install
    bin.install "git-secret-vault"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/git-secret-vault --version")
  end
end
