#!/usr/bin/env python3
import sys
import re
import pathlib

version, sha_aarch64, sha_x86_64_macos, sha_x86_64_linux = sys.argv[1:5]
formula = pathlib.Path("packaging/homebrew/git-secret-vault.rb")
text = formula.read_text()

# Replace version
text = re.sub(r'version "[^"]*"', f'version "{version}"', text)

# Replace sha256 values in order: aarch64-macos, x86_64-macos, x86_64-linux
sha_values = [sha_aarch64, sha_x86_64_macos, sha_x86_64_linux]
count = 0


def replacer(m):
    global count
    val = sha_values[count] if count < len(sha_values) else m.group(0)[7:-1]
    count += 1
    return f'sha256 "{val}"'


text = re.sub(r'sha256 "[^"]*"', replacer, text)
formula.write_text(text)
print(f"Updated {formula} to version {version}")
