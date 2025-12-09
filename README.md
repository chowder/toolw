# toolw

Like `gradlew` but for any CLI tool. Lock tool versions in your repo so users don't need to install them globally. Works cross-platform with a single lockfile.

## Quick Start

Copy `toolw` to your project and create `toolw.lock.json`:

```jsonc
{
  // Each tool can have multiple binaries for different platforms
  "gh": {
    "binaries": [
      {
        // "archive" for tar.gz/zip files, "file" for standalone executables
        "kind": "archive",
        "url": "https://github.com/cli/cli/releases/download/v2.44.1/gh_2.44.1_linux_amd64.tar.gz",
        "sha256": "f11eefb646768e3f53e2185f6d3b01b4cb02112c2c60e65a4b5875150287ff97",
        // Path to binary inside the archive (archive-type only)
        "file": "gh_2.44.1_linux_amd64/bin/gh",
        "os": "linux",      // "linux", "macos", or "windows"
        "cpu": "x86_64"     // "x86_64" or "arm64"
      },
      {
        "kind": "archive",
        "url": "https://github.com/cli/cli/releases/download/v2.44.1/gh_2.44.1_macOS_amd64.zip",
        "sha256": "1c545505b5b88feaffeba00b7284ccac3f2002b67461b1246eaec827eb07c31b",
        "file": "gh_2.44.1_macOS_amd64/bin/gh",
        "os": "macos",
        "cpu": "x86_64"
      }
    ]
  },
  // Example of a standalone binary (not an archive)
  "jq": {
    "binaries": [
      {
        "kind": "file",
        "url": "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64",
        "sha256": "5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5",
        "os": "linux",
        "cpu": "x86_64"
        // No "file" field needed for kind="file"
      }
    ]
  }
}
```

## Usage

```
toolw [OPTIONS] <tool-name> [tool-args...]

OPTIONS:
  --help              Show help message
  --version           Show version
  --clean             Clean cache directory
  -c, --config PATH   Path to lockfile (default: ./toolw.lock.json)
```

**Direct invocation:**
```bash
./toolw gh version
```

**Symlink mode:**
```bash
ln -s toolw gh
./gh version
```

## Configuration

**Lockfile discovery** (in order of precedence):
1. `-c/--config` flag
2. Adjacent to `toolw` script
3. Current working directory

**Cache directory** (default: `~/.cache/toolw/`):
```bash
export TOOLW_CACHE_DIR=/custom/cache/dir
./toolw gh version

# Clean cache
./toolw --clean
```

## Authentication

### Credential Helper

Use `TOOLW_CREDENTIAL_HELPER` to specify an executable that provides authorization credentials:

```bash
export TOOLW_CREDENTIAL_HELPER=/path/to/credential-helper
./toolw gh version
```

The credential helper should be a binary that: 

- Receives the download URL as the first and only command-line argument
- Outputs the Authorization header value to stdout (e.g., `Bearer token` or `Basic base64creds`)
- Exits with code 0 on success, non-zero on failure
- Sends error messages to stderr

**Example:**
```bash
#!/bin/bash
# credential-helper.sh
URL="$1"

# Fetch token from your credential store, secrets manager, or API
# This is just an example - use your actual credential retrieval method
TOKEN=$(cat ~/.my-secret-token)

echo "Bearer $TOKEN"
```

Make it executable:
```bash
chmod +x credential-helper.sh
export TOOLW_CREDENTIAL_HELPER=$PWD/credential-helper.sh
```

### `.netrc` Authentication

If `TOOLW_CREDENTIAL_HELPER` is not set, `toolw` will attempt to use credentials from your `~/.netrc` file.

## Requirements

Python 3.8+. Supports Linux, macOS, Windows on x86_64 and arm64.
