#!/usr/bin/env python3
# /// script
# [tool.uv]
# exclude-newer = "2025-12-10T00:00:00Z"
# ///
import argparse
import hashlib
import json
import netrc
import os
import platform
import random
import shutil
import string
import subprocess
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional, Tuple

sys.stdout = sys.stderr

VERSION = "1.0.0"
LOCKFILE_NAME = "toolw.lock.json"


def log(msg: str) -> None:
    print(f"[toolw] {msg}", file=sys.stderr)


def die(msg: str) -> NoReturn:
    print(f"[toolw] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


class AuthorizationHeaderHandler(urllib.request.BaseHandler):
    def __init__(self, auth_value: str) -> None:
        self.auth_value = auth_value

    def http_request(self, request: urllib.request.Request) -> urllib.request.Request:
        request.add_header('Authorization', self.auth_value)
        return request

    https_request = http_request


def _invoke_credential_helper(url: str) -> Optional[str]:
    helper_path = os.environ.get('TOOLW_CREDENTIAL_HELPER')
    if not helper_path:
        return None

    if not Path(helper_path).is_file():
        die(f"TOOLW_CREDENTIAL_HELPER not found: {helper_path}")
    if not os.access(helper_path, os.X_OK):
        die(f"TOOLW_CREDENTIAL_HELPER is not executable: {helper_path}")

    try:
        result = subprocess.run(
            [helper_path, url],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or '(no error message)'
            die(f"Credential helper failed (exit {result.returncode}): {stderr}")

        auth_value = result.stdout.strip()
        if not auth_value:
            die("Credential helper returned empty authorization value")

        return auth_value

    except subprocess.TimeoutExpired:
        die("Credential helper timed out after 10 seconds")
    except Exception as e:
        die(f"Failed to execute credential helper: {e}")


def _create_netrc_handler(url: str) -> urllib.request.HTTPBasicAuthHandler:
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()

    try:
        netrc_auth = netrc.netrc()
        hostname = urllib.parse.urlparse(url).hostname
        if hostname:
            auth_info = netrc_auth.authenticators(hostname)
            if auth_info:
                login, _, password = auth_info
                if password is not None:
                    password_mgr.add_password(None, url, login, password)
    except:  # noqa
        pass

    return urllib.request.HTTPBasicAuthHandler(password_mgr)


def create_authenticated_opener(url: str) -> urllib.request.OpenerDirector:
    auth_value = _invoke_credential_helper(url)
    if auth_value:
        auth_handler = AuthorizationHeaderHandler(auth_value)
        return urllib.request.build_opener(auth_handler)

    netrc_handler = _create_netrc_handler(url)
    return urllib.request.build_opener(netrc_handler)


def parse_arguments() -> Tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(prog='toolw', add_help=False)
    parser.add_argument('--help', action='store_true')
    parser.add_argument('--version', action='store_true')
    parser.add_argument('--clean', action='store_true')
    parser.add_argument('-c', '--config')
    parser.add_argument('tool', nargs='?')
    parser.add_argument('args', nargs=argparse.REMAINDER)
    return parser.parse_known_args()


def print_help() -> None:
    """
    We disable ArgumentParser's built-in help (add_help=False) because:
    1. Help is context-sensitive: 'toolw --help' shows this message,
       but 'toolw <tool> --help' passes --help to the underlying tool
    2. ArgumentParser's built-in help would exit immediately, preventing
       passthrough to wrapped executables
    """
    print(f"""toolw version {VERSION}

USAGE:
    toolw [OPTIONS] <tool-name> [tool-args...]

OPTIONS:
    --help              Show this help message
    --version           Show version
    --clean             Clean cache
    -c, --config PATH   Path to lockfile

CACHE:
    ~/.cache/toolw/ (override with TOOLW_CACHE_DIR)
""", file=sys.stderr)


def determine_tool_name(args: argparse.Namespace, script_path: str) -> str:
    script_name = Path(script_path).name
    if script_name in ('toolw', 'toolw.py'):
        if not args.tool:
            die("No tool specified")
        return args.tool
    return script_name


def discover_lockfile(config_path: Optional[str], script_path: str) -> Path:
    if config_path:
        lockfile = Path(config_path)
        if lockfile.is_file():
            return lockfile
        die(f"Lockfile not found: {config_path}")

    candidates = [
        Path(script_path).resolve().parent / LOCKFILE_NAME,
        Path.cwd() / LOCKFILE_NAME
    ]

    for path in candidates:
        if path.is_file():
            return path

    die(f"Could not find {LOCKFILE_NAME}")


def parse_lockfile(path: Path) -> Dict[str, Any]:
    try:
        with path.open() as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON: {e}")
    except OSError as e:
        die(f"Failed to read lockfile: {e}")


def detect_platform() -> Tuple[str, str]:
    system = platform.system().lower()
    os_map = {'darwin': 'macos', 'linux': 'linux', 'windows': 'windows'}
    if system not in os_map:
        die(f"Unsupported OS: {system}")

    machine = platform.machine().lower()
    if machine in ('x86_64', 'amd64', 'x64'):
        cpu = 'x86_64'
    elif machine in ('arm64', 'aarch64'):
        cpu = 'arm64'
    else:
        die(f"Unsupported CPU: {machine}")

    return os_map[system], cpu


def select_binary(tool_config: Dict[str, Any], os_name: str, cpu_arch: str) -> Dict[str, Any]:
    if 'binaries' not in tool_config:
        die("Invalid tool config: missing 'binaries'")

    for binary in tool_config['binaries']:
        if binary.get('os') == os_name and binary.get('cpu') == cpu_arch:
            if binary['kind'] == 'archive' and 'file' not in binary:
                die("Archive missing 'file' field")
            return binary

    available = ', '.join(f"{b.get('os')}/{b.get('cpu')}" for b in tool_config['binaries'])
    die(f"No binary for {os_name}/{cpu_arch}. Available: {available}")


def _get_required_env(name: str, error_msg: str) -> str:
    """Get a required environment variable or die with error message."""
    value = os.environ.get(name)
    if value is None:
        die(error_msg)
    assert value is not None  # Help type checker understand control flow
    return value


def get_cache_dir() -> Path:
    toolw_cache = os.environ.get('TOOLW_CACHE_DIR')
    if toolw_cache is not None:
        return Path(toolw_cache)

    system = platform.system().lower()

    if system == 'windows':
        base_dir = Path(_get_required_env('LOCALAPPDATA', '%LOCALAPPDATA% is not defined'))
    elif system == 'darwin':
        home_dir = _get_required_env('HOME', '$HOME is not defined')
        base_dir = Path(home_dir) / 'Library/Caches'
    elif system == 'linux':
        xdg_cache = os.environ.get('XDG_CACHE_HOME')
        if xdg_cache is None:
            home_dir = _get_required_env('HOME', 'neither $XDG_CACHE_HOME nor $HOME are defined')
            base_dir = Path(home_dir) / '.cache'
        else:
            base_dir = Path(xdg_cache)
    else:
        die(f"Unsupported operating system '{system}'")

    return base_dir / 'toolw'


def get_cache_path(sha256: str, kind: str, archive_path: Optional[str] = None) -> Path:
    blob_dir = get_cache_dir() / 'blobs' / sha256
    if kind == 'file':
        return blob_dir / 'binary'
    if archive_path is None:
        raise ValueError("archive_path is required for archive kind")
    return blob_dir / archive_path


def clean_cache() -> None:
    cache_dir = get_cache_dir()
    if cache_dir.exists():
        shutil.rmtree(cache_dir)


def download_file(url: str, dest_path: Path) -> None:
    opener = create_authenticated_opener(url)

    try:
        log(f"Downloading {url}")
        with opener.open(url) as response, dest_path.open('wb') as f:
            shutil.copyfileobj(response, f)
    except urllib.error.URLError as e:
        die(f"Download failed: {e}")


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def extract_archive(archive_path: Path, extract_dir: Path) -> None:
    is_tarball = (
        archive_path.name.endswith('.tar.gz') or
        archive_path.suffix == '.tgz' or
        tarfile.is_tarfile(archive_path)
    )

    if is_tarball:
        with tarfile.open(archive_path, 'r:*') as tar:
            for member in tar.getmembers():
                # Prevent path traversal attacks
                if member.name.startswith('/') or '..' in member.name:
                    die(f"Unsafe path in archive: {member.name}")
            tar.extractall(extract_dir)
    elif archive_path.suffix == '.zip' or zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            for name in zf.namelist():
                # Prevent path traversal attacks
                if name.startswith('/') or '..' in name:
                    die(f"Unsafe path in archive: {name}")
            zf.extractall(extract_dir)
    else:
        die("Unknown archive format")


def download_and_cache(url: str, expected_sha256: str, kind: str, archive_file: Optional[str] = None) -> Path:
    final_path = get_cache_path(expected_sha256, kind, archive_file)
    if final_path.exists():
        return final_path

    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    staging_dir = get_cache_dir() / f'staging-{suffix}'
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        download_path = staging_dir / 'download'
        download_file(url, download_path)

        actual_sha256 = compute_sha256(download_path)
        if actual_sha256 != expected_sha256:
            die(f"Checksum mismatch: expected {expected_sha256}, got {actual_sha256}")

        if kind == 'file':
            final_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(download_path), str(final_path))
            final_path.chmod(0o755)
        else:
            if archive_file is None:
                die("archive_file is required for archive kind")
            assert archive_file is not None
            extract_archive(download_path, staging_dir)
            if not (staging_dir / archive_file).exists():
                die(f"File not found in archive: {archive_file}")

            blob_dir = get_cache_dir() / 'blobs' / expected_sha256
            blob_dir.mkdir(parents=True, exist_ok=True)

            top_level = archive_file.split('/')[0]
            shutil.move(str(staging_dir / top_level), str(blob_dir / top_level))
            final_path.chmod(0o755)

        return final_path
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def main() -> None:
    args, unknown_args = parse_arguments()

    if args.version:
        print(f"toolw version {VERSION}")
        sys.exit(0)

    if args.clean:
        clean_cache()
        sys.exit(0)

    if args.help and not args.tool:
        print_help()
        sys.exit(0)

    tool_name = determine_tool_name(args, sys.argv[0])
    tool_args = args.args + unknown_args

    lockfile = parse_lockfile(discover_lockfile(args.config, sys.argv[0]))

    if tool_name not in lockfile:
        die(f"Tool '{tool_name}' not found. Available: {', '.join(lockfile.keys())}")

    os_name, cpu_arch = detect_platform()
    binary = select_binary(lockfile[tool_name], os_name, cpu_arch)

    archive_file = binary.get('file') if binary['kind'] == 'archive' else None
    tool_path = download_and_cache(binary['url'], binary['sha256'], binary['kind'], archive_file)

    os.execv(str(tool_path), [str(tool_path)] + tool_args)


if __name__ == '__main__':
    main()
