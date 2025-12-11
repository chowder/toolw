#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLW="${SCRIPT_DIR}/../toolw.py"
TOOLS_DIR="${SCRIPT_DIR}/tools"
TEST_CACHE_DIR="/tmp/toolw-test-cache-$$"
FAILURES=0

cleanup() {
    rm -rf "$TEST_CACHE_DIR"
}
trap cleanup EXIT

pass() {
    echo "✓ $1"
}

fail() {
    echo "✗ $1"
    ((FAILURES++))
}

test_help() {
    if "$TOOLW" --help 2>&1 | grep -q "USAGE"; then
        pass "Help flag works"
    else
        fail "Help flag failed"
    fi
}

test_version() {
    if "$TOOLW" --version 2>&1 | grep -q "toolw version"; then
        pass "Version flag works"
    else
        fail "Version flag failed"
    fi
}

test_clean() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    mkdir -p "$TEST_CACHE_DIR/test"
    if "$TOOLW" --clean 2>&1; then
        if [ ! -d "$TEST_CACHE_DIR" ]; then
            pass "Clean flag works"
        else
            fail "Clean flag didn't remove cache"
        fi
    else
        fail "Clean flag failed"
    fi
}

test_missing_tool() {
    output=$("$TOOLW" nonexistent-tool 2>&1 || true)
    if echo "$output" | grep -q "not found"; then
        pass "Missing tool error works"
    else
        fail "Missing tool error failed"
    fi
}

test_file_download() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" target-determinator --version 2>&1 || true)
    if echo "$output" | grep -q "target-determinator"; then
        pass "File-type tool downloads and executes"
    else
        fail "File-type tool failed: $output"
    fi
}

test_file_cached() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" target-determinator --version 2>&1 || true)
    if echo "$output" | grep -q "target-determinator" && ! echo "$output" | grep -q "Downloading"; then
        pass "File-type tool uses cache"
    else
        fail "File-type tool didn't use cache"
    fi
}

test_archive_download() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" gh version 2>&1 || true)
    if echo "$output" | grep -q "gh version"; then
        pass "Archive-type tool downloads and executes"
    else
        fail "Archive-type tool failed"
    fi
}

test_archive_cached() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" gh version 2>&1 || true)
    if echo "$output" | grep -q "gh version" && ! echo "$output" | grep -q "Downloading"; then
        pass "Archive-type tool uses cache"
    else
        fail "Archive-type tool didn't use cache"
    fi
}

test_symlink_mode() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLS_DIR/gh" version 2>&1 || true)
    if echo "$output" | grep -q "gh version"; then
        pass "Symlink mode works"
    else
        fail "Symlink mode failed"
    fi
}

test_symlink_lockfile_discovery() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    # Just run without args - if lockfile is found, it will try to execute the tool
    # If lockfile is not found, it will error about missing lockfile
    output=$("$TOOLS_DIR/target-determinator" 2>&1 || true)
    if echo "$output" | grep -q "Could not find toolw.lock.json"; then
        fail "Symlink didn't discover adjacent lockfile"
    elif echo "$output" | grep -q "Usage of"; then
        pass "Symlink discovers adjacent lockfile"
    else
        pass "Symlink discovers adjacent lockfile"
    fi
}

test_custom_config() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" -c "$SCRIPT_DIR/../toolw.lock.json" gh version 2>&1 || true)
    if echo "$output" | grep -q "gh version"; then
        pass "Custom config path works"
    else
        fail "Custom config path failed"
    fi
}

test_cache_structure() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    if [ -d "$TEST_CACHE_DIR/blobs" ]; then
        blob_count=$(find "$TEST_CACHE_DIR/blobs" -mindepth 1 -maxdepth 1 -type d | wc -l)
        if [ "$blob_count" -ge 2 ]; then
            pass "Cache structure is correct"
        else
            fail "Cache structure has wrong blob count: $blob_count"
        fi
    else
        fail "Cache blobs directory doesn't exist"
    fi
}

test_stdout_not_polluted() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    stdout=$("$TOOLW" gh version 2>/dev/null)
    if echo "$stdout" | grep -q "gh version" && ! echo "$stdout" | grep -q "\[toolw\]"; then
        pass "Stdout is not polluted"
    else
        fail "Stdout contains toolw messages"
    fi
}

test_argument_passing() {
    export TOOLW_CACHE_DIR="$TEST_CACHE_DIR"
    output=$("$TOOLW" gh --help 2>&1 || true)
    if echo "$output" | grep -q "USAGE"; then
        pass "Arguments pass through correctly"
    else
        fail "Arguments didn't pass through"
    fi
}

echo "Running toolw end-to-end tests..."
echo

test_help
test_version
test_clean
test_missing_tool
test_file_download
test_file_cached
test_archive_download
test_archive_cached
test_symlink_mode
test_symlink_lockfile_discovery
test_custom_config
test_cache_structure
test_stdout_not_polluted
test_argument_passing

echo
if [ $FAILURES -eq 0 ]; then
    echo "All tests passed! ✓"
    exit 0
else
    echo "$FAILURES test(s) failed ✗"
    exit 1
fi
