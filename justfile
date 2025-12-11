# List all available recipes
default:
    @just --list

# Run all checks across all supported Python versions
check:
    just check-py 3.8
    just check-py 3.9
    just check-py 3.10
    just check-py 3.11
    just check-py 3.12
    just check-py 3.13

e2e:
    ./tests/e2e_tests.bash

format:
    uv run --no-project --with ruff ruff format .

# Run checks on specific Python version
check-py version:
    uv run --no-project --python {{version}} --with ruff --with ty ruff check .
    uv run --no-project --python {{version}} --with ruff --with ty ty check .

clean:
    rm -rf .ty_cache .ruff_cache __pycache__ .venv
    ./toolw --clean
