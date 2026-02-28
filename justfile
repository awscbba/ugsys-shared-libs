# ugsys-shared-libs task runner
default:
    @just --list

# Install git hooks (run once after cloning)
install-hooks:
    @bash scripts/install-hooks.sh

# Uninstall git hooks
uninstall-hooks:
    @rm -f .git/hooks/pre-commit .git/hooks/pre-push
    @echo "✓ Git hooks removed"

# Create a feature branch (enforces naming convention)
branch name:
    git checkout -b feature/{{name}}

# Lint all packages
lint:
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        echo "=== Linting $$pkg ==="; \
        src=$$(find $$pkg -maxdepth 1 -mindepth 1 -type d ! -name '.*' ! -name 'tests' ! -name '__pycache__' ! -name '.venv' ! -name '.pytest_cache' ! -name '.ruff_cache' | head -1); \
        uv run --directory $$pkg --extra dev ruff check $$src/; \
    done

# Format all packages
format:
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        echo "=== Formatting $$pkg ==="; \
        src=$$(find $$pkg -maxdepth 1 -mindepth 1 -type d ! -name '.*' ! -name 'tests' ! -name '__pycache__' ! -name '.venv' ! -name '.pytest_cache' ! -name '.ruff_cache' | head -1); \
        uv run --directory $$pkg --extra dev ruff format $$src/; \
    done

# Check formatting without modifying
format-check:
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        echo "=== Format check $$pkg ==="; \
        src=$$(find $$pkg -maxdepth 1 -mindepth 1 -type d ! -name '.*' ! -name 'tests' ! -name '__pycache__' ! -name '.venv' ! -name '.pytest_cache' ! -name '.ruff_cache' | head -1); \
        uv run --directory $$pkg --extra dev ruff format --check $$src/; \
    done

# Run tests for all packages
test:
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        echo "=== Testing $$pkg ==="; \
        uv run --directory $$pkg --extra dev pytest tests/ -v --tb=short; \
    done

# Run tests for a specific package: just test-pkg auth-client
test-pkg pkg:
    uv run --directory {{pkg}} --extra dev pytest tests/ -v --tb=short

# Sync all package dependencies
sync:
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        echo "=== Syncing $$pkg ==="; \
        uv sync --directory $$pkg --extra dev; \
    done

# Security scan
security-scan:
    @echo "=== Bandit SAST ==="
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        src=$$(find $$pkg -maxdepth 1 -mindepth 1 -type d ! -name '.*' ! -name 'tests' ! -name '__pycache__' ! -name '.venv' ! -name '.pytest_cache' ! -name '.ruff_cache' | head -1); \
        uv tool run bandit -r $$src/ -ll -ii || true; \
    done
    @echo "=== pip-audit ==="
    @for pkg in auth-client logging-lib event-lib testing-lib; do \
        uv export --directory $$pkg --no-hashes --no-dev --frozen > /tmp/$$pkg-reqs.txt 2>/dev/null; \
        uv tool run pip-audit -r /tmp/$$pkg-reqs.txt || true; \
    done

# Build wheel + sdist for a package: just build auth-client
build pkg:
    @echo "=== Building {{pkg}} ==="
    uv tool run hatch build --clean
    @echo "✓ dist/ artifacts ready"

# Tag and trigger publish for a package: just release auth-client 0.2.0
release pkg version:
    @echo "Tagging {{pkg}}/v{{version}} ..."
    git tag -a "{{pkg}}/v{{version}}" -m "release: {{pkg}} v{{version}}"
    git push origin "{{pkg}}/v{{version}}"
    @echo "✓ Tag pushed — publish workflow triggered"
