# Local shortcuts; CI runs the underlying Python commands directly.

# List available recipes
default:
    @just --list

# Run the repository checks
check: test pages-check validate

# Run unit tests
test:
    python3 -m unittest discover -s tests

# Validate the published registry
validate:
    python3 scripts/validate-packs.py

# Regenerate the Markdown registry pages
pages:
    python3 scripts/build-pack-pages.py

# Install the site dependencies (requires Node.js 22.23.4 or newer)
pages-install:
    @if command -v mise >/dev/null 2>&1; then mise exec node@22.23.4 -- npm ci; else npm ci; fi

# Preview pages at http://127.0.0.1:8000/mvm-packs/ and rebuild on input changes
pages-dev: pages-install
    @if command -v mise >/dev/null 2>&1; then mise exec node@22.23.4 -- python3 scripts/watch-pack-pages.py; else python3 scripts/watch-pack-pages.py; fi

# Check that the generated pages are current
pages-check:
    python3 scripts/build-pack-pages.py --check
