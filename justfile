# Local shortcuts; CI runs the underlying Python commands directly.

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

# Regenerate pages whenever registry inputs change (Ctrl+C to stop)
pages-dev:
    python3 scripts/watch-pack-pages.py

# Check that the generated pages are current
pages-check:
    python3 scripts/build-pack-pages.py --check
