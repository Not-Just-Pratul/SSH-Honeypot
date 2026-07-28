# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-28

### Added
- Project restructured into proper Python package with `src/` layout
- `pyproject.toml` with full metadata, dependencies, and tool configs
- Console script entry point (`ssh-honeypot` CLI command)
- Package entry point for `python -m ssh_honeypot`
- JWT authentication support for REST API (`API_JWT_SECRET`, `API_JWT_ENABLED`)
- JWT token endpoint (`POST /api/auth/token`)
- Discord alert notifications with rich embed formatting
- Slack alert notifications with Block Kit formatting
- Comprehensive test suite (111 tests across 6 test modules):
  - Config parsing and defaults
  - Database operations (CRUD, search, filter, stats)
  - GeoIP enrichment (with mocks)
  - Honeypot server interface and brute-force detection
  - Logger sanitization
  - JWT generation/verification and API endpoints
- Docker multi-stage production build
- Docker Compose with all-in-one and production profiles
- `.dockerignore` for optimized builds
- Container health checks and security hardening
- GitHub Actions CI/CD workflows:
  - Test workflow (matrix across Python 3.10-3.13)
  - Lint workflow (ruff, bandit, mypy)
  - Docker build and push to GHCR
  - Weekly security scan with bandit and safety
- `pre-commit` hooks configuration (ruff, bandit, mypy)
- MIT License
- Contributing guide (`CONTRIBUTING.md`)
- Change log (`CHANGELOG.md`)
- Security policy (`SECURITY.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)

### Changed
- All modules moved from root to `src/ssh_honeypot/` package
- Internal imports use absolute package references
- `app.py` at root is backward-compatible wrapper
- `BruteForceDetector` lock changed from `Lock` to `RLock` to prevent deadlock
- `datetime.utcnow()` replaced with `datetime.now(timezone.utc)` (deprecation fix)
- Root `requirements.txt` updated for development compatibility
- `.gitignore` extended for build artifacts and IDE files

### Fixed
- Deadlock in `BruteForceDetector.get_stats()` calling `get_banned_ips()` while holding lock
- `datetime.utcnow()` deprecation warnings in database module
- `HONEYPOT_HOST_KEY_PATH` default path for package layout
- Streamlit dashboard uses config values for page config

## [0.1.0] - 2026-07-26

### Added
- Initial release with SSH honeypot server
- Streamlit SOC dashboard with dark/light theme
- REST API with attack data and stats endpoints
- GeoIP enrichment via MaxMind GeoLite2
- Brute-force detection with optional fail2Ban integration
- Telegram, Discord, Slack, and email alerts
- SQLite database with CSV fallback logging
- GeoIP map, charts, live feed, and export features