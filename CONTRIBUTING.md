# Contributing to SSH Honeypot

Thank you for considering contributing to the SSH Honeypot project! This document outlines the guidelines for contributing.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check the [issue tracker](https://github.com/Not-Just-Pratul/SSH-Honeypot/issues) for existing issues.
2. If no existing issue, [create a new one](https://github.com/Not-Just-Pratul/SSH-Honeypot/issues/new).
3. Include:
   - A clear, descriptive title
   - Steps to reproduce the bug
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Logs or screenshots if applicable

### Suggesting Features

1. Open a [feature request](https://github.com/Not-Just-Pratul/SSH-Honeypot/issues/new).
2. Clearly describe the feature and its use case.
3. Explain how it aligns with the project's goals.

### Pull Requests

1. **Fork the repository** and create your branch from `main`.
2. **Set up your environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or .\venv\Scripts\activate on Windows
   pip install -e ".[dev]"
   ```
3. **Make your changes** following the coding standards below.
4. **Write tests** for any new functionality.
5. **Run the test suite**:
   ```bash
   python -m pytest tests/ -v
   ```
6. **Run linting**:
   ```bash
   ruff check src/ tests/
   ruff format --check src/ tests/
   bandit -c pyproject.toml -r src/
   ```
7. **Commit your changes** using Conventional Commits format:
   - `feat: add new feature`
   - `fix: resolve issue with X`
   - `docs: update README`
   - `test: add tests for X`
   - `refactor: improve X structure`
   - `chore: update dependencies`
8. **Push to your fork** and submit a pull request.

## Development Guidelines

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with a 120-character line limit.
- Use type hints for all function signatures.
- Write docstrings for all public functions and classes (Google style).
- Keep functions focused and single-purpose.

### Testing

- All new features must include tests.
- Aim for at least 80% code coverage.
- Use pytest fixtures for common setup.
- Mock external dependencies (network, databases) in unit tests.

### Project Structure

```
src/ssh_honeypot/     # Package source
tests/                # Test suite
├── conftest.py       # Shared fixtures
├── test_config.py
├── test_database.py
├── test_geo.py
├── test_honeypot.py
├── test_logger.py
└── test_api.py
```

### Security Considerations

- Never commit `.env` files, credentials, or API keys.
- All user-supplied data must be sanitized before storage.
- Use parameterized queries for all database operations.
- Add escaping for any data rendered in HTML/dashboard.
- Run `bandit` before submitting PRs.

## Questions?

Open a [discussion](https://github.com/Not-Just-Pratul/SSH-Honeypot/discussions) or issue for any questions.