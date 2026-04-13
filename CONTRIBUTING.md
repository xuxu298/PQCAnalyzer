# Contributing to VN-PQC Readiness Analyzer

Thank you for your interest! / Cam on ban quan tam den du an!

## Getting Started

1. Fork the repo
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/vn-pqc-analyzer`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Run tests: `pytest`

## Development Workflow

1. Create a branch: `git checkout -b feat/my-feature`
2. Write code + tests
3. Run linting: `ruff check .`
4. Run tests: `pytest --cov=src --cov-report=term-missing`
5. Commit (conventional commits): `git commit -m "feat: add xyz scanner"`
6. Push and open a PR

## Branch Naming

- `feat/description` -- new feature
- `fix/description` -- bug fix
- `docs/description` -- documentation
- `refactor/description` -- code refactoring
- `test/description` -- test additions/fixes

## Code Style

- Python 3.10+, type hints required
- Google-style docstrings
- Linting: ruff
- Max line length: 100 characters
- All user-facing strings via i18n (no hardcoded Vietnamese or English)

## Testing Requirements

- All new features must include tests
- Target coverage: 80%+
- Use sample fixtures in `tests/fixtures/` (never scan real hosts in tests)
- Integration tests: mark with `@pytest.mark.integration`

## Adding a New Scanner Plugin

Subclass `BaseScanner` (when available) or follow the pattern in existing scanners:
1. Create `src/scanner/your_scanner.py`
2. Parse target input, extract crypto algorithms
3. Look up each algorithm in `AlgorithmDatabase`
4. Return `ScanResult` with `Finding` objects
5. Add tests in `tests/test_scanner/test_your_scanner.py`
6. Add CLI command in `src/cli.py`

## i18n

When adding user-facing strings:
1. Add key + translations to `src/utils/i18n.py`
2. Use `t("key_name", param=value)` in code

## Pull Request Checklist

- [ ] Tests pass (`pytest`)
- [ ] Linting passes (`ruff check .`)
- [ ] New strings are i18n-ready
- [ ] Documentation updated (if applicable)
- [ ] No secrets/credentials committed
- [ ] Conventional commit messages
