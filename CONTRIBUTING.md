# Contributing

Thanks for contributing to secure-torch.

Primary contribution workflow lives in `docs/contributing.md`.

## Quick Start

```bash
git clone https://github.com/Avanishk05/secure-torch
cd secure-torch
pip install -e .
pip install pytest pytest-cov mypy ruff bandit
```

## Before Opening a Pull Request

- Run tests: `pytest tests/ -v`
- Run lint: `ruff check src/ tests/`
- Run typing checks: `mypy src/secure_torch/ --ignore-missing-imports`
- Add/adjust tests for behavior changes
- Follow commit style from `docs/contributing.md`

## Conduct

By participating, you agree to follow `CODE_OF_CONDUCT.md`.
