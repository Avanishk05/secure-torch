# Contributing

## Setup

```bash
git clone https://github.com/Avanishk05/secure-torch
cd secure-torch
pip install -e .
pip install pytest pytest-cov mypy ruff bandit
```

## Running tests

```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ tests/cve/ -v

# Integration tests
pytest tests/integration/ -v

# With coverage
pytest tests/ --cov=secure_torch --cov-report=html
```

## Lint & type check

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/secure_torch/ --ignore-missing-imports
bandit -r src/secure_torch/ -ll
```

## Adding a new format validator

1. Create `src/secure_torch/formats/your_format.py`
2. Implement `validate_your_format(path: Path, scorer: ThreatScorer) -> None`
3. Add detection in `format_detect.py`
4. Dispatch in `loader.py:_run_validators`
5. Add unit tests in `tests/unit/test_parsers.py`

## Adding a CVE regression test

1. Add a test to `tests/cve/test_cve_regressions.py`
2. Name it `test_cve_YYYY_NNNNN_description`
3. Include the CVE number and a brief description in the docstring

## Commit style

```
feat: add GGUF format validator
fix: handle STACK_GLOBAL with empty string stack
test: add CVE-2024-XXXXX regression
docs: update threat scoring table
```

## Pull request checklist

- [ ] Tests pass: `pytest tests/ -v`
- [ ] Lint clean: `ruff check src/ tests/`
- [ ] New CVE? Add regression test
- [ ] New format? Add unit tests
- [ ] Update `CHANGELOG.md`
