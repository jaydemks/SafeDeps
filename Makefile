.PHONY: install-dev format format-check lint typecheck test coverage build smoke checks

PYTHON ?= python

install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

format:
	$(PYTHON) -m ruff format safedeps tests
	$(PYTHON) -m ruff check --fix safedeps tests

format-check:
	$(PYTHON) -m ruff format --check safedeps tests

lint:
	$(PYTHON) -m ruff check safedeps tests

typecheck:
	$(PYTHON) -m mypy safedeps --ignore-missing-imports

test:
	$(PYTHON) -m pytest

coverage:
	$(PYTHON) -m pytest --cov=safedeps --cov-report=term-missing --cov-report=xml

build:
	$(PYTHON) -m build --no-isolation
	$(PYTHON) -m twine check dist/*

smoke:
	$(PYTHON) -m safedeps.cli --help
	$(PYTHON) -m safedeps.cli explain FLOATING_VERSION

checks: lint typecheck coverage build smoke
