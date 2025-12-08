# -------- Settings --------
PY        ?= python3
PIP       ?= pip
PKG       ?= drm
SRC       ?= src
TESTS     ?= tests
VENV      ?= .venv
POETRY    ?= poetry
PYTHON    ?= $(VENV)/bin/python
PIPX      ?= $(VENV)/bin/pip

# Tools (override if you prefer alternatives)
BLACK     ?= $(VENV)/bin/black
RUFF      ?= $(VENV)/bin/ruff
MYPY      ?= $(VENV)/bin/mypy
PYTEST    ?= $(VENV)/bin/pytest
COVER     ?= coverage
PYRIGHT   ?= $(VENV)/bin/pyright

# -------- Meta --------
.PHONY: help venv install install-poetry sync clean dist \
        fmt lint typecheck test cov bench run cli export seed \
        docker-build docker-run docker-shell precommit

help:
	@echo "Common targets:"
	@echo "  venv            Create virtualenv"
	@echo "  install         Install deps (requirements.txt)"
	@echo "  install-poetry  Install deps (poetry)"
	@echo "  sync            Format+lint+typecheck+test"
	@echo "  fmt             Run code formatters (black)"
	@echo "  lint            Run linters (ruff)"
	@echo "  typecheck       Static type checking (mypy/pyright)"
	@echo "  test            Pytest with coverage"
	@echo "  cov             Coverage HTML report"
	@echo "  run             Run CLI (see CLI target vars)"
	@echo "  export          Export reproducible state"
	@echo "  docker-build    Build container"
	@echo "  docker-run      Run container"
	@echo "  precommit       Install pre-commit hooks"

# -------- Env / Install --------
venv:
	@test -d $(VENV) || $(PY) -m venv $(VENV)
	@$(PIPX) install --upgrade pip wheel

install: venv
	@$(PIPX) install -r requirements.txt
	@$(PIPX) install -e .

install-poetry: venv
	@$(POETRY) install

# -------- Quality Gates --------
fmt: venv
	@$(BLACK) $(SRC) $(TESTS)

lint: venv
	@$(RUFF) check $(SRC) $(TESTS)

typecheck: venv
	@$(MYPY) $(SRC) || true
	@$(PYRIGHT) || true

test: venv
	@$(PYTEST) -q --maxfail=1 --disable-warnings --cov=$(PKG) --cov-report=term-missing $(TESTS)

cov:
	@$(PYTEST) -q --cov=$(PKG) --cov-report=html
	@echo "open htmlcov/index.html"

sync: fmt lint typecheck test

# -------- Run / CLI --------
# Example CLI entrypoint: src/drm/cli.py (Typer/Click)
CLI_CMD ?= $(PYTHON) -m $(PKG).cli
run: venv
	@$(CLI_CMD) --help

# Example: pass-through to CLI
# make cli ARGS="encrypt --input in.mp4 --output out.enc"
cli: venv
	@$(CLI_CMD) $(ARGS)

# -------- Project Ops --------
export: venv
	@$(PYTHON) scripts/export_state.py --out data/exports/state-$(shell date +%Y%m%d-%H%M%S).zip

seed: venv
	@$(PYTHON) scripts/setup.sh || bash scripts/setup.sh

clean:
	@rm -rf $(VENV) .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info htmlcov .coverage
	@find $(SRC) -name "__pycache__" -type d -exec rm -rf {} +

dist: venv
	@$(PYTHON) -m build

# -------- Docker --------
IMAGE ?= drm-toolkit:latest
docker-build:
	@docker build -t $(IMAGE) .

docker-run:
	@docker run --rm -it -v $$PWD/data:/app/data $(IMAGE)

docker-shell:
	@docker run --rm -it -v $$PWD:/app $(IMAGE) /bin/bash

# -------- Git Hooks --------
precommit: venv
	@$(PIPX) install pre-commit
	@$(VENV)/bin/pre-commit install

