PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: install test gui clean

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -r requirements-dev.txt
	$(BIN)/pip install -e . --no-deps

test:
	$(BIN)/python -m pytest

gui:
	$(BIN)/python -m securecrypt gui

clean:
	find . -path ./$(VENV) -prune -o -name __pycache__ -type d -exec rm -rf {} +
	rm -rf .pytest_cache build *.egg-info
