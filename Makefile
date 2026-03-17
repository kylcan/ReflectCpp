.PHONY: help deps dev-deps test eval eval-smoke dataset

PY := $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)
PIP := $(shell if [ -x .venv/bin/pip ]; then echo .venv/bin/pip; else echo python3 -m pip; fi)

SENTINEL_OFFLINE ?= 1

help:
	@echo "Targets: deps dev-deps test eval eval-smoke dataset"
	@echo "  make test       - run pytest"
	@echo "  make eval       - run eval (offline by default)"
	@echo "  make eval-smoke - run eval on 10 cases"

deps:
	$(PIP) install -r requirements.txt

dev-deps: deps
	$(PIP) install pytest

test:
	$(PY) -m pytest -q

dataset:
	$(PY) -m eval.generate_dataset

eval:
	SENTINEL_OFFLINE=$(SENTINEL_OFFLINE) $(PY) -m eval.run_eval

eval-smoke:
	SENTINEL_OFFLINE=$(SENTINEL_OFFLINE) $(PY) -m eval.run_eval --limit 10
