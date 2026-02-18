.PHONY: help install dev test lint format clean run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	uv pip install -e .

dev: ## Install development dependencies
	uv pip install -e ".[dev]"

test: ## Run tests with coverage
	uv run pytest

lint: ## Run linting checks
	uv run ruff check
	uv run mypy meshmap

lint-fix: ## Run linting fixes
	uv run ruff check --fix .

format: ## Format code with ruff
	uv run ruff format .

clean: ## Clean up generated files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete

run: ## Run meshmap
	uv run meshmap

sync: ## Sync dependencies
	uv pip sync

lock: ## Update lock file
	uv pip compile pyproject.toml -o requirements.txt
