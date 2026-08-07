.PHONY: test-all build release clean

test-all:
	uv run ruff check .
	uv run ruff format --check .
	uv run pytest

build:
	uv build --no-sources

release: build
	uv publish

clean:
	rm -rf dist/ .ruff_cache/ .pytest_cache/ src/*.egg-info
