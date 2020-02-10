.PHONY: build test test-watch run

build:
	@docker build -t heimdall .

test:
	@docker run --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app heimdall python -m unittest

test-watch:
	@ptw
