.PHONY: build test test-watch run

build:
	@docker build -t heimdall .

run:
	@docker run --rm -v ${PWD}:/app -w /app heimdall python /app/main.py

test:
	@docker run --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app heimdall python -m unittest

test-watch:
	@ptw
