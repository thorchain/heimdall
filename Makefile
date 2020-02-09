.PHONY: test run

run:
	@docker run --rm -v ${PWD}:/app python:3.8-alpine python /app/main.py

test:
	@docker run --rm -e PYTHONPATH=/app -v ${PWD}:/app python:3.8-alpine python -m unittest
