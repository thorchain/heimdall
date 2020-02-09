.PHONY: test run

run:
	@docker run --rm -v ${PWD}:/app python:3.8-alpine python /app/main.py
