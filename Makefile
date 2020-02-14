.PHONY: build test test-watch run

clean:
	rm *.pyc

build:
	@docker build -t heimdall .

lint:
	@docker run --rm -v ${PWD}:/app pipelinecomponents/flake8:latest flake8

format:
	@docker run --rm -v ${PWD}:/app cytopia/black /app

test:
	@docker run --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app heimdall python -m unittest

test-watch:
	@ptw

smoke:
	@docker run --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app heimdall python smoke.py
