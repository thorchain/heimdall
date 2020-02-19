IMAGE_NAME = registry.gitlab.com/thorchain/heimdall

ifeq ($(OS),Windows_NT)
    uname_s := Windows
else
    uname_s := $(shell uname -s)
endif

# system specific variables, add more here
DOCKER_OPTS.Linux := --network=host
DOCKER_OPTS = $(DOCKER_OPTS.$(uname_s))

clean:
	rm *.pyc

build:
	@docker build -t ${IMAGE_NAME} .

lint:
	@docker run --rm -v ${PWD}:/app pipelinecomponents/flake8:latest flake8

format:
	@docker run --rm -v ${PWD}:/app cytopia/black /app

test:
	@docker run --rm -e EXPORT=${EXPORT} -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python -m unittest tests/test_*

test-coverage:
	@docker run --rm -e EXPORT=${EXPORT} -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} coverage run -m unittest tests/test_*

test-watch:
	@ptw tests/test_*

smoke:
	@docker run ${DOCKER_OPTS} --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python smoke.py

health:
	@docker run ${DOCKER_OPTS} --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python health.py

.PHONY: build lint format test test-watch health smoke
