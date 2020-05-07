IMAGE_NAME = registry.gitlab.com/thorchain/heimdall
DOCKER_OPTS = --network=host --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app

clean:
	rm *.pyc

build:
	@docker build -t ${IMAGE_NAME} .

lint:
	@docker run --rm -v ${PWD}:/app pipelinecomponents/flake8:latest flake8

format:
	@docker run --rm -v ${PWD}:/app cytopia/black /app

test:
	@docker run ${DOCKER_OPTS} -e RUNE=${RUNE} -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} ${IMAGE_NAME} python -m unittest tests/test_*

test-coverage:
	@docker run ${DOCKER_OPTS} -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} ${IMAGE_NAME} coverage run -m unittest tests/test_*

test-coverage-report:
	@docker run ${DOCKER_OPTS} -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} ${IMAGE_NAME} coverage report -m

test-watch:
	@PYTHONPATH=${PWD} ptw tests/test_*

benchmark-stake:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/benchmark.py --tx-type=stake --num=${NUM}

benchmark-swap:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/benchmark.py --tx-type=swap --num=${NUM}

smoke:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/smoke.py --fast-fail=True

health:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/health.py

bitcoin-reorg:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/bitcoin_reorg.py

shell:
	@docker run ${DOCKER_OPTS} -it ${IMAGE_NAME} sh

.PHONY: build lint format test test-watch health smoke shell
