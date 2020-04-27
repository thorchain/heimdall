IMAGE_NAME = registry.gitlab.com/thorchain/heimdall

clean:
	rm *.pyc

build:
	@docker build -t ${IMAGE_NAME} .

lint:
	@docker run --rm -v ${PWD}:/app pipelinecomponents/flake8:latest flake8

format:
	@docker run --rm -v ${PWD}:/app cytopia/black /app

test:
	@docker run --rm -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python -m unittest tests/test_*

test-coverage:
	@docker run --rm -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} coverage run -m unittest tests/test_*

test-coverage-report:
	@docker run --rm -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} coverage report -m

test-watch:
	@PYTHONPATH=${PWD} ptw tests/test_*

benchmark-stake:
	@docker run ${DOCKER_OPTS} --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python benchmark.py --binance="http://host.docker.internal:26660" --thorchain="http://host.docker.internal:1317" --tx-type=stake --num=${NUM}

benchmark-swap:
	@docker run ${DOCKER_OPTS} --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python benchmark.py --binance="http://host.docker.internal:26660" --thorchain="http://host.docker.internal:1317" --tx-type=swap --num=${NUM}

smoke:
	@docker run --network=host --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python smoke.py --fast-fail=True

health:
	@docker run --network=host --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app ${IMAGE_NAME} python health.py

shell:
	@docker run --network=host --rm -e PYTHONPATH=/app -v ${PWD}:/app -w /app -it ${IMAGE_NAME} sh

.PHONY: build lint format test test-watch health smoke shell
