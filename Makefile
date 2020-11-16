include Makefile.cicd
IMAGE_NAME = registry.gitlab.com/thorchain/heimdall
LOGLEVEL?=INFO
RUNE?=THOR.RUNE
DOCKER_OPTS = --network=host --rm -e RUNE=${RUNE} -e LOGLEVEL=${LOGLEVEL} -e PYTHONPATH=/app -v ${PWD}:/app -w /app

clean:
	rm *.pyc

build:
	@docker build -t ${IMAGE_NAME} .

lint:
	@docker run --rm -v ${PWD}:/app pipelinecomponents/flake8:latest flake8

format:
	@docker run --rm -v ${PWD}:/app cytopia/black /app

test:
	@docker run ${DOCKER_OPTS} -e EXPORT=${EXPORT} -e EXPORT_EVENTS=${EXPORT_EVENTS} ${IMAGE_NAME} python -m unittest tests/test_*

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

kube-smoke:
	@kubectl replace --force -f kube/smoke.yml

kube-benchmark-stake:
	@sed -e 's|NUM|${NUM}|g' kube/benchmark-stake.yml | kubectl replace --force -f -

kube-benchmark-swap:
	@sed -e 's|NUM|${NUM}|g' kube/benchmark-swap.yml | kubectl replace --force -f -

health:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/health.py

health-chaosnet:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/health.py --binance-api=https://dex.binance.org --thorchain=http://18.159.165.210:1317 --midgard=http://18.159.165.210:8080 --margin-err=0.1

bitcoin-reorg:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/smoke.py --fast-fail=True --bitcoin-reorg=True

ethereum-reorg:
	@docker run ${DOCKER_OPTS} ${IMAGE_NAME} python scripts/smoke.py --fast-fail=True --ethereum-reorg=True

shell:
	@docker run ${DOCKER_OPTS} -it ${IMAGE_NAME} sh

.PHONY: build lint format test test-watch health smoke shell
