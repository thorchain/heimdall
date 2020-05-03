[![pipeline status](https://gitlab.com/thorchain/heimdall/badges/master/pipeline.svg)](https://gitlab.com/thorchain/heimdall/commits/master)
[![coverage report](https://gitlab.com/thorchain/heimdall/badges/master/coverage.svg)](https://gitlab.com/thorchain/heimdall/-/commits/master)


Heimdall

****

> **Mirror**
>
> This repo mirrors from THORChain Gitlab to Github.
> To contribute, please contact the team and commit to the Gitlab repo:
>
> https://gitlab.com/thorchain/heimdall


****
========

Heimdall is the gatekeeper who sees all. His role within the stack is to
ensure all the various components function and work properly. He verifies that
THORchain operates with the correct mathematics, emits the correct events,
crypto, etc.

## Requirements
 *  Python 3
 *  Docker

## Build Heimdall

Build docker image to run Heimdall:

```bash
make build
```

## Unit Testing

```bash
make test
```

#### Continuous Unit Testing
If you want to continuously run tests as you save files, install
`pytest-watch`

```bash
pip3 install pytest-watch
```

Then run the follow make command...

```bash
make test-watch
```

## Integration Testing
To run a suite of tests against a live Thorchain complete stack, start one up
locally.

### Start THORNode stack

```bash
git clone --single-branch -b master https://gitlab.com/thorchain/thornode.git
cd thornode
docker pull registry.gitlab.com/thorchain/thornode:mocknet
make -C thornode/build/docker reset-mocknet-standalone
```

### Run smoke tests

```bash
make smoke
```

### Run health tests

```bash
make health
```

### Run Bitcoin reorg tests

```bash
make bitcoin-reorg
```

## Benchmark THORNode

Expect an environment variable NUM to specify the number of txs to generate.

```bash
NUM=100 make benchmark-stake
NUM=100 make benchmark-swap
```

## Misc Tools

### Run linting

```bash
make lint
```

### Format the code

```bash
make format
```
