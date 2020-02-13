[![pipeline status](https://gitlab.com/thorchain/heimdall/badges/master/pipeline.svg)](https://gitlab.com/thorchain/heimdall/commits/master)

Heimdall
========
Heimdall is the gatekeeper who sees all. His role within the stack is to
ensure all the various components function and work properly. He verifies that
THORchain operates with the correct mathematics, emits the correct events,
crypto, etc.

## Requirements
 *  Python 3
 *  Docker

## Testing

```bash
make test
```

#### Continuous Testing
If you want to continuously run tests as you save files, install
`pytest-watch`

```bash
pip3 install pytest-watch
```

Then run the follow make command...

```bash
make test-watch
```

### Integration Testing
To run a suite of tests against a live Thorchain complete stack, start one up
locally.

```bash
git clone --single-branch -b master https://gitlab.com/thorchain/thornode.git
cd thornode
docker pull registry.gitlab.com/thorchain/thornode:mocknet
make -C thornode/build/docker reset-mocknet-standalone
pip3 install -r requirements.txt
python3 smoke.py
```
