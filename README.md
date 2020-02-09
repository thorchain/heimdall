[![pipeline status](https://gitlab.com/thorchain/heimdall/badges/master/pipeline.svg)](https://gitlab.com/thorchain/heimdall/commits/master)

Heimdall
========
Heimdall is the gatekeeper who sees all. His role within the stack is to
ensure all the various components function and work properly. He verifies that
THORchain operates with the correct mathematics, emits the correct events,
crypto, etc.

## Run

```bash
make run
```

## Testing

```bash
make test
```

#### Continuous Testing
If you want to continuously run tests as you save files, install
`pytest-watch`

```bash
pip install pytest-watch
```

Then run the follow make command...

```bash
make test-watch
```
