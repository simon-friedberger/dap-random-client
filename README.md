# Description

This is supposed to be a working DAP client for testing servers and
infrastructure.

## Usage

### Submit Reports

```
DAP_ENV=prod cargo run
```

`DAP_ENV` can be any of `prod`, `stage`, and `dev` with `dev` is used as the default if this environment variable is not specified.

## Run via Docker

A docker image is provided to run the submission job with `dap-random-client` and then the collection job with `janus-collect`. By default, it will submit reports to the `dev` environment (for the Aggregator/Helper), you need to provide the following environment variables for the collection job.

- `DAP_AUTH_BEARER_TOKEN`
- `DAP_HPKE_CONFIG`
- `DAP_HPKE_PRIVATE_KEY`

You can also set the following environment variables to override the default settings.

- `DAP_ENV=dev`
- `DAP_DURATION=600`
- `DAP_TASK_ID="yL5q2lPLTl1VgHvMEUBB8BEunmdmb7-7QKiRxI0ocTU"`
- `DAP_LEADER="https://dap-07-1.api.divviup.org"`
- `DAP_VDAF=sum`
- `DAP_VDAF_ARGS="--bits 1"`
