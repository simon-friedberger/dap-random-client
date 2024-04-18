FROM lukemathwalker/cargo-chef:latest-rust-1.75-bookworm AS chef
WORKDIR /app

# Plan for dap-random-client
FROM chef AS planner-client
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Build dap-random-client
FROM chef AS builder-client
COPY --from=planner-client /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Plan for janus-collector
FROM chef AS planner-janus
ARG JANUS_VERSION=0.7.5
RUN \
    apt-get -qq update && \
    apt-get -qq install -y git && \
    git clone https://github.com/divviup/janus.git . && \
    git checkout -b ${JANUS_VERSION} ${JANUS_VERSION} && \
    cargo chef prepare --recipe-path recipe.json

# Build janus
FROM chef AS builder-janus
COPY --from=planner-janus /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN \
    apt-get -qq update && \
    apt-get -qq install -y cmake && \
    cargo chef cook --release --recipe-path recipe.json
COPY --from=planner-janus /app/. .
RUN cargo build --release --bin collect

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN \
    groupadd --gid 10001 app && \
    useradd --uid 10001 --gid 10001 --home /app --create-home app && \
    apt-get -qq update && \
    apt-get -qq install -y libssl-dev pkg-config ca-certificates && \
    rm -rf /var/lib/apt/lists

COPY --from=builder-client /app/target/release/dap-random-client .
COPY --from=builder-janus /app/target/release/collect .
COPY ./scripts/submit-n-collect.sh .
COPY ./*.json .

USER app

# Submission settings
#ENV DAP_ENV=
ENV DAP_CFG=divviup-stage-only.json
ENV DAP_CLIENT=/app/dap-random-client

# Collection settings
ENV DAP_DURATION=300
ENV DAP_COLLECTOR=/app/collect
ENV DAP_TASK_ID="k4gk4F49vbDpKItMjnLulsijY_gKfMHsqJiUaFpmzXs"
ENV DAP_LEADER="https://staging-dap-09-1.api.divviup.org"
ENV DAP_AUTH_BEARER_TOKEN=
ENV DAP_VDAF=sumvec
ENV DAP_VDAF_ARGS="--bits 8 --length 20"
ENV DAP_HPKE_CONFIG=
ENV DAP_HPKE_PRIVATE_KEY=
ENTRYPOINT ["/app/submit-n-collect.sh"]
