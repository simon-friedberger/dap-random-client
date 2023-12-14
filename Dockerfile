FROM lukemathwalker/cargo-chef:latest-rust-1.74-bookworm AS chef
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
WORKDIR /app
ARG JANUS_VERSION=0.6.6
RUN \
    apt-get -qq update && \
    apt-get -qq install -y git && \
    git clone https://github.com/divviup/janus.git . && \
    git checkout -b ${JANUS_VERSION} ${JANUS_VERSION} && \
    cargo chef prepare --recipe-path recipe.json

# Build dap-random-client
FROM chef AS builder-janus
COPY --from=planner-janus /app/. .
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
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
COPY ./divviupconfig-dev.json .
COPY ./divviupconfig-stage.json .
COPY ./divviupconfig-prod.json .

USER app

ENTRYPOINT ["/app/dap-random-client"]
