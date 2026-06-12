FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/attestd /usr/local/bin/attestd
EXPOSE 80
CMD ["/usr/local/bin/attestd"]
