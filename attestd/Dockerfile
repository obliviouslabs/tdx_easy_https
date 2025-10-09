FROM rust:latest AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/attestd /usr/local/bin/attestd
EXPOSE 80
CMD ["/usr/local/bin/attestd"]