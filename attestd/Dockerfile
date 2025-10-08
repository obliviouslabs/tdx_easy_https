# Use the official Rust image as the build environment
FROM rust:latest AS builder

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml ./

# Copy the source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Use a minimal Debian image for the runtime
FROM debian:bookworm-slim

# Install CA certificates if needed (for HTTPS, but probably not necessary here)
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/attestd /usr/local/bin/attestd

# Expose port 80
EXPOSE 80

# Run the application
CMD ["/usr/local/bin/attestd"]