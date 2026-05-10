FROM rust:1.82-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin operator

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/operator /usr/local/bin/operator
COPY --from=builder /app/crates/operator/static /static

EXPOSE 8080 50051

ENTRYPOINT ["operator"]
CMD ["operator.toml"]
