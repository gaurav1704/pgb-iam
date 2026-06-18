FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev linux-pam-dev pkgconfig
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && touch src/lib.rs src/main.rs
RUN cargo build --release 2>/dev/null; true
COPY src/ src/
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates linux-pam
COPY --from=builder /app/target/release/pgb-iam /usr/local/bin/pgb-iam
COPY config.toml global-bundle.pem /etc/pgb-iam/
WORKDIR /etc/pgb-iam
EXPOSE 6432 9090 9091
ENTRYPOINT ["pgb-iam"]
