FROM rust:1.68-slim as build

RUN apt-get update && apt-get install -y musl-tools build-essential
RUN rustup target add x86_64-unknown-linux-musl

ADD . /src
WORKDIR /src

RUN cargo build --locked --release --target x86_64-unknown-linux-musl

FROM alpine:3.17 as runtime

COPY --from=build /src/target/x86_64-unknown-linux-musl/release/whoop /whoop

ENTRYPOINT [ "/whoop" ]
