FROM rust:1.68-alpine3.17 as build

RUN apk add --no-cache musl-dev

ADD . /src
WORKDIR /src

RUN cargo build --locked --release

FROM scratch

EXPOSE ${PORT:-8000}

COPY --from=build /src/target/release/whoop /whoop

ENTRYPOINT [ "/whoop" ]
