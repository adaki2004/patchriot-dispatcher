# Use scripts/prepare-deploy.py to create the two-repository build context.
FROM rust:1.94.1-alpine@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS rust
RUN apk add --no-cache musl-dev gcc
WORKDIR /source
COPY patchriot-core ./patchriot-core
COPY patchriot-dispatcher ./patchriot-dispatcher
WORKDIR /source/patchriot-dispatcher
RUN cargo build --locked --release

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63
RUN apk add --no-cache ca-certificates
COPY --from=rust /source/patchriot-dispatcher/target/release/patchriot-dispatcher /usr/local/bin/patchriot-dispatcher
USER 65534:65534
ENV PATCHRIOT_BIND=[::]:7411
EXPOSE 7411
ENTRYPOINT ["/usr/local/bin/patchriot-dispatcher"]
