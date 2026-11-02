# Use scripts/prepare-deploy.py to create the two-repository build context.
ARG PATCHRIOT_IMAGE=service
FROM rust:1.94.1-alpine@sha256:77237dd363a0b127bb5ef532c2d64c0deb380b738e43a9c4bdac73398d6d0a08 AS rust
RUN apk add --no-cache musl-dev gcc
WORKDIR /source
COPY patchriot-core ./patchriot-core
COPY patchriot-dispatcher ./patchriot-dispatcher
WORKDIR /source/patchriot-dispatcher
RUN cargo build --locked --release --bins

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS runtime
RUN apk add --no-cache ca-certificates
USER 65534:65534

FROM runtime AS service
COPY --from=rust /source/patchriot-dispatcher/target/release/patchriot-dispatcher /usr/local/bin/patchriot-dispatcher
ENV PATCHRIOT_BIND=[::]:7411
EXPOSE 7411
ENTRYPOINT ["/usr/local/bin/patchriot-dispatcher"]

# Optional companion: userspace Tailscale, no TUN device or network capabilities.
FROM tailscale/tailscale:1.104.4@sha256:ed6480b33c6eb67c9cbd203ed42b9fb57e361986725b6856def71b7a3d9e276c AS tailscale
FROM runtime AS mesh
USER root
COPY --from=rust /source/patchriot-dispatcher/target/release/patchriot-relay-gateway /usr/local/bin/patchriot-relay-gateway
COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscaled /usr/local/bin/containerboot /usr/local/bin/
COPY patchriot-dispatcher/NOTICE /usr/share/licenses/patchriot-dispatcher/NOTICE
COPY patchriot-dispatcher/deploy/serve.json /etc/patchriot/serve.json
COPY --chmod=755 patchriot-dispatcher/deploy/start-gateway.sh /usr/local/bin/start-gateway
RUN mkdir -p /var/lib/tailscale && chown 65534:65534 /var/lib/tailscale && chmod 700 /var/lib/tailscale
USER 65534:65534
ENV TS_STATE_DIR=/var/lib/tailscale TS_HOSTNAME=patchriot-gateway
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD wget -q -O /dev/null http://127.0.0.1:9002/healthz && wget -q -O /dev/null http://127.0.0.1:7412/health
ENTRYPOINT ["/usr/local/bin/start-gateway"]

# The normal dispatcher remains the default. Select mesh explicitly at build time.
FROM ${PATCHRIOT_IMAGE}
