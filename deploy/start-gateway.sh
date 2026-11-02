#!/bin/sh
# One managed gateway per state volume. Neither child receives the other's key.
set -eu
umask 077
: "${DATABASE_URL:?DATABASE_URL is required}"
: "${PATCHRIOT_AUDIENCE:?PATCHRIOT_AUDIENCE is required}"
if [ "$(id -u)" = 0 ]; then
  echo "Run the gateway as an unprivileged user." >&2
  exit 1
fi
export TS_STATE_DIR="${TS_STATE_DIR:-/var/lib/tailscale}"
case "$TS_STATE_DIR" in /*) ;; *) echo "TS_STATE_DIR must be absolute." >&2; exit 1;; esac
if [ -L "$TS_STATE_DIR" ]; then
  echo "Tailscale state must be a real private directory." >&2
  exit 1
fi
mkdir -p "$TS_STATE_DIR"
chmod 700 "$TS_STATE_DIR"
if [ ! -w "$TS_STATE_DIR" ]; then
  echo "The state volume must be writable by the gateway user." >&2
  exit 1
fi
if [ -z "${TS_AUTHKEY:-}" ] && [ ! -s "$TS_STATE_DIR/tailscaled.state" ]; then
  echo "A tagged Tailscale auth key or existing private machine state is required." >&2
  exit 1
fi

# Pin the transport: no Funnel, exit node, subnet routing, SSH or generic proxy.
unset TS_DEST_IP TS_ROUTES TS_TAILNET_TARGET_IP TS_TAILNET_TARGET_FQDN
unset TS_SOCKS5_SERVER TS_OUTBOUND_HTTP_PROXY_LISTEN TS_EXTRA_ARGS TS_TAILSCALED_EXTRA_ARGS
unset TS_CLIENT_ID TS_CLIENT_SECRET TS_ID_TOKEN
export TS_USERSPACE=true TS_AUTH_ONCE=true TS_ACCEPT_DNS=false TS_KUBE_SECRET=""
export TS_SOCKET=/tmp/patchriot-tailscaled.sock TS_SERVE_CONFIG=/etc/patchriot/serve.json
export TS_LOCAL_ADDR_PORT=127.0.0.1:9002 TS_ENABLE_HEALTH_CHECK=true TS_ENABLE_METRICS=false

gateway_pid=""
mesh_pid=""
cleanup() {
  trap '' INT TERM
  for child in "$gateway_pid" "$mesh_pid"; do
    if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null || true; fi
  done
  wait || true
}
trap cleanup EXIT
trap 'exit 0' INT TERM
(
  unset TS_AUTHKEY PATCHRIOT_INTERNAL_KEY PATCHRIOT_JEV_OPENROUTER_KEY
  exec patchriot-relay-gateway
) &
gateway_pid=$!
(
  unset DATABASE_URL PATCHRIOT_AUDIENCE PATCHRIOT_INTERNAL_KEY PATCHRIOT_JEV_OPENROUTER_KEY
  exec containerboot
) &
mesh_pid=$!

while kill -0 "$gateway_pid" 2>/dev/null && kill -0 "$mesh_pid" 2>/dev/null; do
  sleep 1
done
echo "A gateway process stopped; shutting down its companion." >&2
exit 1
