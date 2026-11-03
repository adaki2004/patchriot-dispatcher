#!/bin/sh
# Railway mounts volumes as root. Only this fixed directory needs preparation;
# the gateway and Tailscale always start without root or Linux capabilities.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if [ "$(id -u)" = 0 ]; then
  if [ "${TS_STATE_DIR:-/var/lib/tailscale}" != /var/lib/tailscale ] || [ -L /var/lib/tailscale ]; then
    echo "Root initialization only supports the real /var/lib/tailscale directory." >&2
    exit 1
  fi
  mkdir -p /var/lib/tailscale
  # No recursive ownership changes: existing state files are never rewritten.
  chown 65534:65534 /var/lib/tailscale
  chmod 700 /var/lib/tailscale
  exec /bin/setpriv --reuid=65534 --regid=65534 --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    /usr/local/bin/start-gateway
fi
exec /usr/local/bin/start-gateway
