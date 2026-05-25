#!/bin/sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "usage: sh install-podman-server.sh <public-host-or-ip> [release-tag]" >&2
  exit 1
fi

HOST="$1"
TAG="${2:-latest}"
NETWORK="${WARDEN_NETWORK:-ai-warden-net}"
SERVER_NAME="${WARDEN_SERVER_NAME:-warden-server}"
CADDY_NAME="${WARDEN_CADDY_NAME:-warden-caddy}"
IDLE_TIMEOUT="${WARDEN_SESSION_IDLE_TIMEOUT_SECONDS:-600}"
MAX_IDLE_TIMEOUT="${WARDEN_SESSION_MAX_IDLE_TIMEOUT_SECONDS:-7200}"
IDLE_WARNING="${WARDEN_SESSION_IDLE_WARNING_SECONDS:-60}"
IMAGE="ghcr.io/ai-remote-warden/warden-server:${TAG}"
CADDY_IMAGE="docker.io/library/caddy:2"
CONFIG_DIR="${WARDEN_CONFIG_DIR:-/tmp/warden-deploy}"
CADDYFILE="${CONFIG_DIR}/Caddyfile"
USE_TLS_INTERNAL="yes"

if [ "${WARDEN_HTTP_PORT:-}" != "" ]; then
  HTTP_PORT="${WARDEN_HTTP_PORT}"
elif [ "$(id -u)" -eq 0 ]; then
  HTTP_PORT="80"
else
  HTTP_PORT="8080"
fi

if [ "${WARDEN_HTTPS_PORT:-}" != "" ]; then
  HTTPS_PORT="${WARDEN_HTTPS_PORT}"
elif [ "$(id -u)" -eq 0 ]; then
  HTTPS_PORT="443"
else
  HTTPS_PORT="8443"
fi

case "${HOST}" in
  *[!0-9.]* | *.*.*.*.* | "")
    ;;
  *.*.*.*)
    USE_TLS_INTERNAL="no"
    ;;
esac

if [ "${USE_TLS_INTERNAL}" = "yes" ]; then
  PUBLIC_HOST="https://${HOST}"
  VERIFY_HOST="${HOST}"
  if [ "${HTTPS_PORT}" != "443" ]; then
    PUBLIC_HOST="${PUBLIC_HOST}:${HTTPS_PORT}"
    VERIFY_HOST="${VERIFY_HOST}:${HTTPS_PORT}"
  fi
else
  PUBLIC_HOST="http://${HOST}"
  VERIFY_HOST="${HOST}"
  if [ "${HTTP_PORT}" != "80" ]; then
    PUBLIC_HOST="${PUBLIC_HOST}:${HTTP_PORT}"
    VERIFY_HOST="${VERIFY_HOST}:${HTTP_PORT}"
  fi
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required but not installed" >&2
  exit 1
fi

mkdir -p "${CONFIG_DIR}"

podman pull "${IMAGE}"
podman rm -f "${CADDY_NAME}" "${SERVER_NAME}" >/dev/null 2>&1 || true

if [ "${USE_TLS_INTERNAL}" = "yes" ]; then
  cat > "${CADDYFILE}" <<EOF
${HOST} {
	tls internal
	reverse_proxy ${SERVER_NAME}:8080
}
EOF

  if ! podman network exists "${NETWORK}"; then
    podman network create "${NETWORK}"
  fi

  podman pull "${CADDY_IMAGE}"

  podman run --replace -d \
    --name "${SERVER_NAME}" \
    --network "${NETWORK}" \
    --network-alias "${SERVER_NAME}" \
    -e WARDEN_CONTROL_ADDR=:8080 \
    -e WARDEN_PUBLIC_HOST="${PUBLIC_HOST}" \
    -e WARDEN_SESSION_IDLE_TIMEOUT_SECONDS="${IDLE_TIMEOUT}" \
    -e WARDEN_SESSION_MAX_IDLE_TIMEOUT_SECONDS="${MAX_IDLE_TIMEOUT}" \
    -e WARDEN_SESSION_IDLE_WARNING_SECONDS="${IDLE_WARNING}" \
    "${IMAGE}"

  podman run --replace -d \
    --name "${CADDY_NAME}" \
    --network "${NETWORK}" \
    -p "${HTTP_PORT}:80" \
    -p "${HTTPS_PORT}:443" \
    -v "${CADDYFILE}:/etc/caddy/Caddyfile:ro" \
    -v caddy_data:/data \
    -v caddy_config:/config \
    "${CADDY_IMAGE}"

  echo "Warden server started with Caddy TLS."
  echo "Host: ${PUBLIC_HOST}"
  echo "Image: ${IMAGE}"
  echo "Verify: curl -k https://${VERIFY_HOST}/v1/policy/default"
  echo "Logs:"
  echo "  podman logs -f ${SERVER_NAME}"
  echo "  podman logs -f ${CADDY_NAME}"
else
  podman run --replace -d \
    --name "${SERVER_NAME}" \
    -p "${HTTP_PORT}:8080" \
    -e WARDEN_CONTROL_ADDR=:8080 \
    -e WARDEN_PUBLIC_HOST="${PUBLIC_HOST}" \
    -e WARDEN_SESSION_IDLE_TIMEOUT_SECONDS="${IDLE_TIMEOUT}" \
    -e WARDEN_SESSION_MAX_IDLE_TIMEOUT_SECONDS="${MAX_IDLE_TIMEOUT}" \
    -e WARDEN_SESSION_IDLE_WARNING_SECONDS="${IDLE_WARNING}" \
    "${IMAGE}"

  echo "WARNING: ${HOST} looks like an IP address, so the quick-start deployment is using plain HTTP."
  echo "WARNING: Traffic is not encrypted. Use this only for testing or private networks."
  echo "WARNING: To enable HTTPS, redeploy with a DNS name instead of an IP address."
  echo "Warden server started."
  echo "Host: ${PUBLIC_HOST}"
  echo "Image: ${IMAGE}"
  echo "Verify: curl ${PUBLIC_HOST}/v1/policy/default"
  echo "Logs:"
  echo "  podman logs -f ${SERVER_NAME}"
fi
