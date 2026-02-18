#!/bin/bash
#
# qubes-vchan-env.sh - Generate systemd environment file for vchan services
#
# Runs early in boot (after qubesdb-config-read) to produce
# /run/qubes/vchan.env with VCHAN_DOMAIN and VCHAN_TRANSPORT.
# This file is sourced by qubes-db.service and qrexec-agent.service
# via EnvironmentFile= so they know the domain ID and transport mode.
#
# Boot chain:
#   qubesdb-config-read.service  (reads virtio-serial -> cache file)
#   -> qubes-vchan-env.service   (THIS: reads cache -> env file)
#   -> qubes-db.service          (qubesdb-daemon, uses VCHAN_DOMAIN)
#   -> qubes-qrexec-agent.service (qrexec agent, uses VCHAN_DOMAIN)
#

set -euf

. /usr/lib/qubes/init/hypervisor.sh
. /usr/lib/qubes/init/qubes-domain-id.sh

ENV_DIR="/run/qubes"
ENV_FILE="${ENV_DIR}/vchan.env"

mkdir -p "$ENV_DIR"

{
    echo "VCHAN_DOMAIN=${VCHAN_DOMAIN}"
    echo "VCHAN_TRANSPORT=${QUBES_TRANSPORT}"

    # For vchan-socket library: set transport to vsock when virtio-vsock
    # is available (indicated by /dev/vsock or vsock kernel module).
    if [ -e /dev/vsock ] || [ -d /sys/module/vmw_vsock_virtio_transport ]; then
        echo "VCHAN_TRANSPORT_MODE=vsock"
    else
        echo "VCHAN_TRANSPORT_MODE=unix"
    fi

    echo "QUBES_HYPERVISOR=${QUBES_HYPERVISOR}"
} > "${ENV_FILE}"

chmod 0644 "${ENV_FILE}"
echo "qubes-vchan-env: wrote ${ENV_FILE} (domain=${VCHAN_DOMAIN}, transport=${QUBES_TRANSPORT})" >&2
