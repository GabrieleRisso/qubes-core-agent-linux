#!/bin/bash
#
# qubes-domain-id.sh - Determine and export the local domain ID
#
# Under Xen, the domain ID comes from xenstore.
# Under KVM (and xen-shim), we read it from the virtio-serial initial
# config cache (written by qubesdb-config-read at boot), or from
# qubesdb after the vchan-socket connection is up.
#
# Exports VCHAN_DOMAIN for use by vchan-socket connections.
#

. /usr/lib/qubes/init/hypervisor.sh

get_domain_id() {
    # Method 1: Read from initial config cache (KVM/xen-shim boot-time
    # injection).  This is available before qubesdb-daemon connects and
    # is the primary source when using vchan-socket transport.
    if [ -f /var/run/qubes/qubesdb-initial.cache ]; then
        local cached_id
        cached_id=$(grep '^/qubes-domain-id=' /var/run/qubes/qubesdb-initial.cache 2>/dev/null | cut -d= -f2-)
        if [ -n "$cached_id" ] && [ "$cached_id" -gt 0 ] 2>/dev/null; then
            echo "$cached_id"
            return 0
        fi
    fi

    # Method 2: Read from qubesdb (works after qubesdb is connected)
    if command -v qubesdb-read >/dev/null 2>&1; then
        local qdb_id
        qdb_id=$(qubesdb-read /qubes-domain-id 2>/dev/null)
        if [ -n "$qdb_id" ] && [ "$qdb_id" -gt 0 ] 2>/dev/null; then
            echo "$qdb_id"
            return 0
        fi
    fi

    # Method 3: Xen-specific: read from xenstore (only for native Xen,
    # not xen-shim; under xen-shim QEMU's xenstore emulation is local
    # and may not have the domain ID).
    if is_xen && ! uses_vchan_socket && [ -f /proc/xen/xsd_port ]; then
        local xen_domid
        xen_domid=$(xenstore-read domid 2>/dev/null)
        if [ -n "$xen_domid" ]; then
            echo "$xen_domid"
            return 0
        fi
    fi

    # Method 4: Read from DMI/SMBIOS (some KVM configurations set this)
    if [ -f /sys/class/dmi/id/chassis_serial ]; then
        local serial
        serial=$(cat /sys/class/dmi/id/chassis_serial 2>/dev/null)
        if [ -n "$serial" ] && [ "$serial" -gt 0 ] 2>/dev/null; then
            echo "$serial"
            return 0
        fi
    fi

    # Fallback: use 1 for vchan-socket guests, 0 for Xen
    if uses_vchan_socket; then
        echo "1"
    else
        echo "0"
    fi
    return 1
}

if [ -z "${VCHAN_DOMAIN:-}" ]; then
    VCHAN_DOMAIN=$(get_domain_id)
fi
export VCHAN_DOMAIN
