#!/bin/bash
#
# qubes-domain-id.sh - Determine and export the local domain ID
#
# Under Xen, the domain ID comes from /proc/xen/xsd_port or similar.
# Under KVM, we read it from qubesdb (/qubes-domain-id) or from the
# virtio-serial initial config cache, or derive it from libvirt metadata.
#
# Exports VCHAN_DOMAIN for use by vchan-socket connections.
#

. /usr/lib/qubes/init/hypervisor.sh

get_domain_id() {
    # Method 1: Read from qubesdb (works after qubesdb is connected)
    if command -v qubesdb-read >/dev/null 2>&1; then
        local qdb_id
        qdb_id=$(qubesdb-read /qubes-domain-id 2>/dev/null)
        if [ -n "$qdb_id" ] && [ "$qdb_id" -gt 0 ] 2>/dev/null; then
            echo "$qdb_id"
            return 0
        fi
    fi

    # Method 2: Read from initial config cache (KVM boot-time injection)
    if [ -f /var/run/qubes/qubesdb-initial.cache ]; then
        local cached_id
        cached_id=$(grep '^/qubes-domain-id=' /var/run/qubes/qubesdb-initial.cache 2>/dev/null | cut -d= -f2-)
        if [ -n "$cached_id" ] && [ "$cached_id" -gt 0 ] 2>/dev/null; then
            echo "$cached_id"
            return 0
        fi
    fi

    # Method 3: Xen-specific: read from /proc/xen
    if is_xen && [ -f /proc/xen/xsd_port ]; then
        # Under Xen, the domain ID is available via xenstore or /proc
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

    # Fallback: domain 0 means dom0, use 1 as default for guest VMs
    if is_kvm; then
        echo "1"
    else
        echo "0"
    fi
    return 1
}

# Determine and export the domain ID
if [ -z "${VCHAN_DOMAIN:-}" ]; then
    VCHAN_DOMAIN=$(get_domain_id)
fi
export VCHAN_DOMAIN
