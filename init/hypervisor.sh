#!/bin/bash
#
# Qubes OS hypervisor detection utility
#
# Exports two variables:
#   QUBES_HYPERVISOR  = xen | kvm         (what the guest kernel sees)
#   QUBES_TRANSPORT   = xen | vchan-socket (IPC transport for qubesdb/qrexec)
#
# Under native Xen: QUBES_HYPERVISOR=xen,  QUBES_TRANSPORT=xen
# Under native KVM: QUBES_HYPERVISOR=kvm,  QUBES_TRANSPORT=vchan-socket
# Under xen-shim:   QUBES_HYPERVISOR=xen,  QUBES_TRANSPORT=vchan-socket
#
# The transport variable resolves the ambiguity when QEMU's Xen HVM
# emulation is active: the guest sees Xen CPUID leaves but the actual
# qubesdb/qrexec communication goes over virtio-vsock / vchan-socket.
#
# Detection methods for QUBES_HYPERVISOR (in order of preference):
#   1. /sys/hypervisor/type (set by Xen or QEMU Xen emulation)
#   2. Device tree hypervisor node (ARM64 KVM detection)
#   3. cpuid leaf 0x40000000 vendor string (via /proc/cpuinfo, x86 only)
#   4. Xen/KVM-specific device nodes
#   5. Virtio bus presence
#   6. systemd-detect-virt (fallback)
#   7. DMI/SMBIOS product name
#
# Detection for QUBES_TRANSPORT:
#   - /dev/virtio-ports/org.qubes-os.qubesdb present -> vchan-socket
#   - /var/run/qubes/qubesdb-initial.cache with /qubes-transport -> use it
#   - Otherwise: same as QUBES_HYPERVISOR
#

QUBES_HOST_ARCH="$(uname -m)"

detect_transport() {
    # The virtio-serial QubesDB port is the definitive indicator that
    # dom0 injected config via the KVM path (even under xen-shim).
    if [ -c /dev/virtio-ports/org.qubes-os.qubesdb ] || \
       [ -e /dev/virtio-ports/org.qubes-os.qubesdb ]; then
        echo "vchan-socket"
        return 0
    fi

    # Check the boot-time config cache written by qubesdb-config-read
    if [ -f /var/run/qubes/qubesdb-initial.cache ]; then
        local cached_transport
        cached_transport=$(grep '^/qubes-transport=' /var/run/qubes/qubesdb-initial.cache 2>/dev/null | cut -d= -f2-)
        if [ -n "$cached_transport" ]; then
            echo "$cached_transport"
            return 0
        fi
    fi

    # No virtio-serial port and no cache -> native hypervisor transport
    echo ""
    return 1
}

detect_hypervisor() {
    # Method 1: /sys/hypervisor/type (Xen-specific sysfs node, works on all arches)
    if [ -f /sys/hypervisor/type ]; then
        local hv_type
        hv_type=$(cat /sys/hypervisor/type 2>/dev/null)
        case "$hv_type" in
            xen)
                echo "xen"
                return 0
                ;;
        esac
    fi

    # Method 2: Device tree hypervisor node (ARM64 KVM/Xen detection)
    if [ "$QUBES_HOST_ARCH" = "aarch64" ]; then
        if [ -f /sys/firmware/devicetree/base/hypervisor/compatible ]; then
            local dt_compat
            dt_compat=$(cat /sys/firmware/devicetree/base/hypervisor/compatible 2>/dev/null | tr '\0' ' ')
            case "$dt_compat" in
                *kvm*)
                    echo "kvm"
                    return 0
                    ;;
                *xen*)
                    echo "xen"
                    return 0
                    ;;
            esac
        fi

        # ARM64: PSCI + virtio devices -> KVM
        if [ -d /sys/firmware/devicetree/base/psci ]; then
            if [ -d /sys/bus/virtio/devices ] && \
               [ "$(ls -A /sys/bus/virtio/devices 2>/dev/null)" ]; then
                echo "kvm"
                return 0
            fi
        fi
    fi

    # Method 3: Check /proc/cpuinfo for hypervisor vendor (x86 only)
    if [ "$QUBES_HOST_ARCH" = "x86_64" ] && [ -f /proc/cpuinfo ]; then
        if grep -qi 'KVMKVMKVM\|KVM' /proc/cpuinfo 2>/dev/null; then
            echo "kvm"
            return 0
        fi
        if grep -qi 'XenVMMXenVMM\|Xen' /proc/cpuinfo 2>/dev/null; then
            echo "xen"
            return 0
        fi
    fi

    # Method 4: Check for Xen-specific or KVM-specific device nodes
    if [ -e /dev/xen/xenbus ] || [ -d /proc/xen ]; then
        echo "xen"
        return 0
    fi
    if [ -e /dev/kvm ] || [ -d /sys/module/kvm ]; then
        echo "kvm"
        return 0
    fi

    # Method 5: Virtio bus presence (strong KVM indicator on any arch)
    if [ -d /sys/bus/virtio/devices ]; then
        if [ "$(ls -A /sys/bus/virtio/devices 2>/dev/null)" ]; then
            echo "kvm"
            return 0
        fi
    fi

    # Method 6: systemd-detect-virt (if available)
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt
        virt=$(systemd-detect-virt 2>/dev/null || true)
        case "$virt" in
            xen|xen-hvm|xen-pv)
                echo "xen"
                return 0
                ;;
            kvm|qemu)
                echo "kvm"
                return 0
                ;;
        esac
    fi

    # Method 7: DMI/SMBIOS product name (may not exist on ARM64)
    if [ -f /sys/class/dmi/id/product_name ]; then
        local product
        product=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
        case "$product" in
            *KVM*|*QEMU*|*Standard*PC*)
                echo "kvm"
                return 0
                ;;
            *Xen*|*HVM*domU*)
                echo "xen"
                return 0
                ;;
        esac
    fi

    # Default: on ARM64, assume KVM (no Xen support); on x86, assume Xen
    if [ "$QUBES_HOST_ARCH" = "aarch64" ]; then
        echo "kvm"
    else
        echo "xen"
    fi
    return 1
}

# Cache the result so we only detect once per boot
if [ -z "${QUBES_HYPERVISOR:-}" ]; then
    QUBES_HYPERVISOR=$(detect_hypervisor)
fi

if [ -z "${QUBES_TRANSPORT:-}" ]; then
    QUBES_TRANSPORT=$(detect_transport) || true
    if [ -z "$QUBES_TRANSPORT" ]; then
        # No explicit transport detected; derive from hypervisor type
        if [ "$QUBES_HYPERVISOR" = "kvm" ]; then
            QUBES_TRANSPORT="vchan-socket"
        else
            QUBES_TRANSPORT="xen"
        fi
    fi
fi

export QUBES_HYPERVISOR
export QUBES_TRANSPORT

is_xen() {
    [ "$QUBES_HYPERVISOR" = "xen" ]
}

is_kvm() {
    [ "$QUBES_HYPERVISOR" = "kvm" ]
}

is_xen_shim() {
    [ "$QUBES_HYPERVISOR" = "xen" ] && [ "$QUBES_TRANSPORT" = "vchan-socket" ]
}

uses_vchan_socket() {
    [ "$QUBES_TRANSPORT" = "vchan-socket" ]
}

is_aarch64() {
    [ "$QUBES_HOST_ARCH" = "aarch64" ]
}
