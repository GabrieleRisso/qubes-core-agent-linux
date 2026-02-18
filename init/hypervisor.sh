#!/bin/bash
#
# Qubes OS hypervisor detection utility
#
# Detects whether the VM is running under Xen or KVM and exports
# QUBES_HYPERVISOR=xen|kvm for use by boot scripts.
#
# Detection methods (in order of preference):
#   1. /sys/hypervisor/type (set by Xen)
#   2. Device tree hypervisor node (ARM64 KVM detection)
#   3. cpuid leaf 0x40000000 vendor string (via /proc/cpuinfo, x86 only)
#   4. Xen/KVM-specific device nodes
#   5. systemd-detect-virt (fallback)
#   6. DMI/SMBIOS product name
#
# Architecture notes:
#   - On x86_64, cpuid and DMI are the primary detection methods
#   - On aarch64, device tree and virtio device presence are used instead
#     (ARM has no cpuid instruction and may lack DMI/SMBIOS)
#

QUBES_HOST_ARCH="$(uname -m)"

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
    # On ARM64, QEMU's 'virt' machine type exposes hypervisor info via DT.
    # KVM sets compatible = "linux,kvm" in the /hypervisor DT node.
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

        # ARM64: Check for KVM via PSCI (Power State Coordination Interface)
        # KVM on ARM64 uses PSCI for CPU management; its presence with
        # virtio devices strongly indicates KVM.
        if [ -d /sys/firmware/devicetree/base/psci ]; then
            if [ -d /sys/bus/virtio/devices ] && \
               [ "$(ls -A /sys/bus/virtio/devices 2>/dev/null)" ]; then
                echo "kvm"
                return 0
            fi
        fi
    fi

    # Method 3: Check /proc/cpuinfo for hypervisor vendor (x86 only)
    # ARM64 does not have cpuid; this method is skipped on aarch64.
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

export QUBES_HYPERVISOR

is_xen() {
    [ "$QUBES_HYPERVISOR" = "xen" ]
}

is_kvm() {
    [ "$QUBES_HYPERVISOR" = "kvm" ]
}

is_aarch64() {
    [ "$QUBES_HOST_ARCH" = "aarch64" ]
}
