#!/bin/bash
#
# Qubes OS hypervisor detection utility
#
# Detects whether the VM is running under Xen or KVM and exports
# QUBES_HYPERVISOR=xen|kvm for use by boot scripts.
#
# Detection methods (in order of preference):
#   1. /sys/hypervisor/type (set by Xen)
#   2. cpuid leaf 0x40000000 vendor string (via /proc/cpuinfo)
#   3. systemd-detect-virt (fallback)
#   4. DMI/SMBIOS product name
#

detect_hypervisor() {
    # Method 1: /sys/hypervisor/type (Xen-specific sysfs node)
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

    # Method 2: Check /proc/cpuinfo for hypervisor vendor
    if [ -f /proc/cpuinfo ]; then
        if grep -qi 'KVMKVMKVM\|KVM' /proc/cpuinfo 2>/dev/null; then
            echo "kvm"
            return 0
        fi
        if grep -qi 'XenVMMXenVMM\|Xen' /proc/cpuinfo 2>/dev/null; then
            echo "xen"
            return 0
        fi
    fi

    # Method 3: Check for Xen-specific or KVM-specific device nodes
    if [ -e /dev/xen/xenbus ] || [ -d /proc/xen ]; then
        echo "xen"
        return 0
    fi
    if [ -e /dev/kvm ] || [ -d /sys/module/kvm ]; then
        echo "kvm"
        return 0
    fi

    # Method 4: systemd-detect-virt (if available)
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

    # Method 5: DMI/SMBIOS product name
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

    # Default: assume Xen for backward compatibility
    echo "xen"
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
