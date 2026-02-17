#!/bin/bash
#
# qubesdb-hotplug-watcher.sh - Watch qubesdb for device changes
#
# On KVM, this replaces xenstore watches for device hotplug notifications.
# Watches qubesdb paths for block device and network device changes,
# then triggers appropriate udev/systemd actions.
#

set -euf

. /usr/lib/qubes/init/functions

# Only run under KVM
is_kvm || exit 0

log() {
    logger -t "qubesdb-hotplug" -- "$@"
}

# Watch for block device changes
watch_block_devices() {
    qubesdb-watch /qubes-block-devices/ | while read -r path; do
        local action
        local dev_path
        action=$(qubesdb-read "${path}/action" 2>/dev/null || echo "")
        dev_path=$(qubesdb-read "${path}/device" 2>/dev/null || echo "")

        case "$action" in
            add)
                log "Block device add: $dev_path"
                udevadm trigger --action=add --subsystem-match=block \
                    --property-match=DEVNAME="$dev_path" 2>/dev/null || :
                ;;
            remove)
                log "Block device remove: $dev_path"
                udevadm trigger --action=remove --subsystem-match=block \
                    --property-match=DEVNAME="$dev_path" 2>/dev/null || :
                ;;
        esac
    done
}

# Watch for network configuration changes
watch_network() {
    qubesdb-watch /qubes-netvm-external-ip/ /qubes-ip /qubes-gateway | while read -r path; do
        log "Network config changed: $path"
        systemctl restart qubes-network.service 2>/dev/null || :
    done
}

# Watch for USB device changes
watch_usb_devices() {
    qubesdb-watch /qubes-usb-devices/ | while read -r path; do
        local action
        action=$(qubesdb-read "${path}/action" 2>/dev/null || echo "")
        log "USB device change: $path action=$action"
    done
}

log "Starting qubesdb hotplug watcher"

# Run all watchers in parallel
watch_block_devices &
watch_network &
watch_usb_devices &

wait
