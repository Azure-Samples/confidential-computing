#!/usr/bin/env bash
set -euo pipefail
trap 'echo "ERROR: signed-driver probe failed at line $LINENO; inspect the node and stop the disposable cluster before retrying." >&2' ERR

kernel=6.8.0-1071-azure-fde
version=615.71.09
test "$(uname -r)" = "$kernel"
test ! -d /sys/module/nvidia
test ! -e /tmp/signed-driver
test ! -e "/lib/firmware/nvidia/$version"
test -z "$(ls -A /run/nvidia/driver)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates kmod mokutil libpciaccess0
mokutil --sb-state | grep -Fx 'SecureBoot enabled'
mkdir /tmp/signed-driver
cd /tmp/signed-driver
apt-get download "linux-modules-nvidia-615-open-$kernel=6.8.0-1071.78" \
    "nvidia-firmware-615-$version=$version-0ubuntu0.24.04.2" \
    "nvidia-utils-615=$version-0ubuntu0.24.04.2" \
    "libnvidia-compute-615=$version-0ubuntu0.24.04.2" \
    "nvidia-compute-utils-615=$version-0ubuntu0.24.04.2" \
    "libnvidia-cfg1-615=$version-0ubuntu0.24.04.2"
echo "8b3ef898a5a32d08f748f197472a65903bd09a303e00f0bf94435430cc4437e0  linux-modules-nvidia-615-open-${kernel}_6.8.0-1071.78_amd64.deb" |
    sha256sum -c -
for deb in ./*.deb; do dpkg-deb -x "$deb" root; done

module_dir="$PWD/root/lib/modules/$kernel/kernel/nvidia-615-open"
for module in nvidia nvidia-uvm nvidia-modeset nvidia-drm nvidia-peermem; do
    test "$(modinfo -F signer "$module_dir/$module.ko")" = 'Canonical Ltd. Kernel Module Signing'
    test "$(modinfo -F version "$module_dir/$module.ko")" = "$version"
    test "$(modinfo -F vermagic "$module_dir/$module.ko" | cut -d' ' -f1)" = "$kernel"
done
mkdir -p "/lib/firmware/nvidia/$version"
cp -a "root/lib/firmware/nvidia/$version/." "/lib/firmware/nvidia/$version/"
modprobe ecdsa_generic
modprobe ecdh
modprobe ecc
insmod "$module_dir/nvidia.ko"
insmod "$module_dir/nvidia-uvm.ko"

export LD_LIBRARY_PATH="$PWD/root/usr/lib/x86_64-linux-gnu"
root/usr/bin/nvidia-persistenced --user root --uvm-persistence-mode --verbose \
    --nvidia-cfg-path="$LD_LIBRARY_PATH"
sleep 5
test -s /var/run/nvidia-persistenced/nvidia-persistenced.pid
kill -0 "$(cat /var/run/nvidia-persistenced/nvidia-persistenced.pid)"
root/usr/bin/nvidia-smi conf-compute -f | grep -Fx 'CC status: ON'
root/usr/bin/nvidia-smi conf-compute -e | grep -Fx 'CC Environment: PRODUCTION'
root/usr/bin/nvidia-smi conf-compute -srs 1
for attempt in 1 2 3; do
    root/usr/bin/nvidia-smi --query-gpu=uuid,persistence_mode --format=csv,noheader |
        grep -E '^GPU-[[:xdigit:]-]+, Enabled$'
    root/usr/bin/nvidia-smi conf-compute -q |
        grep -E 'CC GPUs Ready State[[:space:]]*: Ready$'
    sleep 5
done

cp -a root/. /run/nvidia/driver/
echo SIGNED_DRIVER_LOADED=1
exit 0
