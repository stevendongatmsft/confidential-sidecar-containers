#!/bin/bash

set -e

die() { echo "$*" 1>&2 ; exit 1; }

if [ $# -ne 2 ]; then
        die "Usage: build.sh <kernel-rpm> <work-dir>"
fi

KERNEL=$1

[ -f $KERNEL ] || die "Kernel package ($KERNEL) doesn't exist"

# Extract the kernel version string.
KERNEL_VER=$(echo $(basename $KERNEL) | sed 's/kernel-uvm-\(.*\).x86_64.rpm/\1/')
if [ -z "$KERNEL_VER" ]; then
        die "Unable to determine kernel version, expecting file name to be 'kernel-uvm-VER.x86_64.rpm'"
fi
echo Kernel id: ${KERNEL_VER}

# Check that the devel package exists.
DEVEL=$(echo $(basename $KERNEL) | sed 's/kernel-uvm-\(.*\).x86_64.rpm/kernel-uvm-devel-\1.x86_64.rpm/')
DEVEL="$(dirname $KERNEL)/$DEVEL"
[ -f $DEVEL ] || die "Kernel devel package ($DEVEL) doesn't exist"

# Create work directory and extract rpms to it.
WORK_DIR=$2
mkdir -p $WORK_DIR

cp $KERNEL $WORK_DIR
cp $DEVEL $WORK_DIR

echo "Extracting kernel files"
pushd $WORK_DIR

rpm2archive $(basename $KERNEL) 
rmp2archive $(basename $DEVEL)
tar xzf $(basename $KERNEL).tgz --one-top-level=kernel
tar xzf $(basename $DEVEL).tgz --one-top-level=kernel

echo "Cloning kata-containers repo"
git clone --depth 1 --branch cc-msft-prototypes https://github.com/microsoft/kata-containers.git

echo "Building containerd"
git clone --depth 1 --branch wedsonaf/tardev https://github.com/microsoft/confidential-containers-containerd.git
pushd confidential-containers-containerd/
GODEBUG=1 make
popd

echo "Building kata runtime"
pushd kata-containers/src/runtime/
make SKIP_GO_VERSION_CHECK=1
popd

echo "Building tardev snapshotter"
pushd kata-containers/src/tardev-snapshotter
make
popd

echo "Building kernel module"
pushd kata-containers/src/tarfs
make KDIR=../../../kernel/usr/src/linux-headers-${KERNEL_VER}
make KDIR=../../../kernel/usr/src/linux-headers-${KERNEL_VER} install
popd
KERNEL_MODULES_DIR=$PWD/kata-containers/src/tarfs/_install/lib/modules/${KERNEL_VER}

echo "Building the agent"
pushd kata-containers/src/agent
make LIBC=gnu BUILD_TYPE=debug
popd

echo "Building OPA"
git clone --depth 1 https://github.com/open-policy-agent/opa.git
pushd opa
make build WASM_ENABLED=0
sudo cp opa_linux_amd64 /usr/bin/opa
popd

echo "Building rootfs"
pushd kata-containers/tools/osbuilder
sudo -E PATH=$PATH AGENT_SOURCE_BIN="$(sudo readlink -f ../../src/agent/target/x86_64-unknown-linux-gnu/debug/kata-agent)" make DISTRO=cbl-mariner KERNEL_MODULES_DIR=$KERNEL_MODULES_DIR rootfs
rootfs_path="$(sudo readlink -f ./cbl-mariner_rootfs)"
pushd ../../src/agent
sudo -E PATH=$PATH make install-services DESTDIR="${rootfs_path}"
popd

echo "Building kata-containers.img"
sudo -E PATH=$PATH make DISTRO=cbl-mariner image
popd

echo "Collecting all pieces"
mkdir -p to_copy
sudo cp kata-containers/tools/osbuilder/kata-containers.img to_copy/
cp kata-containers/src/tardev-snapshotter/tardev-snapshotter.service to_copy/
cp kata-containers/src/tardev-snapshotter/target/release/tardev-snapshotter to_copy/
cp kata-containers/src/runtime/containerd-shim-kata-v2 to_copy/
cp kata-containers/src/runtime/config/configuration-clh.toml to_copy/
cp confidential-containers-containerd/bin/containerd to_copy/
cp kernel/boot/vmlinux.bin to_copy/

popd