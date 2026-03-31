#!/bin/bash

set -euxo pipefail

WORKDIR=$(pwd)
export DEBIAN_FRONTEND=noninteractive

#==========================================================================#
#                        init build env                                    #
#==========================================================================#
apt-get update
apt-get install -qq -y ca-certificates
apt-get install -qq -y --no-install-recommends \
  acl aptly aria2 axel bc binfmt-support binutils-aarch64-linux-gnu bison \
  bsdextrautils btrfs-progs build-essential busybox ca-certificates ccache \
  clang coreutils cpio crossbuild-essential-arm64 cryptsetup curl \
  debian-archive-keyring debian-keyring debootstrap device-tree-compiler \
  dialog dirmngr distcc dosfstools dwarves e2fsprogs expect f2fs-tools \
  fakeroot fdisk file flex gawk gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi \
  gdisk git gnupg gzip htop imagemagick jq kmod lib32ncurses-dev \
  lib32stdc++6 libbison-dev libc6-dev-armhf-cross libc6-i386 libcrypto++-dev \
  libelf-dev libfdt-dev libfile-fcntllock-perl libfl-dev libfuse-dev \
  libgcc-12-dev-arm64-cross libgmp3-dev liblz4-tool libmpc-dev libncurses-dev \
  libncurses5 libncurses5-dev libncursesw5-dev libpython2.7-dev \
  libpython3-dev libssl-dev libusb-1.0-0-dev linux-base lld llvm locales \
  lsb-release lz4 lzma lzop make mtools ncurses-base ncurses-term \
  nfs-kernel-server ntpdate openssl p7zip p7zip-full parallel parted patch \
  patchutils pbzip2 pigz pixz pkg-config pv python2 python2-dev python3 \
  python3-dev python3-distutils python3-pip python3-setuptools \
  python-is-python3 qemu-user-static rar rdfind rename rsync sed \
  squashfs-tools swig tar tree u-boot-tools udev unzip util-linux uuid \
  uuid-dev uuid-runtime vim wget whiptail xfsprogs xsltproc xxd xz-utils \
  zip zlib1g-dev zstd binwalk ripgrep sudo &> /dev/null

localedef -i zh_CN -f UTF-8 zh_CN.UTF-8 || true
mkdir -p ${WORKDIR}/release
git config --global user.name yifengyou
git config --global user.email 842056007@qq.com

#==========================================================================#
#                        vulns                                             #
#==========================================================================#
cd ${WORKDIR}/

git clone https://git.kernel.org/pub/scm/linux/security/vulns.git vulns.git
tar -zcf ${WORKDIR}/release/vulns.git.tar.gz vulns.git
ls -alh ${WORKDIR}/release/vulns.git.tar.gz
ls -alh vulns.git

#==========================================================================#
#                        linux-stable                                      #
#==========================================================================#
cd ${WORKDIR}
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git linux-stable.git
ls -alh linux-stable.git

#==========================================================================#
#                        target kernel                                     #
#==========================================================================#
cd ${WORKDIR}
git clone https://atomgit.com/openeuler/kernel.git openeuler_kernel.git
ls -alh openeuler_kernel.git

#==========================================================================#
#                        check patch                                       #
#==========================================================================#
cd ${WORKDIR}
python3 main.py \
  --dir ${WORKDIR}/vulns.git/cve/published/ \
  --target ${WORKDIR}/openeuler_kernel.git \
  --mainline ${WORKDIR}/linux-stable.git \
  --output ${WORKDIR}/output

cd ${WORKDIR}/output
tar -zcvf ${WORKDIR}/release/openeuler_kernel_cve.tar.gz .

ls -alh ${WORKDIR}/release/
md5sum ${WORKDIR}/release/*
echo "Build completed successfully!"
exit 0
