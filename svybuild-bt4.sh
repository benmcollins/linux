#!/bin/bash

target=bt4

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-$target"
export MAKEFLAGS="O=$dir -j$nway ARCH=powerpc"

rootdir="/opt/fsl-networking/QorIQ-SDK-V1.8/sysroots/i686-fslsdk-linux"

export PATH="$PATH:$rootdir/usr/bin/powerpc64-fsl-linux"
export MAKEFLAGS="$MAKEFLAGS CROSS_COMPILE=powerpc64-fsl-linux-"

if ! test -f "$dir/.config"; then
	test -d "$dir" || mkdir "$dir"
	cp "svy-configs/svy-$target" "$dir/.config"
fi

make uImage
make t4240mfcs.dtb
