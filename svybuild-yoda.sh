#!/bin/bash

target=yoda

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-$target"
export MAKEFLAGS="O=$dir -j$nway ARCH=powerpc"

if type -p powerpc-linux-gnu-gcc; then
	export MAKEFLAGS="$MAKEFLAGS CROSS_COMPILE=powerpc-linux-gnu-"
else
	# Cross compiling?
	if [ -d /opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux ]; then
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux"
	else
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/i686-fsl_networking_sdk-linux"
	fi
	export PATH="$PATH:$rootdir/usr/bin/ppce500mc-fsl_networking-linux"
	export MAKEFLAGS="$MAKEFLAGS CROSS_COMPILE=powerpc64-fsl_networking-linux-"
fi

if ! test -f "$dir/.config"; then
	test -d "$dir" || mkdir "$dir"
	cp "svy-configs/svy-$target" "$dir/.config"
fi

make uImage
