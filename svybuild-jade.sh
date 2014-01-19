#!/bin/sh

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-jade"
export MAKEFLAGS="O=$dir -j$nway"

buildarch="`uname -p`"

if [ "$buildarch" != "ppc" -a "$buildarch" != "ppc64" ]; then
	if [ -d /opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux ]; then
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux"
	else
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/i686-fsl_networking_sdk-linux"
	fi
	export PATH="$PATH:$rootdir/usr/bin/ppce500mc-fsl_networking-linux"
	export MAKEFLAGS="$MAKEFLAGS CROSS_COMPILE=powerpc-fsl_networking-linux- ARCH=powerpc"
fi

test -d "$dir" || mkdir "$dir"

test -f "$dir/.config" || cp svy-configs/svy-jade "$dir/.config"

make uImage
