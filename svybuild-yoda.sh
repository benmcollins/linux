#!/bin/sh

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-yoda"
export MAKEFLAGS="O=$dir -j$nway"

buildarch="`uname -p`"

if [ "$buildarch" != "ppc" ]; then
	if [ -d /opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux ]; then
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux"
	else
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/i686-fsl_networking_sdk-linux"
	fi
	export PATH="$PATH:$rootdir/usr/bin/ppc64e6500-fsl_networking-linux"
	export MAKEFLAGS="$MAKEFLAGS CROSS_COMPILE=powerpc64-fsl_networking-linux- ARCH=powerpc"
fi

test -d "$dir" || mkdir "$dir"

test -f "$dir/.config" || cp svy-configs/svy-yoda "$dir/.config"

make uImage
