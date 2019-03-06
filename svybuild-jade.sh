#!/bin/bash
# Linux configs in svy-configs.

#debug
set +x

# config filename and build directory suffix.
target="$1"
[ -n "$target" ] || target=svy-jade

cpus=$(getconf _NPROCESSORS_ONLN)
nway=$(echo "($cpus * 15) / 10" | bc)
export CONCURRENCY_LEVEL=$nway

dir="$(pwd)/../build-$target"
export MAKEFLAGS="O=$dir -j$nway -l$nway V=1 ARCH=powerpc"

# @note CAPS not allowed when using bindeb-pkg.
rev="cyphre-btv1-2"
tstamp=$(date "+%Y%m%d%H%M%S")
describe=$(git describe)
svytop=.

case "$1" in
bt4)
	dtb="t4240mfcs"
	image=uImage
	;;
ct1)
	dtb="cts1000"
	image="uImage"
	;;
ct1-fw)
	dtb="cts1000"
	image=uImage
	;;
svy-jade-fips|ct1-fips-builtin|ct1-fips)
	dtb="cts1000"
	rev=""
	image=bindeb-pkg
	;;
ct1-fips-yocto)
	if ! [ -d ../linux-yocto ]; then \
		pushd ..
		git clone git://git.freescale.com/ppc/sdk/linux.git linux-yocto
		popd -
	fi
	cd ../linux-yocto
	branch="sdk-v2.0.x"
	git checkout -b $branch orig/$branch
	svytop=../svy_linux
	dtb=""
	rev=$tstamp
	image=""
	;;
ct1-fips-qoriq)
	if ! [ -d ../linux-qoriq ]; then \
		pushd ..
		git clone https://github.com/qoriq-open-source/linux.git linux-qoriq
		popd
	fi
	cd ../linux-qoriq
	svytop=../svy_linux
	dtb=""
	rev=$tstamp
	image=bindeb-pkg
	;;
ct1-fips-linux)
	if ! [ -d ../linux ]; then \
		pushd ..
		git clone https://github.com/torvalds/linux.git
		popd
	fi
	cd ../linux
	svytop=../svy_linux
	dtb=""
	rev=$tstamp
	image=bindeb-pkg
	prepare="prepare"
	;;
ct1-fips-fw)
	dtb="cts1000"
	image=uImage
	;;
*)
	echo "Pick one of ct1, ct1-fw, ct1-fips, ct1-fips-fw, ct1-fips-linux, ct1-fips-builtin svy-jade-fips, or bt4" 1>&2
	exit 1
esac

# Set final extraversion.
#export MAKEFLAGS="$MAKEFLAGS EXTRAVERSION=-$rev "

arch=$(uname -m)
case "$arch" in
arm*|ppc*)
        ;;
*)
	# TODO: Add arm, CROSS_COMPILE determined by target above.
	CROSS_COMPILE="powerpc-linux-gnu-"
	# Cross compiling with NXP tools?
	if [ -d /opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux ]; then
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/x86_64-fsl_networking_sdk-linux"
	elif [ -d /opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/i686-fsl_networking_sdk-linux ]; then
		rootdir="/opt/fsl-networking/QorIQ-SDK-V1.4/sysroots/i686-fsl_networking_sdk-linux"
	fi
	if [ -n "$rootdir" ]; then
		 export PATH="$PATH:$rootdir/usr/bin/ppce500mc-fsl_networking-linux"
		 CROSS_COMPILE="powerpc-fsl_networking-linux-"
	fi
	export MAKEFLAGS="${MAKEFLAGS} CROSS_COMPILE=${CROSS_COMPILE} "
esac

echo "*** ${MAKEFLAGS}"

if ! test -f "$dir/.config"; then
	test -d "$dir" || mkdir -p "$dir"
	cp "$svytop/svy-configs/$target" "$dir/.config"
fi
[ -n "${prepare}" ] && make prepare
make $image
[ -n "${dtb}" ] &&  make ${dtb}.dtb
