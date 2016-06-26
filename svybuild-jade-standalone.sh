#!/bin/bash

target=jade-standalone

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-$target"
export MAKEFLAGS="O=$dir -j$nway ARCH=powerpc"

if ! test -f "$dir/.config"; then
	test -d "$dir" || mkdir "$dir"
	cp "svy-configs/svy-$target" "$dir/.config"
fi

make uImage
make modules
