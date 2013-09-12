#!/bin/sh

cpus=`getconf _NPROCESSORS_ONLN`
nway=`echo "($cpus * 15) / 10" | bc`

dir="`pwd`/build-yoda"
export MAKEFLAGS="O=$dir -j$nway"

test -d "$dir" || mkdir "$dir"

test -f "$dir/.config" || cp svy-configs/svy-yoda "$dir/.config"

make uImage
