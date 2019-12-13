# skmm-host driver for x86
Fork of git://git.freescale.com/ppc/sdk/skmm-host.git

forward porting from kernel 3.13.0

Original driver is powerpc for Ubuntu 12.04, Kernel 3.13, gcc 4.6.3. 
Additions will be made to move to 4.1, 4.16, and 4.19 kernels.

Baseline is sdk-v2.0.x.
Makefile: pkc=y is the only change from base sdk 2.0 for 3.13.

Updates for 4.x kernels will be on sdk-v2.0.x-linux-4.x.

## Updates for 4.4.0-148-generic

Updates for Ubuntu 14.04/linux 4.4.0-148-generic/gcc 4.8.4.
 
There were minor API and #define changes.

New patch files were created for 4.4.

## Updates for 4.16.18-cyphre

Updates for Ubuntu 14.04/linux 4.16.18-cyphre/gcc 4.8.4.

Makefile:

- includes config.mk. Most of the Kbuild variables have moved to
config.mk.

- KBUILD variables failed unless objs were dereferences. 
All _KOBJ variables removed.

- Extra PKC removed. PKC is now built in  the kernel.

- Minor API and define changes.




