#!/bin/bash
#
# this script is used to rebuild all QEMU binaries for the host
# platforms.
#
# assume that the device tree is in TOP
#

case $(uname -s) in
    Linux)
        HOST_NUM_CPUS=`cat /proc/cpuinfo | grep processor | wc -l`
        ;;
    Darwin|FreeBsd)
        HOST_NUM_CPUS=`sysctl -n hw.ncpu`
        ;;
    CYGWIN*|*_NT-*)
        HOST_NUM_CPUS=$NUMBER_OF_PROCESSORS
        ;;
    *)  # let's play safe here
        HOST_NUM_CPUS=1
esac

cd `dirname $0`
rm -rf objs/* &&
./android-configure.sh $@ &&
make -j$HOST_NUM_CPUS &&
echo "Done. !!"

## start -- zhouhao
## copy some essential files
echo "copy some essential files ..."
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/boot_offsets.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/dex_offsets.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/jnimethod.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/kernelinfo.conf ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/libcmethod.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/libmmethod.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/native_offsets.txt ./objs
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/prop.txt ./objs
## assume that directory ./objs/lib is already existed
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/libart.so ./objs/lib/
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/libc.so ./objs/lib/
cp /home/zhouhao/WORKING_DIRECTORY_NDROID/NDroid_Config/libm.so ./objs/lib/
echo "copy done!"
## end -- zhouhao
