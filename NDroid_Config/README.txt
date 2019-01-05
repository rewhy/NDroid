--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
resolve boot.oat

step-1: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        adb pull /data/dalvik-cache/arm/system@framework@boot.oat

step-2: cd ~/WORKING_DIRECTORY_NDROID/out/host/linux-x86/bin
        ./oatdump --oat-file=/path/WORKING_DIRECTORY_NDROID/NDroid_Config/system@framework@boot.oat --output=/path/WORKING_DIRECTORY_NDROID/NDroid_Config/boot_oatdump.txt --instruction-set=arm

step-3: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        python createOATOffsetsFile.py boot_oatdump.txt boot_offsets.txt true

step-4: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        python createOATOffsetsFile.py boot_oatdump.txt native_offsets.txt false
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------resolve libart.so

step-1: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        adb pull /system/lib/libart.so

step-2: cd ~/WORKING_DIRECTORY_NDROID/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin
        ./arm-linux-androideabi-objdump -D /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libart.so > /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libart_objdump.txt

step-3: cd ~/WORKING_DIRECTORY_NDROID/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin
        ./arm-linux-androideabi-readelf -s /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libart.so | grep 'FUNC' > /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libart_readelf.txt

step-4: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        python 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
resolve libc.so

step-1: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        adb pull /system/lib/libc.so

step-2: cd ~/WORKING_DIRECTORY_NDROID/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin
        ./arm-linux-androideabi-readelf -s /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libc.so | grep 'FUNC' > /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libc_readelf.txt

step-3: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        python createSOOffsetFile.py libc_readelf.txt libcmethod.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
resolve libm.so

step-1: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        adb pull /system/lib/libm.so

step-2: cd ~/WORKING_DIRECTORY_NDROID/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.8/bin
        ./arm-linux-androideabi-readelf -s /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libm.so | grep 'FUNC' > /path/WORKING_DIRECTORY_NDROID/NDroid_Config/libm_readelf.txt

step-3: cd ~/WORKING_DIRECTORY_NDROID/NDroid_Config
        python createSOOffsetFile.py libm_readelf.txt libmmethod.txt
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
NOTICE
1. the native method in the "dex_offsets.txt" file should be added to the end of the "native_offsets.txt" file
2. adjust the dex2oat property: adb shell stop; adb shell setprop dalvik.vm.dex2oat-filter everything; adb shell start; 
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

./oatdump --oat-file=/path/WORKING_DIRECTORY_NDROID/NDroid_Config/data@app@hk.polyu.asynctask-1@base.apk@classes.dex --output=/path/WORKING_DIRECTORY_NDROID/NDroid_Config/AsyncTask_oatdump.txt --instruction-set=arm

