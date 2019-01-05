/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file NativeLibraryWhitelist.h
 *   Creates a list of known native libraries for the Android system.
 * @author Lok Yan
 * @date 5 Jan 2012
 */

#ifndef NATIVE_LIBRARY_WHITELIST_H
#define NATIVE_LIBRARY_WHITELIST_H

#include "utils/StringHashtable.h"

static void NativeLibraryWhitelist_free(StringHashtable* pTable)
{
  StringHashtable_free(pTable);
}

static StringHashtable* NativeLibraryWhitelist_new()
{
  StringHashtable* pTable = StringHashtable_new();
  if (pTable == NULL)
  {
    return (pTable);
  }

  StringHashtable_add(pTable, "/lib/egl/libEGL_emulation.so");
  StringHashtable_add(pTable, "/lib/egl/libGLES_android.so");
  StringHashtable_add(pTable, "/lib/egl/libGLESv1_CM_emulation.so");
  StringHashtable_add(pTable, "/lib/egl/libGLESv2_emulation.so");

  StringHashtable_add(pTable, "/lib/hw/audio_policy.default.so");
  StringHashtable_add(pTable, "/lib/hw/audio.primary.default.so");
  StringHashtable_add(pTable, "/lib/hw/audio.primary.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/bluetooth.default.so");
  StringHashtable_add(pTable, "/lib/hw/camera.goldfish.jpeg.so");
  StringHashtable_add(pTable, "/lib/hw/camera.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/gps.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/gralloc.default.so");
  StringHashtable_add(pTable, "/lib/hw/gralloc.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/keystore.default.so");
  StringHashtable_add(pTable, "/lib/hw/lights.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/local_time.default.so");
  StringHashtable_add(pTable, "/lib/hw/power.default.so");
  StringHashtable_add(pTable, "/lib/hw/power.goldfish.so");
  StringHashtable_add(pTable, "/lib/hw/sensors.goldfish.so");

  StringHashtable_add(pTable, "/lib/crtbegin_so.o");
  StringHashtable_add(pTable, "/lib/crtend_so.o");
  StringHashtable_add(pTable, "/lib/interrupter.so");
  StringHashtable_add(pTable, "/lib/invoke_mock_media_player.so");
  StringHashtable_add(pTable, "/lib/libandroidfw.so");
  StringHashtable_add(pTable, "/lib/libandroid_runtime.so");
  StringHashtable_add(pTable, "/lib/libandroid_servers.so");
  StringHashtable_add(pTable, "/lib/libandroid.so");
  StringHashtable_add(pTable, "/lib/libart-compiler.so");
  StringHashtable_add(pTable, "/lib/libart.so");
  StringHashtable_add(pTable, "/lib/libasan_preload.so");
  StringHashtable_add(pTable, "/lib/libaudioeffect_jni.so");
  StringHashtable_add(pTable, "/lib/libaudioflinger.so");
  StringHashtable_add(pTable, "/lib/libaudioutils.so");
  StringHashtable_add(pTable, "/lib/libbcc.sha1.so");
  StringHashtable_add(pTable, "/lib/libbcc.so");
  StringHashtable_add(pTable, "/lib/libbcinfo.so");
  StringHashtable_add(pTable, "/lib/libbinder.so");
  StringHashtable_add(pTable, "/lib/libbluetooth_jni.so");
  StringHashtable_add(pTable, "/lib/libbt-hci.so");
  StringHashtable_add(pTable, "/lib/libbt-utils.so");
  StringHashtable_add(pTable, "/lib/libart.so");
  StringHashtable_add(pTable, "/lib/libcamera_client.so");
  StringHashtable_add(pTable, "/lib/libcamera_metadata.so");
  StringHashtable_add(pTable, "/lib/libcameraservice.so");
  StringHashtable_add(pTable, "/lib/libchromium_net.so");
  StringHashtable_add(pTable, "/lib/libc_malloc_debug_leak.so");
  StringHashtable_add(pTable, "/lib/libc_malloc_debug_qemu.so");
  StringHashtable_add(pTable, "/lib/libclcore.bc");
  StringHashtable_add(pTable, "/lib/libclcore_debug.bc");
  StringHashtable_add(pTable, "/lib/libcommon_time_client.so");
  StringHashtable_add(pTable, "/lib/libcompiler_rt.so");
  StringHashtable_add(pTable, "/lib/libconnectivitymanager.so");
  StringHashtable_add(pTable, "/lib/libcorkscrew.so");
  StringHashtable_add(pTable, "/lib/libcrypto.so");
  StringHashtable_add(pTable, "/lib/libc.so");
  StringHashtable_add(pTable, "/lib/libctest.so");
  StringHashtable_add(pTable, "/lib/libcutils.so");
  StringHashtable_add(pTable, "/lib/libdefcontainer_jni.so");
  StringHashtable_add(pTable, "/lib/libdiskconfig.so");
  StringHashtable_add(pTable, "/lib/libdl.so");
  StringHashtable_add(pTable, "/lib/libdrmframework_jni.so");
  StringHashtable_add(pTable, "/lib/libdrmframework.so");
  StringHashtable_add(pTable, "/lib/libdvm.so");
  StringHashtable_add(pTable, "/lib/libeffects.so");
  StringHashtable_add(pTable, "/lib/libEGL.so");
  StringHashtable_add(pTable, "/lib/libETC1.so");
  StringHashtable_add(pTable, "/lib/libexif.so");
  StringHashtable_add(pTable, "/lib/libexpat.so");
  StringHashtable_add(pTable, "/lib/libext2_blkid.so");
  StringHashtable_add(pTable, "/lib/libext2_com_err.so");
  StringHashtable_add(pTable, "/lib/libext2_e2p.so");
  StringHashtable_add(pTable, "/lib/libext2fs.so");
  StringHashtable_add(pTable, "/lib/libext2_uuid.so");
  StringHashtable_add(pTable, "/lib/libext4_utils.so");
  StringHashtable_add(pTable, "/lib/libFFTEm.so");
  StringHashtable_add(pTable, "/lib/libfilterfw.so");
  StringHashtable_add(pTable, "/lib/libfilterpack_imageproc.so");
  StringHashtable_add(pTable, "/lib/libft2.so");
  StringHashtable_add(pTable, "/lib/libgabi++.so");
  StringHashtable_add(pTable, "/lib/libgccdemangle.so");
  StringHashtable_add(pTable, "/lib/libGLES_trace.so");
  StringHashtable_add(pTable, "/lib/libGLESv1_CM.so");
  StringHashtable_add(pTable, "/lib/libGLESv1_enc.so");
  StringHashtable_add(pTable, "/lib/libGLESv2_enc.so");
  StringHashtable_add(pTable, "/lib/libGLESv2.so");
  StringHashtable_add(pTable, "/lib/libGLESv3.so");
  StringHashtable_add(pTable, "/lib/libgui.so");
  StringHashtable_add(pTable, "/lib/libhardware_legacy.so");
  StringHashtable_add(pTable, "/lib/libhardware.so");
  StringHashtable_add(pTable, "/lib/libharfbuzz_ng.so");
  StringHashtable_add(pTable, "/lib/libhwui.so");
  StringHashtable_add(pTable, "/lib/libicui18n.so");
  StringHashtable_add(pTable, "/lib/libicuuc.so");
  StringHashtable_add(pTable, "/lib/libinputservice.so");
  StringHashtable_add(pTable, "/lib/libinput.so");
  StringHashtable_add(pTable, "/lib/libiprouteutil.so");
  StringHashtable_add(pTable, "/lib/libjavacore.so");
  StringHashtable_add(pTable, "/lib/libjavacrypto.so");
  StringHashtable_add(pTable, "/lib/libjhead_jni.so");
  StringHashtable_add(pTable, "/lib/libjhead.so");
  StringHashtable_add(pTable, "/lib/libjni_eglfence.so");
  StringHashtable_add(pTable, "/lib/libjni_filtershow_filters.so");
  StringHashtable_add(pTable, "/lib/libjnigraphics.so");
  StringHashtable_add(pTable, "/lib/libjni_jpegstream.so");
  StringHashtable_add(pTable, "/lib/libjni_latinime.so");
  StringHashtable_add(pTable, "/lib/libjni_mosaic.so");
  StringHashtable_add(pTable, "/lib/libjni_pacprocessor.so");
  StringHashtable_add(pTable, "/lib/libjni_pinyinime.so");
  StringHashtable_add(pTable, "/lib/libjni_tinyplanet.so");
  StringHashtable_add(pTable, "/lib/libjpeg.so");
  StringHashtable_add(pTable, "/lib/libkeystore_binder.so");
  StringHashtable_add(pTable, "/lib/libLLVM.so");
  StringHashtable_add(pTable, "/lib/liblog.so");
  StringHashtable_add(pTable, "/lib/liblogwrap.so");
  StringHashtable_add(pTable, "/lib/libmdnssd.so");
  StringHashtable_add(pTable, "/lib/libmedia_jni.so");
  StringHashtable_add(pTable, "/lib/libmedialogservice.so");
  StringHashtable_add(pTable, "/lib/libmediaplayerservice.so");
  StringHashtable_add(pTable, "/lib/libmedia.so");
  StringHashtable_add(pTable, "/lib/libmemtrack.so");
  StringHashtable_add(pTable, "/lib/libm.so");
  StringHashtable_add(pTable, "/lib/libmtp.so");
  StringHashtable_add(pTable, "/lib/libnativehelper.so");
  StringHashtable_add(pTable, "/lib/libnbaio.so");
  StringHashtable_add(pTable, "/lib/libnetlink.so");
  StringHashtable_add(pTable, "/lib/libnetutils.so");
  StringHashtable_add(pTable, "/lib/libnfc_ndef.so");
  StringHashtable_add(pTable, "/lib/libOpenglSystemCommon.so");
  StringHashtable_add(pTable, "/lib/libOpenMAXAL.so");
  StringHashtable_add(pTable, "/lib/libOpenSLES.so");
  StringHashtable_add(pTable, "/lib/libpac.so");
  StringHashtable_add(pTable, "/lib/libpagemap.so");
  StringHashtable_add(pTable, "/lib/libpixelflinger.so");
  StringHashtable_add(pTable, "/lib/libpng.so");
  StringHashtable_add(pTable, "/lib/libportable.so");
  StringHashtable_add(pTable, "/lib/libpowermanager.so");
  StringHashtable_add(pTable, "/lib/libpower.so");
  StringHashtable_add(pTable, "/lib/libreference-ril.so");
  StringHashtable_add(pTable, "/lib/lib_renderControl_enc.so");
  StringHashtable_add(pTable, "/lib/libril.so");
  StringHashtable_add(pTable, "/lib/librilutils.so");
  StringHashtable_add(pTable, "/lib/libRScpp.so");
  StringHashtable_add(pTable, "/lib/libRSCpuRef.so");
  StringHashtable_add(pTable, "/lib/libRSDriver.so");
  StringHashtable_add(pTable, "/lib/librs_jni.so");
  StringHashtable_add(pTable, "/lib/libRS.so");
  StringHashtable_add(pTable, "/lib/librtp_jni.so");
  StringHashtable_add(pTable, "/lib/libselinux.so");
  StringHashtable_add(pTable, "/lib/libsensorservice.so");
  StringHashtable_add(pTable, "/lib/libskia.so");
  StringHashtable_add(pTable, "/lib/libsoftkeymaster.so");
  StringHashtable_add(pTable, "/lib/libsonivox.so");
  StringHashtable_add(pTable, "/lib/libsoundpool.so");
  StringHashtable_add(pTable, "/lib/libsparse.so");
  StringHashtable_add(pTable, "/lib/libspeexresampler.so");
  StringHashtable_add(pTable, "/lib/libsqlite_jni.so");
  StringHashtable_add(pTable, "/lib/libsqlite.so");
  StringHashtable_add(pTable, "/lib/libSR_AudioIn.so");
  StringHashtable_add(pTable, "/lib/libsrec_jni.so");
  StringHashtable_add(pTable, "/lib/libssl.so");
  StringHashtable_add(pTable, "/lib/libstagefright_amrnb_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_avc_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_chromium_http.so");
  StringHashtable_add(pTable, "/lib/libstagefright_enc_common.so");
  StringHashtable_add(pTable, "/lib/libstagefright_foundation.so");
  StringHashtable_add(pTable, "/lib/libstagefright_httplive.so");
  StringHashtable_add(pTable, "/lib/libstagefright_omx.so");
  StringHashtable_add(pTable, "/lib/libstagefright.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_aacdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_aacenc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_amrdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_amrnbenc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_amrwbenc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_flacenc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_g711dec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_gsmdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_h264dec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_h264enc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_mp3dec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_mpeg4dec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_mpeg4enc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_rawdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_vorbisdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_vpxdec.so");
  StringHashtable_add(pTable, "/lib/libstagefright_soft_vpxenc.so");
  StringHashtable_add(pTable, "/lib/libstagefright_wfd.so");
  StringHashtable_add(pTable, "/lib/libstagefright_yuv.so");
  StringHashtable_add(pTable, "/lib/libstdc++.so");
  StringHashtable_add(pTable, "/lib/libstlport.so");
  StringHashtable_add(pTable, "/lib/libsurfaceflinger_ddmconnection.so");
  StringHashtable_add(pTable, "/lib/libsurfaceflinger.so");
  StringHashtable_add(pTable, "/lib/libsuspend.so");
  StringHashtable_add(pTable, "/lib/libsync.so");
  StringHashtable_add(pTable, "/lib/libsysutils.so");
  StringHashtable_add(pTable, "/lib/libthread_db.so");
  StringHashtable_add(pTable, "/lib/libtinyalsa.so");
  StringHashtable_add(pTable, "/lib/libttscompat.so");
  StringHashtable_add(pTable, "/lib/libttspico.so");
  StringHashtable_add(pTable, "/lib/libui.so");
  StringHashtable_add(pTable, "/lib/libusbhost.so");
  StringHashtable_add(pTable, "/lib/libutils.so");
  StringHashtable_add(pTable, "/lib/libvariablespeed.so");
  StringHashtable_add(pTable, "/lib/libvideoeditor_core.so");
  StringHashtable_add(pTable, "/lib/libvideoeditor_jni.so");
  StringHashtable_add(pTable, "/lib/libvideoeditor_osal.so");
  StringHashtable_add(pTable, "/lib/libvideoeditorplayer.so");
  StringHashtable_add(pTable, "/lib/libvideoeditor_videofilters.so");
  StringHashtable_add(pTable, "/lib/libvorbisidec.so");
  StringHashtable_add(pTable, "/lib/libwebrtc_audio_preprocessing.so");
  StringHashtable_add(pTable, "/lib/libwebviewchromium_plat_support.so");
  StringHashtable_add(pTable, "/lib/libwebviewchromium.so");
  StringHashtable_add(pTable, "/lib/libwilhelm.so");
  StringHashtable_add(pTable, "/lib/libwnndict.so");
  StringHashtable_add(pTable, "/lib/libWnnEngDic.so");
  StringHashtable_add(pTable, "/lib/libWnnJpnDic.so");
  StringHashtable_add(pTable, "/lib/libwpa_client.so");
  StringHashtable_add(pTable, "/lib/libz.so");

  StringHashtable_add(pTable, "/lib/soundfx/libaudiopreprocessing.so");
  StringHashtable_add(pTable, "/lib/soundfx/libbundlewrapper.so");
  StringHashtable_add(pTable, "/lib/soundfx/libdownmix.so");
  StringHashtable_add(pTable, "/lib/soundfx/libeffectproxy.so");
  StringHashtable_add(pTable, "/lib/soundfx/libldnhncr.so");
  StringHashtable_add(pTable, "/lib/soundfx/libreverbwrapper.so");
  StringHashtable_add(pTable, "/lib/soundfx/libvisualizer.so");

  StringHashtable_add(pTable, "/lib/ssl/engines/libkeystore.so");

  StringHashtable_add(pTable, "/lib/drm/libfwdlockengine.so");




  return (pTable);
}

#endif//NATIVE_LIBRARY_WHITELIST_H
