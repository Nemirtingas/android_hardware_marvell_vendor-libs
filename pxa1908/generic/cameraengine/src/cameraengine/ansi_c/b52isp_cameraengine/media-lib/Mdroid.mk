LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

include $(LOCAL_PATH)/../../../../../CameraConfig.mk

ifeq (${ENABLE_B52_ISP}, y)
ifeq (${FAKE_B52_DRIVER}, y)
LOCAL_SRC_FILES += \
	src/MediaLib_fake.c \
	src/v4l2subdev.c \
	src/mediactl.c
else
LOCAL_SRC_FILES += \
	src/MediaLib.c \
	src/v4l2subdev.c \
	src/mediactl.c
endif

LOCAL_CFLAGS += \
    -I $(LOCAL_PATH)/../../_include \
    -I bionic/libc/kernel/common/uapi \
	-Werror

LOCAL_CFLAGS += \
	-I $(LOCAL_PATH)/src \
	-D ANDROID

LOCAL_SHARED_LIBRARIES := liblog libcutils

LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_TARGET_ARCH := arm

LOCAL_PRELINK_MODULE := false

LOCAL_MODULE := libmedialib

include $(BUILD_SHARED_LIBRARY)
endif
