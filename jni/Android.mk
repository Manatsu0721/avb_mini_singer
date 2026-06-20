LOCAL_PATH := $(call my-dir)

# libcrypto (From openssl-1.1.1-1.1.1zh, which was drastically minimized via "Configure" at build time.)
# (source code at https://codeload.github.com/kzalewski/openssl-1.1.1/zip/refs/tags/1.1.1zh)
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto-prebuilt
LOCAL_SRC_FILES := mini_openssl_prebuilt/libcrypto.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/mini_openssl_prebuilt/include
include $(PREBUILT_STATIC_LIBRARY)

# RSA4096_Private_key
# (Generated using "ld.lld -r -b binary -m aarch64linux subaru_key.pem -o subaru_key_aarch64.o && ar rcs subaru_key_aarch64.a subaru_key_aarch64.o")
include $(CLEAR_VARS)
LOCAL_MODULE := private_key_object
LOCAL_SRC_FILES := private_key_object/subaru_key_aarch64.a
include $(PREBUILT_STATIC_LIBRARY)

# avb_autosign 1.0
include $(CLEAR_VARS)
LOCAL_MODULE := avb_mini_signer
LOCAL_SRC_FILES := avbtool.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/mini_openssl_prebuilt/include

LOCAL_STATIC_LIBRARIES := libcrypto-prebuilt private_key_object
LOCAL_CFLAGS := -O2 -fdata-sections -ffunction-sections -fvisibility=hidden -std=c11  -fPIE -Wall -Wextra
LOCAL_LDFLAGS := -static \
               -Wl,--build-id=md5 \
               -Wl,--gc-sections \
               -Wl,-Map=output.map

include $(BUILD_EXECUTABLE)