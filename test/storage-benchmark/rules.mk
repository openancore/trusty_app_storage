# Copyright (C) 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/main.c \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libc-trusty \
	trusty/user/base/lib/rng \
	trusty/user/base/lib/storage \
	trusty/user/base/lib/system_state \
	trusty/user/base/lib/unittest

MODULE_DEPS += \
	$(HWCRYPTO_UNITTEST_DEVICE_MODULE)

ifeq (true,$(call TOBOOL,$(WITH_FAKE_HWRNG)))
MODULE_DEFINES += WITH_FAKE_HWRNG=1
endif

ifeq (true,$(call TOBOOL,$(STORAGE_UNITTEST_ON_EMULATOR)))
MODULE_DEFINES += STORAGE_UNITTEST_ON_EMULATOR=1
endif

STORAGE_HAS_FS_TDP ?= false
ifeq (true,$(call TOBOOL,$(STORAGE_HAS_FS_TDP)))
    MODULE_DEFINES += HAS_FS_TDP=1
endif

STORAGE_HAS_FS_NONSECURE_PERSIST ?= false
ifeq (true,$(call TOBOOL,$(STORAGE_HAS_FS_NONSECURE_PERSIST)))
    MODULE_DEFINES += HAS_FS_NSP=1
endif

include make/trusted_app.mk


