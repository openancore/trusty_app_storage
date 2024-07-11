# Copyright (C) 2019 The Android Open Source Project
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

TRUSTY_USER_TESTS += \
	trusty/user/app/storage/test/storage-unittest \

ifneq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
TRUSTY_USER_TESTS += \
	trusty/user/app/storage/test/storage-benchmark
endif

ifeq (true,$(call TOBOOL,$(STORAGE_AIDL_ENABLED)))
TRUSTY_RUST_USER_TESTS += \
	trusty/user/app/storage/test/storage-unittest-aidl \
	trusty/user/app/storage/test/storage-unittest-aidl/ns \

endif
