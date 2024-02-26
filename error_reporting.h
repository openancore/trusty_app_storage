/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "fs.h"
#include <lk/compiler.h>
#include <trusty/uuid.h>
#include <trusty_ipc.h>

#define METRICS_CONSUMER_PORT "com.android.trusty.metrics.consumer"

enum trusty_storage_error_type {
  TRUSTY_STORAGE_ERROR_UNKNOWN = 0,
  TRUSTY_STORAGE_ERROR_SUPERBLOCK_INVALID = 1,
  TRUSTY_STORAGE_ERROR_BLOCK_MAC_MISMATCH = 2,
  TRUSTY_STORAGE_ERROR_BLOCK_HEADER_INVALID = 3,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH = 4,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH_RECOVERED = 5,
  TRUSTY_STORAGE_ERROR_RPMB_COUNTER_READ_FAILURE = 6,
  TRUSTY_STORAGE_ERROR_RPMB_MAC_MISMATCH = 7,
  TRUSTY_STORAGE_ERROR_RPMB_ADDR_MISMATCH = 8,
  TRUSTY_STORAGE_ERROR_RPMB_FAILURE_RESPONSE = 9,
  TRUSTY_STORAGE_ERROR_RPMB_UNKNOWN = 10,
  TRUSTY_STORAGE_ERROR_RPMB_SCSI_ERROR = 11,
  TRUSTY_STORAGE_ERROR_IO_ERROR = 12,
  TRUSTY_STORAGE_ERROR_PROXY_COMMUNICATION_FAILURE = 13,
};

enum trusty_file_system {
  TRUSTY_FS_UNKNOWN = 0,
  TRUSTY_FS_TP = 1,
  TRUSTY_FS_TD = 2,
  TRUSTY_FS_TDP = 3,
  TRUSTY_FS_TDEA = 4,
  TRUSTY_FS_NSP = 5,
};

enum trusty_block_type {
  TRUSTY_BLOCKTYPE_UNKNOWN = 0,
  TRUSTY_BLOCKTYPE_FILES_ROOT = 1,
  TRUSTY_BLOCKTYPE_FREE_ROOT = 2,
  TRUSTY_BLOCKTYPE_FILES_INTERNAL = 3,
  TRUSTY_BLOCKTYPE_FREE_INTERNAL = 4,
  TRUSTY_BLOCKTYPE_FILE_ENTRY = 5,
  TRUSTY_BLOCKTYPE_FILE_BLOCK_MAP = 6,
  TRUSTY_BLOCKTYPE_FILE_DATA = 7,
  TRUSTY_BLOCKTYPE_CHECKPOINT_ROOT = 8,
  TRUSTY_BLOCKTYPE_CHECKPOINT_FILES_ROOT = 9,
  TRUSTY_BLOCKTYPE_CHECKPOINT_FREE_ROOT = 10,
};

struct metrics_report_storage_error_req {
    enum trusty_storage_error_type error;
    char app_id[UUID_STR_SIZE];
    char client_app_id[UUID_STR_SIZE];
    uint32_t write;
    enum trusty_file_system file_system;
    uint64_t file_path_hash;
    enum trusty_block_type block_type;
    uint64_t repair_counter;
} __attribute__((__packed__));

void do_error_report(enum trusty_storage_error_type type,
                     const char* fs_name,
                     enum trusty_block_type block_type);

int connect_metrics_ta(void);

static inline void error_report_superblock_invalid(const char* fs_name) {
    do_error_report(TRUSTY_STORAGE_ERROR_SUPERBLOCK_INVALID, fs_name,
                    TRUSTY_BLOCKTYPE_UNKNOWN);
}

static inline void error_report_block_mac_mismatch(
        const char* fs_name,
        enum trusty_block_type block_type) {
    do_error_report(TRUSTY_STORAGE_ERROR_BLOCK_MAC_MISMATCH, fs_name,
                    block_type);
}

static inline void error_report_rpmb_counter_mismatch(void) {
    do_error_report(TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH, "unknown",
                    TRUSTY_BLOCKTYPE_UNKNOWN);
}

static inline void error_report_rpmb_counter_mismatch_recovered(void) {
    do_error_report(TRUSTY_STORAGE_ERROR_RPMB_COUNTER_MISMATCH_RECOVERED,
                    "unknown", TRUSTY_BLOCKTYPE_UNKNOWN);
}

static inline void error_report_rpmb_counter_read_failure(void) {
    do_error_report(TRUSTY_STORAGE_ERROR_RPMB_COUNTER_READ_FAILURE, "unknown",
                    TRUSTY_BLOCKTYPE_UNKNOWN);
}

static inline void error_report_rpmb_mac_mismatch(void) {
    do_error_report(TRUSTY_STORAGE_ERROR_RPMB_MAC_MISMATCH, "unknown",
                    TRUSTY_BLOCKTYPE_UNKNOWN);
}

static inline void error_report_rpmb_addr_mismatch(void) {
    do_error_report(TRUSTY_STORAGE_ERROR_RPMB_ADDR_MISMATCH, "unknown",
                    TRUSTY_BLOCKTYPE_UNKNOWN);
}
