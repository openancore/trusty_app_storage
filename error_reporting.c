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

#include "error_reporting.h"
#include <uapi/err.h>

#ifdef STORAGE_ENABLE_ERROR_REPORTING

#include <lib/tipc/tipc.h>
#include <lib/tipc/tipc_srv.h>
#include <trusty/uuid.h>
#include <trusty_log.h>

#include <storage_consts.h>
#include <interface/metrics/metrics.h>
#include "block_device_tipc.h"

#define TLOG_TAG "ss-err_rep"

struct uuid storage_service_uuid = STORAGE_SERVICE_UUID;
char storage_service_uuid_str[UUID_STR_SIZE];
handle_t metrics_chan;

static void init_uuid_str(void) {
    if (storage_service_uuid_str[0] == '\0') {
        uuid_to_str(&storage_service_uuid, storage_service_uuid_str);
    }
}

static enum trusty_file_system map_fs_name(const char* name) {
    if (name == file_system_id_tp) {
        return TRUSTY_FS_TP;
    }
    if (name == file_system_id_tdp) {
        return TRUSTY_FS_TDP;
    }
    if (name == file_system_id_td) {
        return TRUSTY_FS_TD;
    }
    if (name == file_system_id_tdea) {
        return TRUSTY_FS_TDEA;
    }
    if (name == file_system_id_nsp) {
        return TRUSTY_FS_NSP;
    }
    TLOGI("Unknown fs name: %s\n", name);
    return TRUSTY_FS_UNKNOWN;
}

void do_error_report(enum trusty_storage_error_type type,
                     const char* fs_name,
                     enum trusty_block_type block_type) {
    init_uuid_str();

    struct metrics_report_storage_error_req atom = {
            .error = TRUSTY_STORAGE_ERROR_UNKNOWN,
            .app_id = {},
            .client_app_id = {},
            .write = 0,
            .file_system = TRUSTY_FS_UNKNOWN,
            .file_path_hash = 0,
            .block_type = TRUSTY_BLOCKTYPE_UNKNOWN,
            .repair_counter = 0,
    };

    struct metrics_req req;
    req.cmd = METRICS_CMD_REPORT_STORAGE_ERROR;

    memcpy(storage_service_uuid_str, atom.app_id, UUID_STR_SIZE);

    struct iovec iovs[] = {
            {
                    .iov_base = &req,
                    .iov_len = sizeof(req),
            },
            {
                    .iov_base = &atom,
                    .iov_len = sizeof(atom),
            },
    };
    struct ipc_msg msg = {
            .num_iov = countof(iovs),
            .iov = iovs,
    };

    size_t total_len = sizeof(req) + sizeof(atom);

    int rc = send_msg(metrics_chan, &msg);
    if (rc != (int)total_len) {
        TLOGE("failed (%d) to send storage event\n", rc);
    }
}

int connect_metrics_ta(void) {
    handle_t chan;
    int rc = tipc_connect(&chan, METRICS_CONSUMER_PORT);
    if (rc != NO_ERROR) {
        TLOGE("failed (%d) to connect to metrics TA\n", rc);
        return rc;
    }
    metrics_chan = chan;
    return NO_ERROR;
}

#else /* STORAGE_ENABLE_ERROR_REPORTING */

void do_error_report(enum trusty_storage_error_type type,
                     const char* fs_name,
                     enum trusty_block_type block_type) {}

int connect_metrics_ta(void) {
    return NO_ERROR;
}

#endif /* STORAGE_ENABLE_ERROR_REPORTING */
