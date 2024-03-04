/*
 * Copyright (C) 2024 The Android Open Source Project
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
#define TLOG_TAG "storage"

#include <lib/rng/trusty_rng.h>
#include <lib/storage/storage.h>
#include <string.h>
#include <trusty_benchmark.h>
#include <uapi/err.h>

/* Storage types to test */
static const char* storage_types[] = {
#if HAS_FS_NSP
        STORAGE_CLIENT_NSP_PORT,
#endif
        STORAGE_CLIENT_TD_PORT,
#if HAS_FS_TDP
        STORAGE_CLIENT_TDP_PORT,
#endif
        STORAGE_CLIENT_TDEA_PORT, STORAGE_CLIENT_TP_PORT};

/* How many different storage backends are available */
#define NUM_STORAGE_TYPE countof(storage_types)

static struct {
    storage_session_t ss;
    const char* port;
    uint8_t* data;
} storage_state;

static size_t size_params[] = {32,   64,   128,  256,  512,
                               1024, 2048, 4096, 8192, 16384};

static void get_formatted_value_cb(char* buf,
                                   size_t buf_size,
                                   int64_t value,
                                   const char* metric_name) {
    if (strcmp("time_ms", metric_name) == 0) {
        int64_t milli_sec = value / 1000000;
        int64_t us_sec = (value % 1000000) / 1000;
        snprintf(buf, buf_size, "%" PRId64 ".%03" PRId64 "", milli_sec, us_sec);
    } else {
        snprintf(buf, buf_size, "%" PRId64, value);
    }
}

static void get_param_name_cb(char* buf, size_t buf_size, size_t param_idx) {
    char* s = strrchr(storage_types[bench_get_param_idx() % NUM_STORAGE_TYPE],
                      '.');
    if (s) {
        ++s;
        snprintf(buf, buf_size, "%zu - %s",
                 size_params[param_idx / NUM_STORAGE_TYPE], s);
    }
}

BENCH_SETUP(storage) {
    int rc = NO_ERROR;

    storage_state.ss = STORAGE_INVALID_SESSION;
    storage_state.port =
            storage_types[bench_get_param_idx() % NUM_STORAGE_TYPE];

    rc = storage_open_session(&storage_state.ss, storage_state.port);
    if (rc < 0) {
        TLOGE("failed (%d) to open %s session\n", rc, storage_state.port);
        return ERR_GENERIC;
    }

    size_t sz = size_params[bench_get_param_idx() / NUM_STORAGE_TYPE];
    storage_state.data = malloc(sz * sizeof(uint8_t));
    trusty_rng_secure_rand(storage_state.data, sz);
test_abort:
    return rc;
}

BENCH_TEARDOWN(storage) {
    if (storage_state.ss != STORAGE_INVALID_SESSION) {
        storage_close_session(storage_state.ss);
    }
    storage_state.port = NULL;

    free(storage_state.data);
    storage_state.data = NULL;
}

BENCH(storage, latency, 100, _, NUM_STORAGE_TYPE* countof(size_params)) {
    int rc;
    file_handle_t handle;
    const char* fname = "test_transact_commit_writes";

    // open create truncate file (with commit)
    rc = storage_open_file(
            storage_state.ss, &handle, fname,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_TRUNCATE,
            STORAGE_OP_COMPLETE);
    EXPECT_EQ(0, rc);

    storage_write(handle, 0, storage_state.data,
                  size_params[bench_get_param_idx() / NUM_STORAGE_TYPE],
                  STORAGE_OP_COMPLETE);

    rc = storage_end_transaction(storage_state.ss, true);
    EXPECT_EQ(0, rc);

    // cleanup
    storage_close_file(handle);
    storage_delete_file(storage_state.ss, fname, STORAGE_OP_COMPLETE);
    return NO_ERROR;
}

BENCH_RESULT(storage,
             latency,
             time_ms,
             get_formatted_value_cb,
             get_param_name_cb) {
    return bench_get_duration_ns();  // Formatted to ms by callback
}

PORT_TEST(storage, "com.android.trusty.storage.bench");
