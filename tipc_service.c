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

#include "tipc_service.h"

#include <interface/storage/storage.h>
#include <lib/tipc/tipc.h>

#include "block_device_tipc.h"
#include "client_tipc.h"

#define SS_ERR(args...) fprintf(stderr, "ss: " args)

// TODO: Put this somewhere central?
static const char* port_name(enum storage_filesystem_type fs_type) {
    switch (fs_type) {
    case STORAGE_TP:
        return STORAGE_CLIENT_TP_PORT;
    case STORAGE_TDEA:
        return STORAGE_CLIENT_TDEA_PORT;
    case STORAGE_TDP:
        return STORAGE_CLIENT_TDP_PORT;
    case STORAGE_TD:
        return STORAGE_CLIENT_TD_PORT;
    case STORAGE_NSP:
        return STORAGE_CLIENT_NSP_PORT;
    case STORAGE_FILESYSTEMS_COUNT:
    default:
        SS_ERR("%s: Tried to get port for unrecognized storage_filesystem_type type: (%d)\n",
               __func__, fs_type);
        return NULL;
    }
}

static int client_port_context_init(struct client_port_context* self,
                                    enum storage_filesystem_type fs_type,
                                    struct block_device_tipc* ctx,
                                    struct tipc_hset* hset) {
    if (!block_device_tipc_fs_connected(ctx, fs_type)) {
        return 0;
    }
    self->tr_state = block_device_tipc_get_fs(ctx, fs_type);
    return client_create_port(hset, &self->client_ctx, port_name(fs_type));
}

static void client_port_context_destroy(struct client_port_context* self,
                                        enum storage_filesystem_type fs_type,
                                        struct block_device_tipc* ctx) {
    if (!block_device_tipc_fs_connected(ctx, fs_type)) {
        return;
    }
    ipc_port_destroy(&self->client_ctx);
}

int storage_tipc_service_init(struct storage_tipc_service* self,
                              struct block_device_tipc* ctx,
                              struct tipc_hset* hset) {
    int ret = client_port_context_init(&self->fs_rpmb, STORAGE_TP, ctx, hset);
    if (ret < 0) {
        goto err_fs_rpmb_create_port;
    }

    ret = client_port_context_init(&self->fs_rpmb_boot, STORAGE_TDEA, ctx,
                                   hset);
    if (ret < 0) {
        goto err_fs_rpmb_boot_create_port;
    }

    ret = client_port_context_init(&self->fs_tdp, STORAGE_TDP, ctx, hset);
    if (ret < 0) {
        goto err_fs_tdp_create_port;
    }

    ret = client_port_context_init(&self->fs_ns, STORAGE_TD, ctx, hset);
    if (ret < 0) {
        goto err_fs_ns_create_port;
    }

    ret = client_port_context_init(&self->fs_nsp, STORAGE_NSP, ctx, hset);
    if (ret < 0) {
        goto err_fs_nsp_create_port;
    }
    return 0;

err_fs_nsp_create_port:
    client_port_context_destroy(&self->fs_ns, STORAGE_TD, ctx);
err_fs_ns_create_port:
    client_port_context_destroy(&self->fs_tdp, STORAGE_TDP, ctx);
err_fs_tdp_create_port:
    client_port_context_destroy(&self->fs_rpmb_boot, STORAGE_TDEA, ctx);
err_fs_rpmb_boot_create_port:
    client_port_context_destroy(&self->fs_rpmb, STORAGE_TP, ctx);
err_fs_rpmb_create_port:
    return ret;
}

void storage_tipc_service_destroy(struct storage_tipc_service* self,
                                  struct block_device_tipc* ctx) {
    client_port_context_destroy(&self->fs_nsp, STORAGE_NSP, ctx);
    client_port_context_destroy(&self->fs_ns, STORAGE_TD, ctx);
    client_port_context_destroy(&self->fs_tdp, STORAGE_TDP, ctx);
    client_port_context_destroy(&self->fs_rpmb_boot, STORAGE_TDEA, ctx);
    client_port_context_destroy(&self->fs_rpmb, STORAGE_TP, ctx);
}
