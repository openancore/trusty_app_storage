/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "proxy.h"

#include <assert.h>
#include <lk/list.h>  // for containerof
#include <stdlib.h>
#include <string.h>
#include <uapi/err.h>

#include <interface/storage/storage.h>
#include <lib/hwkey/hwkey.h>

#include "aidl_service.h"
#include "block_device.h"
#include "block_device_tipc.h"
#include "ipc.h"
#include "rpmb.h"
#include "tipc_service.h"

#define SS_ERR(args...) fprintf(stderr, "ss: " args)

static void proxy_disconnect(struct ipc_channel_context* ctx);

static struct storage_session* proxy_context_to_session(
        struct ipc_channel_context* context) {
    assert(context != NULL);
    struct storage_session* session =
            containerof(context, struct storage_session, proxy_ctx);
    assert(session->magic == STORAGE_SESSION_MAGIC);
    return session;
}

static int get_storage_encryption_key(hwkey_session_t session,
                                      uint8_t* key,
                                      uint32_t key_size) {
    static const struct key storage_key_derivation_data = {
            .byte = {
                    0xbc, 0x10, 0x6c, 0x9e, 0xc1, 0xa4, 0x71, 0x04,
                    0x83, 0xab, 0x03, 0x4b, 0x75, 0x8a, 0xb3, 0x5e,
                    0xfb, 0xe5, 0x43, 0x6c, 0xe6, 0x74, 0xb7, 0xfc,
                    0xee, 0x20, 0xad, 0xae, 0xfb, 0x34, 0xab, 0xd3,
            }};

    if (key_size != sizeof(storage_key_derivation_data.byte)) {
        return ERR_BAD_LEN;
    }

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    int rc = hwkey_derive(session, &kdf_version,
                          storage_key_derivation_data.byte, key, key_size);
    if (rc < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, rc);
        return rc;
    }

    return NO_ERROR;
}

#if !WITH_HKDF_RPMB_KEY
static int get_rpmb_auth_key(hwkey_session_t session,
                             uint8_t* key,
                             uint32_t key_size) {
    const char* storage_auth_key_id = "com.android.trusty.storage_auth.rpmb";

    int rc = hwkey_get_keyslot_data(session, storage_auth_key_id, key,
                                    &key_size);
    if (rc < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, rc);
        return rc;
    }

    return NO_ERROR;
}
#endif

static int storage_service_init(struct storage_service* self,
                                struct tipc_hset* hset,
                                handle_t chan_handle) {
    int rc;

    rc = hwkey_open();
    if (rc < 0) {
        SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
        goto err_hwkey_open;
    }

    hwkey_session_t hwkey_session = (hwkey_session_t)rc;

    /* Generate encryption key */
    rc = get_storage_encryption_key(hwkey_session, self->key.byte,
                                    sizeof(self->key));
    if (rc < 0) {
        SS_ERR("%s: can't get storage key: (%d) \n", __func__, rc);
        goto err_get_storage_key;
    }

    struct rpmb_key* rpmb_key_ptr = NULL;
    /* Init RPMB key */
#if !WITH_HKDF_RPMB_KEY
    struct rpmb_key rpmb_key;
    rc = get_rpmb_auth_key(hwkey_session, rpmb_key.byte, sizeof(rpmb_key.byte));
    if (rc < 0) {
        SS_ERR("%s: can't get storage auth key: (%d)\n", __func__, rc);
        goto err_get_rpmb_key;
    }

    rpmb_key_ptr = &rpmb_key;
#endif

    rc = block_device_tipc_init(&self->block_device, chan_handle, &self->key,
                                rpmb_key_ptr, hwkey_session);
    if (rc < 0) {
        SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
        goto err_init_block_device;
    }

    rc = storage_aidl_create_service(&self->aidl, hset);
    if (rc < 0) {
        SS_ERR("%s: storage_aidl_create_service failed (%d)\n", __func__, rc);
        goto err_aidl_create_service;
    }

    storage_aidl_enable(&self->aidl, &self->block_device);

    hwkey_close(hwkey_session);
    return NO_ERROR;

err_aidl_create_service:
err_init_block_device:
#if !WITH_HKDF_RPMB_KEY
err_get_rpmb_key:
#endif
err_get_storage_key:
    hwkey_close(hwkey_session);
err_hwkey_open:
    free(self);
err_alloc_service:
    return rc;
}

static void storage_service_disconnect(struct storage_service* self) {
    storage_aidl_disable(&self->aidl, &self->block_device);
    block_device_tipc_disconnect(&self->block_device);
}

static int storage_service_reconnect(struct storage_service* self,
                                     handle_t chan_handle) {
    int rc = block_device_tipc_reconnect(&self->block_device, chan_handle,
                                         &self->key);
    if (rc < 0) {
        return rc;
    }

    storage_aidl_enable(&self->aidl, &self->block_device);
    return NO_ERROR;
}

static void storage_service_destroy(struct storage_service* self) {
    storage_aidl_destroy_service(&self->aidl);
    block_device_tipc_destroy(&self->block_device);
}

struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
                                          const uuid_t* peer_uuid,
                                          handle_t chan_handle) {
    struct proxy_connect_context* self =
            containerof(parent_ctx, struct proxy_connect_context, tipc_ctx);
    struct tipc_hset* hset = parent_ctx->common.hset;
    int rc;

    if (!self->service.initialized) {
        rc = storage_service_init(&self->service, hset, chan_handle);
        if (rc < 0) {
            goto err_service_init;
        }
    } else {
        rc = storage_service_reconnect(&self->service, chan_handle);
        if (rc < 0) {
            goto err_service_reconnect;
        }
    }

    struct storage_session* session = calloc(1, sizeof(*session));
    if (session == NULL) {
        SS_ERR("%s: out of memory\n", __func__);
        goto err_alloc_session;
    }

    session->magic = STORAGE_SESSION_MAGIC;
    session->service = &self->service;

    rc = storage_tipc_service_init(&session->tipc,
                                   &session->service->block_device, hset);
    if (rc < 0) {
        SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
        goto err_init_block_device_tipc;
    }

    session->proxy_ctx.ops.on_disconnect = proxy_disconnect;
    return &session->proxy_ctx;

err_init_block_device_tipc:
    free(session);
err_alloc_session:
    storage_service_disconnect(&self->service);
err_service_reconnect:
    storage_service_destroy(&self->service);
err_service_init:
    return NULL;
}

void proxy_disconnect(struct ipc_channel_context* ctx) {
    struct storage_session* session = proxy_context_to_session(ctx);
    struct storage_service* service = session->service;

    storage_tipc_service_destroy(&session->tipc, &service->block_device);
    free(session);

    storage_service_disconnect(service);
}

void proxy_destroy(struct proxy_connect_context* self) {
    storage_service_destroy(&self->service);
    ipc_port_destroy(&self->tipc_ctx);
}