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

#pragma once

#include <stdlib.h>

#include <lib/tipc/tipc.h>
#include <lk/compiler.h>

struct fs;

enum storage_aidl_filesystem {
    STORAGE_AIDL_TP,
    STORAGE_AIDL_TDEA,
    STORAGE_AIDL_TDP,
    STORAGE_AIDL_TD,
    STORAGE_AIDL_NSP,
    STORAGE_AIDL_FILESYSTEMS_COUNT,
};

__BEGIN_CDECLS

#if STORAGE_AIDL_ENABLED

struct storage_service_aidl_context_inner;

struct storage_service_aidl_context {
    struct storage_service_aidl_context_inner* inner;
};

#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(ctx) \
    (struct storage_service_aidl_context) {             \
        .inner = NULL                                   \
    }

/**
 * storage_aidl_create_service() - Initialize a storage aidl service
 * @ctx: Out-param. Will contain the created &struct
 * storage_aidl_create_service, which must be cleaned up by passing it to
 * storage_aidl_delete_service().
 * @hset: The handle set the service will run on.
 */
int storage_aidl_create_service(struct storage_service_aidl_context* ctx,
                                struct tipc_hset* hset);

/**
 * storage_aidl_delete_service() - Delete a storage aidl service
 * @ctx: The &struct storage_aidl_create_service to delete. When called, there
 * must not be any remaining AIDL objects created from @ctx that are still
 * callable (including remotely).
 */
void storage_aidl_delete_service(struct storage_service_aidl_context* ctx);

/**
 * storage_aidl_enable_filesystem() - Connect the storage aidl service to a
 * backing filesystem
 * @ctx: The &struct storage_aidl_create_service to modify.
 * @fs: Filesystem object to use for access when AIDL calls are made.
 * @fs_type: The type of filesystem to connect. Callers should not connect a
 * second time for the same @fs_type without calling
 * storage_aidl_disable_filesystem() first.
 */
void storage_aidl_enable_filesystem(struct storage_service_aidl_context* ctx,
                                    struct fs* fs,
                                    enum storage_aidl_filesystem fs_type);

/**
 * storage_aidl_disable_filesystem() - Disconnect the storage aidl service from
 a backing filesystem
 * @ctx: The &struct storage_aidl_create_service to modify.
 * @fs_type: The type of filesystem to disconnect. Callers should not disconnect
 from a @fs_type that has not been previously connected with
 storage_aidl_enable_filesystem().

 */
void storage_aidl_disable_filesystem(struct storage_service_aidl_context* ctx,
                                     enum storage_aidl_filesystem fs_type);

#else

struct storage_service_aidl_context {};

#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(ctx) \
    (struct storage_service_aidl_context) {}

static inline int storage_aidl_create_service(
        struct storage_service_aidl_context* ctx,
        struct tipc_hset* hset) {
    *ctx = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(*ctx);
    return EXIT_SUCCESS;
}

static inline void storage_aidl_delete_service(
        struct storage_service_aidl_context* ctx) {}

static inline void storage_aidl_enable_filesystem(
        struct storage_service_aidl_context* ctx,
        struct fs* fs,
        enum storage_aidl_filesystem fs_type) {}

static inline void storage_aidl_disable_filesystem(
        struct storage_service_aidl_context* ctx,
        enum storage_aidl_filesystem fs_type) {}

#endif

__END_CDECLS
