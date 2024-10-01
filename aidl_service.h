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

#include "block_device_tipc.h"

__BEGIN_CDECLS

#if STORAGE_AIDL_ENABLED

struct storage_service_aidl_context_inner;

struct storage_service_aidl_context {
    struct storage_service_aidl_context_inner* inner;
};

#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(self) \
    (struct storage_service_aidl_context) {              \
        .inner = NULL                                    \
    }

/**
 * storage_aidl_create_service() - Initialize a storage aidl service
 * @self: Out-param. Will contain the created &struct
 * storage_service_aidl_context, which must be cleaned up by passing it to
 * storage_aidl_destroy_service().
 * @hset: The handle set the service will run on.
 */
int storage_aidl_create_service(struct storage_service_aidl_context* self,
                                struct tipc_hset* hset);

/**
 * storage_aidl_destroy_service() - Delete a storage aidl service
 * @self: The &struct storage_service_aidl_context to delete. When called, there
 * must not be any remaining AIDL objects created from @self that are still
 * callable (including remotely).
 */
void storage_aidl_destroy_service(struct storage_service_aidl_context* self);

/**
 * storage_aidl_enable() - Connect the storage aidl service to backing
 * filesystems.
 * @self: The &struct storage_service_aidl_context to modify.
 * @block_devices: Context holding the filesystems to connect to.
 *
 * Callers must not connect a second time without calling storage_aidl_disable()
 * first.
 */
void storage_aidl_enable(struct storage_service_aidl_context* self,
                         struct block_device_tipc* block_devices);

/**
 * storage_aidl_disable() - Disconnect the storage aidl service from backing
 * filesystems.
 * @self: The &struct storage_service_aidl_context to modify.
 * @block_devices: Context holding the filesystems to disconnect from. Must be
 * the same &struct block_device_tipc used to enable @self.
 *
 * Callers must only disable a service that has been previously enabled (with
 * storage_aidl_enable()), and must not disable an already-disabled service.
 */
void storage_aidl_disable(struct storage_service_aidl_context* self,
                          struct block_device_tipc* block_devices);

#else

struct storage_service_aidl_context {};

#define STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(self) \
    (struct storage_service_aidl_context) {}

static inline int storage_aidl_create_service(
        struct storage_service_aidl_context* self,
        struct tipc_hset* hset) {
    *self = STORAGE_SERVICE_AIDL_CONTEXT_INITIAL_VALUE(*self);
    return EXIT_SUCCESS;
}

static inline void storage_aidl_destroy_service(
        struct storage_service_aidl_context* self) {}

static inline void storage_aidl_enable(
        struct storage_service_aidl_context* self,
        struct block_device_tipc* block_devices) {}

static inline void storage_aidl_disable(
        struct storage_service_aidl_context* self,
        struct block_device_tipc* block_devices) {}

#endif

__END_CDECLS
