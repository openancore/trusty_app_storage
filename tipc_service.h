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

#include <lib/tipc/tipc.h>
#include <trusty_ipc.h>

#include "block_device_tipc.h"
#include "ipc.h"
#include "tipc_ns.h"

/**
 * struct client_port_context
 * @tr_state:   Pointer to the backing filesystem.
 * @client_ctx: Context for the port opened to clients.
 */
struct client_port_context {
    struct fs* tr_state;
    struct ipc_port_context client_ctx;
};

/**
 * struct storage_tipc_service
 * @fs_rpmb:      Client port for TP.
 * @fs_rpmb_boot: Client port for TDEA.
 * @fs_tdp:       Client port for TDP. If $HAS_FS_TDP is undefined, aliases TP.
 *                Only initialized and available if ns is available.
 * @fs_nsp:       Client port for NSP. If $HAS_FS_NSP is undefined, aliases TDP.
 *                Only initialized and available if ns is available.
 * @fs_ns:        Client port for TD. Only initialized and available if ns is
 *                available.
 */
struct storage_tipc_service {
    struct client_port_context fs_rpmb;
    struct client_port_context fs_rpmb_boot;

    struct client_port_context fs_tdp;
    struct client_port_context fs_nsp;
    struct client_port_context fs_ns;
};

/**
 * storage_tipc_service_init() - Initialize a &struct storage_tipc_service
 *
 * Opens tipc ports through which clients can make changes to storage.
 *
 * @self: Out param. Will contain the newly initialized &struct
 * storage_tipc_service.
 * @ctx: &struct block_device_tipc containing the filesystems backing the
 * client ports.
 * @hset: Handle set to handle incoming messages on the client ports.
 */
int storage_tipc_service_init(struct storage_tipc_service* self,
                              struct block_device_tipc* ctx,
                              struct tipc_hset* hset);

/**
 * storage_tipc_service_destroy() - Deinitialize a &struct storage_tipc_service
 *
 * Closes all tipc client ports that were opened by storage_tipc_service_init().
 *
 * @self: The &struct storage_tipc_service to destroy. The backing memory is not
 * freed.
 * @ctx: The &struct block_device_tipc used to init @self.
 */
void storage_tipc_service_destroy(struct storage_tipc_service* self,
                                  struct block_device_tipc* ctx);