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

#pragma once

#include <stdint.h>

#include <lib/hwkey/hwkey.h>
#include <trusty_ipc.h>

#include "block_device.h"
#include "crypt.h"
#include "fs.h"
#include "rpmb.h"
#include "tipc_ns.h"

/**
 * DOC: File System Identifiers
 *
 * These file system names can be used in log messages to distinguish between
 * operations on different file systems. They are also mapped to identifiers to
 * report metrics events.
 *
 * @file_system_id_td: Tamper detect storage. Rollback or tampering by
 *                     non-secure code will be detected.
 * @file_system_id_tdea: Tamper detect early-access storage. Rollback or
 *                       tampering by non-secure code will be detected.
 *                       Available before the non-secure OS has booted if
 *                       supported by the boot loader.
 * @file_system_id_tdp: Tamper detect persistent storage. Rollback or tampering
 *                      by non-secure code will be detected. Data will persist
 *                      across device wipes.
 * @file_system_id_tp: Tamper proof storage. Non-secure code can prevent read
 *                     and write operations from succeeding, but it cannot
 *                     modify on-disk data.
 * @file_system_id_nsp: Non-secure persistent storage. Deprecated.
 */
extern const char file_system_id_td[];
extern const char file_system_id_tdea[];
extern const char file_system_id_tdp[];
extern const char file_system_id_tp[];
extern const char file_system_id_nsp[];

enum storage_filesystem_type {
    STORAGE_TP,
    STORAGE_TDEA,
    STORAGE_TD,
    STORAGE_TDP,
    STORAGE_NSP,
    STORAGE_FILESYSTEMS_COUNT,
};

/**
 * struct block_device_rpmb
 * @dev:         Block device state
 * @rpmb_state:  State of the backing rpmb
 * @base:        First block to use in rpmb partition
 * @is_userdata: Is this RPMB device tied to the state of the userdata
 * partition?
 */
struct block_device_rpmb {
    struct block_device dev;
    struct rpmb_state* rpmb_state;
    uint16_t base;
    bool is_userdata;
};

/**
 * struct block_device_ns
 * @dev:        Block device state
 * @ipc_handle: IPC handle to use to talk to ns
 * @ns_handle:  Handle of the backing ns file
 * @is_userdata: Is the backing file for this device in the (non-persistent)
 *               userdata partition?
 */
struct block_device_ns {
    struct block_device dev;
    handle_t ipc_handle;
    ns_handle_t ns_handle;
    bool is_userdata;
};

/**
 * struct block_device_tipc
 * @ipc_handle:            IPC handle to use to talk to storageproxy.
 * @rpmb_state:            State of the backing rpmb. Holds a pointer to
 *                         @ipc_handle.
 * @dev_rpmb:              The rpmb block device backing @tr_state_rpmb.
 * @tr_state_rpmb:         Filesystem for rpmb (TP, TDEA).
 * @dev_ns:                The rpmb block device containing the superblock for
 *                         @tr_state_ns.
 * @dev_ns_rpmb:           The rpmb block device backing @tr_state_ns.
 * @tr_state_ns:           Filesystem for TD.
 * @dev_ns_tdp:            The ns block device backing @tr_state_ns_tdp. Only
 *                         present when $HAS_FS_TDP defined.
 * @dev_ns_tdp_rpmb:       The rpmb block device containing the superblock for
 *                         @tr_state_ns_tdp. Only present when $HAS_FS_TDP
 *                         defined.
 * @tr_state_ns_tdp:       Filesystem for TDP. Only present when $HAS_FS_TDP
 *                         defined.
 * @dev_ns_nsp:            The ns block device backing @tr_state_ns_nsp. Only
 *                         present when $HAS_FS_NSP defined.
 * @dev_ns_nsp_superblock: The ns block device containing the superblock for
 *                         @tr_state_ns_nsp. Only present when $HAS_FS_NSP
 *                         defined.
 * @tr_state_ns_nsp:       Filesystem for NSP. Only present when $HAS_FS_NSP
 *                         defined.
 */
struct block_device_tipc {
    handle_t ipc_handle;
    struct rpmb_state* rpmb_state;

    struct block_device_rpmb dev_rpmb;
    struct fs tr_state_rpmb;

    struct block_device_ns dev_ns;
    struct block_device_rpmb dev_ns_rpmb;
    struct fs tr_state_ns;

#if HAS_FS_TDP
    struct block_device_ns dev_ns_tdp;
    struct block_device_rpmb dev_ns_tdp_rpmb;
    struct fs tr_state_ns_tdp;
#endif

#if HAS_FS_NSP
    struct block_device_ns dev_ns_nsp;
    struct block_device_ns dev_ns_nsp_superblock;
    struct fs tr_state_ns_nsp;
#endif
};

__BEGIN_CDECLS

/**
 * block_device_tipc_init() - Initialize a block device context
 * @self: Out param. Will contain the created &struct block_device_tipc,
 * which must later be cleaned up by passing to block_device_tipc_destroy()
 * @ipc_handle: IPC handle to use to talk to ns.
 * @fs_key: Key used to decrypt filesystems.
 * @rpmb_key: Key used to access rpmb. If null, a derived key will be used
 * instead.
 * @hwkey_session: HWCrpyto session handle to use for rpmb access.
 */
int block_device_tipc_init(struct block_device_tipc* self,
                           handle_t ipc_handle,
                           const struct key* fs_key,
                           const struct rpmb_key* rpmb_key,
                           hwkey_session_t hwkey_session);

/**
 * block_device_tipc_destroy() - Destroy a block device context
 * @self: The &struct block_device_tipc to destroy. Does not free the
 * context's memory. Any &struct fs &self returned from calls to
 * block_device_tipc_get_fs() must no longer be in use. @self must have
 * already been disconnected with &block_device_tipc_disconnect().
 */
void block_device_tipc_destroy(struct block_device_tipc* self);

/**
 * block_device_tipc_fs_connected() - Check whether a given filesystem is
 * connected
 *
 * @self: The &struct block_device_tipc from which to check for a filesystem.
 * @fs_type: The type of filesystem to check.
 */
bool block_device_tipc_fs_connected(struct block_device_tipc* self,
                                    enum storage_filesystem_type fs_type);

/**
 * block_device_tipc_get_fs() - Get a reference to one of the managed
 * filesystems
 *
 * @self: The &struct block_device_tipc to get a filesystem from.
 * @fs_type: The type of filesystem to get.
 */
struct fs* block_device_tipc_get_fs(struct block_device_tipc* self,
                                    enum storage_filesystem_type fs_type);

/**
 * block_device_tipc_disconnect() - Disconnect from the block devices
 *
 * Severs ipc connections to the block devices/filesystems backing the &struct
 * fs objects returned by &block_device_tipc_get_fs(). These fs objects state
 * will be maintained, but they must not be used until
 * &block_device_tipc_reconnect() is called.
 *
 * @self: The &struct block_device_tipc to disconnect.
 */
void block_device_tipc_disconnect(struct block_device_tipc* self);

/**
 * block_device_tipc_reconnect() - Reconnect to the block devices
 *
 * Reestablishes ipc connections to the block devices/filesystems backing the
 * &struct fs objects returned by &block_device_tipc_get_fs().
 *
 * @self: The &struct block_device_tipc to reconnect.
 * @ipc_handle: IPC handle to use to talk to backing block devices/filesystems.
 * @fs_key: Key used to decrypt filesystems.
 */
int block_device_tipc_reconnect(struct block_device_tipc* self,
                                handle_t ipc_handle,
                                const struct key* fs_key);

__END_CDECLS
