/*
 * Copyright (C) 2015-2016 The Android Open Source Project
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

#include "block_device_tipc.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>

#include <lib/system_state/system_state.h>
#include <lib/tipc/tipc.h>
#include <lk/compiler.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include <interface/storage/storage.h>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include "block_cache.h"
#include "client_tipc.h"
#include "fs.h"
#include "ipc.h"
#include "rpmb.h"
#include "tipc_ns.h"

#ifdef APP_STORAGE_RPMB_BLOCK_SIZE
#define BLOCK_SIZE_RPMB (APP_STORAGE_RPMB_BLOCK_SIZE)
#else
#define BLOCK_SIZE_RPMB (512)
#endif
#ifdef APP_STORAGE_RPMB_BLOCK_COUNT
#define BLOCK_COUNT_RPMB (APP_STORAGE_RPMB_BLOCK_COUNT)
#else
#define BLOCK_COUNT_RPMB (0) /* Auto detect */
#endif
#ifdef APP_STORAGE_MAIN_BLOCK_SIZE
#define BLOCK_SIZE_MAIN (APP_STORAGE_MAIN_BLOCK_SIZE)
#else
#define BLOCK_SIZE_MAIN (2048)
#endif

/*
 * This is here in case we're using an old storageproxyd that does not have
 * support for STORAGE_FILE_GET_MAX_SIZE
 */
#ifdef APP_STORAGE_MAIN_BLOCK_COUNT
#define BLOCK_COUNT_MAIN (APP_STORAGE_MAIN_BLOCK_COUNT)
#else
#define BLOCK_COUNT_MAIN (0x10000000000 / BLOCK_SIZE_MAIN)
#endif

#define BLOCK_SIZE_RPMB_BLOCKS (BLOCK_SIZE_RPMB / RPMB_BUF_SIZE)

STATIC_ASSERT(BLOCK_SIZE_RPMB_BLOCKS == 1 || BLOCK_SIZE_RPMB_BLOCKS == 2);
STATIC_ASSERT((BLOCK_SIZE_RPMB_BLOCKS * RPMB_BUF_SIZE) == BLOCK_SIZE_RPMB);

STATIC_ASSERT(BLOCK_COUNT_RPMB == 0 || BLOCK_COUNT_RPMB >= 8);

STATIC_ASSERT(BLOCK_SIZE_MAIN >= 256);
STATIC_ASSERT(BLOCK_COUNT_MAIN >= 8);
STATIC_ASSERT(BLOCK_SIZE_MAIN >= BLOCK_SIZE_RPMB);

/* Ensure that we can fit a superblock + backup in an RPMB block */
STATIC_ASSERT(BLOCK_SIZE_RPMB >= 256);

#define SS_ERR(args...) fprintf(stderr, "ss: " args)
#define SS_WARN(args...) fprintf(stderr, "ss: " args)

#ifdef SS_DATA_DEBUG_IO
#define SS_DBG_IO(args...) fprintf(stdout, "ss: " args)
#else
#define SS_DBG_IO(args...) \
    do {                   \
    } while (0)
#endif

const char file_system_id_td[] = "td";
const char file_system_id_tdea[] = "tdea";
const char file_system_id_tdp[] = "tdp";
const char file_system_id_tp[] = "tp";
const char file_system_id_nsp[] = "nsp";

const char ns_filename[] = "0";
const char ns_alternate_filename[] = "alternate/0";
const char tdp_filename[] = "persist/0";
const char nsp_filename[] = "persist/nsp";

struct rpmb_key_derivation_in {
    uint8_t prefix[sizeof(struct key)];
    uint8_t block_data[RPMB_BUF_SIZE];
};

struct rpmb_key_derivation_out {
    struct rpmb_key rpmb_key;
    uint8_t unused[sizeof(struct key)];
};

struct rpmb_span {
    uint16_t start;
    uint16_t block_count;
};

struct rpmb_spans {
    struct rpmb_span key;
    struct rpmb_span ns;
    struct rpmb_span tdp;
    /* Start of the rest of the RPMB, which is used for TP and TDEA */
    uint16_t rpmb_start;
};

static int rpmb_check(struct rpmb_state* rpmb_state, uint16_t block) {
    int ret;
    uint8_t tmp[RPMB_BUF_SIZE];
    ret = rpmb_read(rpmb_state, tmp, block, 1);
    SS_DBG_IO("%s: check rpmb_block %d, ret %d\n", __func__, block, ret);
    return ret;
}

static uint32_t rpmb_search_size(struct rpmb_state* rpmb_state, uint16_t hint) {
    int ret;
    uint32_t low = 0;
    uint16_t high = UINT16_MAX;
    uint16_t curr = hint ? hint - 1 : UINT16_MAX;

    while (low <= high) {
        ret = rpmb_check(rpmb_state, curr);
        switch (ret) {
        case 0:
            low = curr + 1;
            break;
        case -ENOENT:
            high = curr - 1;
            break;
        default:
            return 0;
        };
        if (ret || curr != hint) {
            curr = (low + high) / 2;
            hint = curr;
        } else {
            curr = curr + 1;
        }
    }
    assert((uint32_t)high + 1 == low);
    return low;
}

static struct block_device_rpmb* dev_rpmb_to_state(struct block_device* dev) {
    assert(dev);
    return containerof(dev, struct block_device_rpmb, dev);
}

static void block_device_tipc_rpmb_start_read(struct block_device* dev,
                                              data_block_t block) {
    int ret;
    uint8_t tmp[BLOCK_SIZE_RPMB]; /* TODO: pass data in? */
    uint16_t rpmb_block;
    struct block_device_rpmb* dev_rpmb = dev_rpmb_to_state(dev);

    assert(block < dev->block_count);
    rpmb_block = block + dev_rpmb->base;

    ret = rpmb_read(dev_rpmb->rpmb_state, tmp,
                    rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                    BLOCK_SIZE_RPMB_BLOCKS);

    SS_DBG_IO("%s: block %" PRIu64 ", base %d, rpmb_block %d, ret %d\n",
              __func__, block, dev_rpmb->base, rpmb_block, ret);

    block_cache_complete_read(dev, block, tmp, BLOCK_SIZE_RPMB,
                              ret ? BLOCK_READ_IO_ERROR : BLOCK_READ_SUCCESS);
}

static inline enum block_write_error translate_write_error(int rc) {
    switch (rc) {
    case 0:
        return BLOCK_WRITE_SUCCESS;
    case -EUCLEAN:
        return BLOCK_WRITE_FAILED_UNKNOWN_STATE;
    case ERR_IO:
        return BLOCK_WRITE_SYNC_FAILED;
    default:
        return BLOCK_WRITE_FAILED;
    }
}

static void block_device_tipc_rpmb_start_write(struct block_device* dev,
                                               data_block_t block,
                                               const void* data,
                                               size_t data_size,
                                               bool sync) {
    int ret;
    uint16_t rpmb_block;
    struct block_device_rpmb* dev_rpmb = dev_rpmb_to_state(dev);

    /* We currently sync every rpmb write. TODO: can we avoid this? */
    (void)sync;

    assert(data_size == BLOCK_SIZE_RPMB);
    assert(block < dev->block_count);

    rpmb_block = block + dev_rpmb->base;

    ret = rpmb_write(dev_rpmb->rpmb_state, data,
                     rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                     BLOCK_SIZE_RPMB_BLOCKS, true, dev_rpmb->is_userdata);

    SS_DBG_IO("%s: block %" PRIu64 ", base %d, rpmb_block %d, ret %d\n",
              __func__, block, dev_rpmb->base, rpmb_block, ret);

    block_cache_complete_write(dev, block, translate_write_error(ret));
}

static void block_device_tipc_rpmb_wait_for_io(struct block_device* dev) {
    assert(0); /* TODO: use async read/write */
}

static struct block_device_ns* to_block_device_ns(struct block_device* dev) {
    assert(dev);
    return containerof(dev, struct block_device_ns, dev);
}

static void block_device_tipc_ns_start_read(struct block_device* dev,
                                            data_block_t block) {
    int ret;
    enum block_read_error res;
    uint8_t tmp[BLOCK_SIZE_MAIN]; /* TODO: pass data in? */
    struct block_device_ns* dev_ns = to_block_device_ns(dev);

    ret = ns_read_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
                      block * BLOCK_SIZE_MAIN, tmp, BLOCK_SIZE_MAIN);
    SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
    if (ret == 0) {
        res = BLOCK_READ_NO_DATA;
    } else if (ret == BLOCK_SIZE_MAIN) {
        res = BLOCK_READ_SUCCESS;
    } else {
        res = BLOCK_READ_IO_ERROR;
    }
    block_cache_complete_read(dev, block, tmp, BLOCK_SIZE_MAIN, res);
}

static void block_device_tipc_ns_start_write(struct block_device* dev,
                                             data_block_t block,
                                             const void* data,
                                             size_t data_size,
                                             bool sync) {
    int ret;
    enum block_write_error res = BLOCK_WRITE_FAILED;
    struct block_device_ns* dev_ns = to_block_device_ns(dev);

    assert(data_size == BLOCK_SIZE_MAIN);

    ret = ns_write_pos(dev_ns->ipc_handle, dev_ns->ns_handle,
                       block * BLOCK_SIZE_MAIN, data, data_size,
                       dev_ns->is_userdata, sync);
    SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
    if (ret == BLOCK_SIZE_MAIN) {
        res = BLOCK_WRITE_SUCCESS;
    } else if (ret < 0) {
        res = translate_write_error(ret);
    }
    block_cache_complete_write(dev, block, res);
}

static void block_device_tipc_ns_wait_for_io(struct block_device* dev) {
    assert(0); /* TODO: use async read/write */
}

static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
                                            struct rpmb_state* rpmb_state,
                                            uint16_t base,
                                            uint32_t block_count,
                                            bool is_userdata) {
    dev_rpmb->dev.start_read = block_device_tipc_rpmb_start_read;
    dev_rpmb->dev.start_write = block_device_tipc_rpmb_start_write;
    dev_rpmb->dev.wait_for_io = block_device_tipc_rpmb_wait_for_io;
    dev_rpmb->dev.block_count = block_count;
    dev_rpmb->dev.block_size = BLOCK_SIZE_RPMB;
    dev_rpmb->dev.block_num_size = 2;
    dev_rpmb->dev.mac_size = 2;
    dev_rpmb->dev.tamper_detecting = true;
    list_initialize(&dev_rpmb->dev.io_ops);
    dev_rpmb->rpmb_state = rpmb_state;
    dev_rpmb->base = base;
    dev_rpmb->is_userdata = is_userdata;
}

static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
                                          handle_t ipc_handle,
                                          bool is_userdata) {
    dev_ns->dev.start_read = block_device_tipc_ns_start_read;
    dev_ns->dev.start_write = block_device_tipc_ns_start_write;
    dev_ns->dev.wait_for_io = block_device_tipc_ns_wait_for_io;
    dev_ns->dev.block_size = BLOCK_SIZE_MAIN;
    dev_ns->dev.block_num_size = sizeof(data_block_t);
    dev_ns->dev.mac_size = sizeof(struct mac);
    dev_ns->dev.tamper_detecting = false;
    list_initialize(&dev_ns->dev.io_ops);
    dev_ns->ipc_handle = ipc_handle;
    dev_ns->ns_handle = 0; /* Filled in later */
    dev_ns->is_userdata = is_userdata;
}

/**
 * hwkey_derive_rpmb_key() - Derive rpmb key through hwkey server.
 * @session:  The hwkey session handle.
 * @in:       The input data to derive rpmb key.
 * @out:      The output data from deriving rpmb key.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int hwkey_derive_rpmb_key(hwkey_session_t session,
                                 const struct rpmb_key_derivation_in* in,
                                 struct rpmb_key_derivation_out* out) {
    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    const void* in_buf = in;
    void* out_buf = out;
    uint32_t key_size = sizeof(*out);
    STATIC_ASSERT(sizeof(*in) >= sizeof(*out));

    int ret = hwkey_derive(session, &kdf_version, in_buf, out_buf, key_size);
    if (ret < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, ret);
        return ret;
    }

    return NO_ERROR;
}

/**
 * block_device_tipc_program_key() - Program a rpmb key derived through hwkey
 * server.
 * @state:              The rpmb state.
 * @rpmb_key_part_base: The base of rpmb_key_part in rpmb partition.
 * @in                  The input rpmb key derivation data.
 * @out                 The output rpmb key derivation data.
 * @hwkey_session:      The hwkey session handle.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int block_device_tipc_program_key(struct rpmb_state* state,
                                         uint16_t rpmb_key_part_base,
                                         struct rpmb_key_derivation_in* in,
                                         struct rpmb_key_derivation_out* out,
                                         hwkey_session_t hwkey_session) {
    int ret;

    if (!system_state_provisioning_allowed()) {
        ret = ERR_NOT_ALLOWED;
        SS_ERR("%s: rpmb key provisioning is not allowed (%d)\n", __func__,
               ret);
        return ret;
    }

    STATIC_ASSERT(sizeof(in->block_data) >= sizeof(out->rpmb_key));
    RAND_bytes(in->block_data, sizeof(out->rpmb_key.byte));
    ret = hwkey_derive_rpmb_key(hwkey_session, in, out);
    if (ret < 0) {
        SS_ERR("%s: hwkey_derive_rpmb_key failed (%d)\n", __func__, ret);
        return ret;
    }

    ret = rpmb_program_key(state, &out->rpmb_key);
    if (ret < 0) {
        SS_ERR("%s: rpmb_program_key failed (%d)\n", __func__, ret);
        return ret;
    }

    rpmb_set_key(state, &out->rpmb_key);

    ret = rpmb_write(state, in->block_data,
                     rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1, false,
                     false);
    if (ret < 0) {
        SS_ERR("%s: rpmb_write failed (%d)\n", __func__, ret);
        return ret;
    }

    return 0;
}

static int block_device_tipc_derive_rpmb_key(struct rpmb_state* state,
                                             uint16_t rpmb_key_part_base,
                                             hwkey_session_t hwkey_session) {
    int ret;
    struct rpmb_key_derivation_in in = {
            .prefix = {
                    0x74, 0x68, 0x43, 0x49, 0x2b, 0xa2, 0x4f, 0x77,
                    0xb0, 0x8e, 0xd1, 0xd4, 0xb7, 0x01, 0x0e, 0xc6,
                    0x86, 0x4c, 0xa9, 0xe5, 0x28, 0xf0, 0x20, 0xb1,
                    0xb8, 0x1e, 0x73, 0x3d, 0x8c, 0x9d, 0xb9, 0x96,
            }};
    struct rpmb_key_derivation_out out;

    ret = rpmb_read_no_mac(state, in.block_data,
                           rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1);

    if (ret < 0) {
        ret = block_device_tipc_program_key(state, rpmb_key_part_base, &in,
                                            &out, hwkey_session);
        if (ret < 0) {
            SS_ERR("%s: program_key failed (%d)\n", __func__, ret);
            return ret;
        }

        return 0;
    }

    ret = hwkey_derive_rpmb_key(hwkey_session, &in, &out);
    if (ret < 0) {
        SS_ERR("%s: hwkey_derive_rpmb_key failed (%d)\n", __func__, ret);
        return ret;
    }

    rpmb_set_key(state, &out.rpmb_key);

    /*
     * Validate that the derived rpmb key is correct as we use it to check
     * both mac and content of the block_data.
     */
    ret = rpmb_verify(state, in.block_data,
                      rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1);
    if (ret < 0) {
        SS_ERR("%s: rpmb_verify failed with the derived rpmb key (%d)\n",
               __func__, ret);
        return ret;
    }

    return 0;
}

static int block_device_tipc_init_rpmb_key(struct rpmb_state* state,
                                           const struct rpmb_key* rpmb_key,
                                           uint16_t rpmb_key_part_base,
                                           hwkey_session_t hwkey_session) {
    int ret = 0;

    if (rpmb_key) {
        rpmb_set_key(state, rpmb_key);
    } else {
        ret = block_device_tipc_derive_rpmb_key(state, rpmb_key_part_base,
                                                hwkey_session);
    }

    return ret;
}

static int set_storage_size(handle_t handle, struct block_device_ns* dev_ns) {
    data_block_t sz;

    int ret = ns_get_max_size(handle, dev_ns->ns_handle, &sz);
    if (ret < 0) {
        /* In case we have an old storageproxyd, use default */
        if (ret == ERR_NOT_IMPLEMENTED) {
            sz = BLOCK_COUNT_MAIN * dev_ns->dev.block_size;
            ret = 0;
        } else {
            SS_ERR("%s: Could not get max size: %d\n", __func__, ret);
            return ret;
        }
    } else if (sz < (dev_ns->dev.block_size * 8)) {
        SS_ERR("%s: max storage file size %" PRIu64 " is too small\n", __func__,
               sz);
        return -1;
    }

    dev_ns->dev.block_count = sz / dev_ns->dev.block_size;
    return ret;
}

static bool block_device_tipc_has_ns(struct block_device_tipc* self) {
    return self->dev_ns.dev.block_count;
}

/**
 * init_rpmb_fs() - Initialize @self's RPMB fs and its backing block devices.
 * @self:            The struct block_device_tipc to modify
 * @fs_key:          The key to use for the filesystem.
 * @partition_start: The first RPMB block in the partition to use for this fs.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int init_rpmb_fs(struct block_device_tipc* self,
                        const struct key* fs_key,
                        uint16_t partition_start) {
    int ret;
    uint32_t rpmb_block_count;

    if (BLOCK_COUNT_RPMB) {
        rpmb_block_count = BLOCK_COUNT_RPMB;
        ret = rpmb_check(self->rpmb_state,
                         rpmb_block_count * BLOCK_SIZE_RPMB_BLOCKS - 1);
        if (ret < 0) {
            SS_ERR("%s: bad static rpmb size, %d\n", __func__,
                   rpmb_block_count);
            goto err_bad_rpmb_size;
        }
    } else {
        rpmb_block_count = rpmb_search_size(self->rpmb_state,
                                            0); /* TODO: get hint from ns */
        rpmb_block_count /= BLOCK_SIZE_RPMB_BLOCKS;
    }
    if (rpmb_block_count < partition_start) {
        ret = -1;
        SS_ERR("%s: bad rpmb size, %d\n", __func__, rpmb_block_count);
        goto err_bad_rpmb_size;
    }

    block_device_tipc_init_dev_rpmb(&self->dev_rpmb, self->rpmb_state,
                                    partition_start,
                                    rpmb_block_count - partition_start, false);

    /* TODO: allow non-rpmb based tamper proof storage */
    ret = fs_init(&self->tr_state_rpmb, file_system_id_tp, fs_key,
                  &self->dev_rpmb.dev, &self->dev_rpmb.dev, FS_INIT_FLAGS_NONE);
    if (ret < 0) {
        SS_ERR("%s: failed to initialize TP: %d\n", __func__, ret);
        goto err_init_tr_state_rpmb;
    }
    return 0;

err_init_tr_state_rpmb:
    block_cache_dev_destroy(&self->dev_rpmb.dev);
err_bad_rpmb_size:
    return ret;
}

/**
 * destroy_rpmb_fs() - Destroy @self's RPMB fs and its backing block devices.
 */
static void destroy_rpmb_fs(struct block_device_tipc* self) {
    fs_destroy(&self->tr_state_rpmb);
    block_cache_dev_destroy(&self->dev_rpmb.dev);
}

/**
 * block_device_ns_open_file() - Open an ns backing file
 *
 * @self: The ns block device to use to open the file.
 * @name: The name of the file to open.
 * @create: Whether the file should be created if it doesn't already exist.
 *
 * Return: NO_ERROR on success, error code less than 0 if an error was
 * encountered during initialization.
 */
static int block_device_ns_open_file(struct block_device_ns* self,
                                     const char* name,
                                     bool create) {
    return ns_open_file(self->ipc_handle, name, &self->ns_handle, create);
}

/**
 * block_device_ns_open_file_with_alternate() - Open an ns backing file,
 * possibly falling back to an alternate if the primary is not available.
 *
 * @self:           The ns block device to use to open the file.
 * @name:           The name of the primary file to open.
 * @alternate_name: The name of the alternate file. Ignored if
 *                  STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED is false.
 * @create:         Whether the file should be created if it doesn't already
 *                  exist.
 * @used_alternate: Out-param, set only on successful return. Will tell whether
 *                  the opened file was the alternate.
 *
 * Return: NO_ERROR on success, error code less than 0 if an error was
 * encountered during initialization.
 */
static int block_device_ns_open_file_with_alternate(
        struct block_device_ns* self,
        const char* name,
        const char* alternate_name,
        bool create,
        bool* used_alternate) {
    int ret = block_device_ns_open_file(self, name, create);
    if (ret >= 0) {
        *used_alternate = false;
        return NO_ERROR;
    }

#if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED
    ret = block_device_ns_open_file(self, alternate_name, create);
    if (ret >= 0) {
        *used_alternate = true;
        return NO_ERROR;
    }
#endif
    return ret;
}

enum ns_init_result {
    /* Negative codes reserved for other error values. */
    NS_INIT_SUCCESS = 0,
    NS_INIT_NOT_READY = 1,
};

/**
 * init_ns_fs() - Initialize @self's NS fs and its backing block devices.
 * @self:      The struct block_device_tipc to modify
 * @fs_key:    The key to use for the filesystem.
 * @partition: The RPMB blocks to use for the filesystem's superblocks.
 *
 * If no ns filesystems are available, return NS_INIT_NOT_READY and leave the NS
 * fs uninitialized. (In that case, block_device_tipc_has_ns() will return
 * false.)
 *
 * Return: NS_INIT_SUCCESS on success, NS_INIT_NOT_READY if ns is unavailable,
 * or an error code less than 0 if an error was encountered during
 * initialization.
 */
static int init_ns_fs(struct block_device_tipc* self,
                      const struct key* fs_key,
                      struct rpmb_span partition) {
    block_device_tipc_init_dev_ns(&self->dev_ns, self->ipc_handle, true);

    bool alternate_data_partition;
    int ret = block_device_ns_open_file_with_alternate(
            &self->dev_ns, ns_filename, ns_alternate_filename, true,
            &alternate_data_partition);
    if (ret < 0) {
        /* NS not available; init RPMB fs only */
        self->dev_ns.dev.block_count = 0;
        return NS_INIT_NOT_READY;
    }

    ret = set_storage_size(self->ipc_handle, &self->dev_ns);
    if (ret < 0) {
        goto err_get_td_max_size;
    }

    /* Request empty file system if file is empty */
    uint8_t probe;
    uint32_t ns_init_flags = FS_INIT_FLAGS_NONE;
    ret = ns_read_pos(self->ipc_handle, self->dev_ns.ns_handle, 0, &probe,
                      sizeof(probe));
    if (ret < (int)sizeof(probe)) {
        ns_init_flags |= FS_INIT_FLAGS_DO_CLEAR;
    }

    block_device_tipc_init_dev_rpmb(&self->dev_ns_rpmb, self->rpmb_state,
                                    partition.start, partition.block_count,
                                    true);

#if STORAGE_NS_RECOVERY_CLEAR_ALLOWED
    ns_init_flags |= FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED;
#endif

    /*
     * This must be false if STORAGE_NS_ALTERNATE_SUPERBLOCK_ALLOWED is
     * false.
     */
    if (alternate_data_partition) {
        ns_init_flags |= FS_INIT_FLAGS_ALTERNATE_DATA;
    }

    ret = fs_init(&self->tr_state_ns, file_system_id_td, fs_key,
                  &self->dev_ns.dev, &self->dev_ns_rpmb.dev, ns_init_flags);
    if (ret < 0) {
        SS_ERR("%s: failed to initialize TD: %d\n", __func__, ret);
        goto err_init_fs_ns_tr_state;
    }

    return NS_INIT_SUCCESS;

err_init_fs_ns_tr_state:
    block_cache_dev_destroy(&self->dev_ns.dev);
err_get_td_max_size:
    ns_close_file(self->ipc_handle, self->dev_ns.ns_handle);
    return ret;
}

/**
 * destroy_ns_fs() - Destroy @self's NS fs and its backing block devices.
 */
static void destroy_ns_fs(struct block_device_tipc* self) {
    fs_destroy(&self->tr_state_ns);
    block_cache_dev_destroy(&self->dev_ns.dev);
}

#if HAS_FS_TDP
/**
 * init_tdp_fs() - Initialize @self's TDP fs and its backing block devices.
 * @self:      The struct block_device_tipc to modify
 * @fs_key:    The key to use for the filesystem.
 * @partition: The RPMB blocks to use for the filesystem's superblocks.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int init_tdp_fs(struct block_device_tipc* self,
                       const struct key* fs_key,
                       struct rpmb_span partition) {
    block_device_tipc_init_dev_ns(&self->dev_ns_tdp, self->ipc_handle, false);

    int ret = block_device_ns_open_file(&self->dev_ns_tdp, tdp_filename, true);
    if (ret < 0) {
        SS_ERR("%s: failed to open tdp file (%d)\n", __func__, ret);
        goto err_open_tdp;
    }

    ret = set_storage_size(self->ipc_handle, &self->dev_ns_tdp);
    if (ret < 0) {
        goto err_get_tdp_max_size;
    }

    block_device_tipc_init_dev_rpmb(&self->dev_ns_tdp_rpmb, self->rpmb_state,
                                    partition.start, partition.block_count,
                                    false);

    uint32_t tdp_init_flags = FS_INIT_FLAGS_NONE;
#if STORAGE_TDP_AUTO_CHECKPOINT_ENABLED
    if (!system_state_provisioning_allowed()) {
        /*
         * Automatically create a checkpoint if we are done provisioning but do
         * not already have a checkpoint.
         */
        tdp_init_flags |= FS_INIT_FLAGS_AUTO_CHECKPOINT;
    }
#endif

    ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
                  &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
                  tdp_init_flags);
    if (ret < 0) {
        goto err_init_fs_ns_tdp_tr_state;
    }

#if STORAGE_TDP_RECOVERY_CHECKPOINT_RESTORE_ALLOWED
    if (fs_check(&self->tr_state_ns_tdp) == FS_CHECK_INVALID_BLOCK) {
        SS_ERR("%s: TDP filesystem check failed with invalid block, "
               "attempting to restore checkpoint\n",
               __func__);
        fs_destroy(&self->tr_state_ns_tdp);
        ret = fs_init(&self->tr_state_ns_tdp, file_system_id_tdp, fs_key,
                      &self->dev_ns_tdp.dev, &self->dev_ns_tdp_rpmb.dev,
                      tdp_init_flags | FS_INIT_FLAGS_RESTORE_CHECKPOINT);
        if (ret < 0) {
            SS_ERR("%s: failed to initialize TDP: %d\n", __func__, ret);
            goto err_init_fs_ns_tdp_tr_state;
        }
    }
#endif

    return 0;

err_init_fs_ns_tdp_tr_state:
    block_cache_dev_destroy(&self->dev_ns_tdp.dev);
err_get_tdp_max_size:
    ns_close_file(self->ipc_handle, self->dev_ns_tdp.ns_handle);
err_open_tdp:
    return ret;
}

/**
 * destroy_tdp_fs() - Destroy @self's TDP fs and its backing block devices.
 */
static void destroy_tdp_fs(struct block_device_tipc* self) {
    fs_destroy(&self->tr_state_ns_tdp);
    block_cache_dev_destroy(&self->dev_ns_tdp.dev);
}
#endif

#if HAS_FS_NSP
/**
 * init_nsp_fs() - Initialize @self's NSP fs and its backing block devices.
 * @self:      The struct block_device_tipc to modify
 * @fs_key:    The key to use for the filesystem.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int init_nsp_fs(struct block_device_tipc* self,
                       const struct key* fs_key) {
    block_device_tipc_init_dev_ns(&self->dev_ns_nsp, self->ipc_handle, false);

    int ret = block_device_ns_open_file(&self->dev_ns_nsp, nsp_filename, true);
    if (ret < 0) {
        SS_ERR("%s: failed to open NSP file (%d)\n", __func__, ret);
        goto err_open_nsp;
    }

    ret = set_storage_size(self->ipc_handle, &self->dev_ns_nsp);
    if (ret < 0) {
        goto err_get_nsp_max_size;
    }

    ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
                  &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
                  FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED |
                          FS_INIT_FLAGS_ALLOW_TAMPERING);
    if (ret < 0) {
        SS_ERR("%s: failed to initialize NSP: %d\n", __func__, ret);
        goto err_init_fs_ns_nsp_tr_state;
    }

    /*
     * Check that all files are accessible and attempt to clear the FS if files
     * cannot be accessed.
     */
    if (fs_check(&self->tr_state_ns_nsp) != FS_CHECK_NO_ERROR) {
        SS_ERR("%s: NSP filesystem check failed, attempting to clear\n",
               __func__);
        fs_destroy(&self->tr_state_ns_nsp);
        block_cache_dev_destroy(&self->dev_ns_nsp.dev);

        ret = fs_init(&self->tr_state_ns_nsp, file_system_id_nsp, fs_key,
                      &self->dev_ns_nsp.dev, &self->dev_ns_nsp.dev,
                      FS_INIT_FLAGS_DO_CLEAR | FS_INIT_FLAGS_ALLOW_TAMPERING);
        if (ret < 0) {
            SS_ERR("%s: failed to initialize NSP: %d\n", __func__, ret);
            goto err_init_fs_ns_nsp_tr_state;
        }
    }
    return 0;

err_init_fs_ns_nsp_tr_state:
    block_cache_dev_destroy(&self->dev_ns_nsp.dev);
err_get_nsp_max_size:
    ns_close_file(self->ipc_handle, self->dev_ns_nsp.ns_handle);
err_open_nsp:
    return ret;
}

/**
 * destroy_nsp_fs() - Destroy @self's NSP fs and its backing block devices.
 */
static void destroy_nsp_fs(struct block_device_tipc* self) {
    fs_destroy(&self->tr_state_ns_nsp);
    block_cache_dev_destroy(&self->dev_ns_nsp.dev);
}
#endif

static void block_device_ns_disconnect(struct block_device_ns* self) {
    if (self->ipc_handle != INVALID_IPC_HANDLE) {
        ns_close_file(self->ipc_handle, self->ns_handle);
        self->ipc_handle = INVALID_IPC_HANDLE;
    }
}

static int init_ns_backed_filesystems(struct block_device_tipc* self,
                                      const struct key* fs_key,
                                      struct rpmb_span ns_partition,
                                      struct rpmb_span tdp_partition) {
    int ret = init_ns_fs(self, fs_key, ns_partition);
    if (ret == NS_INIT_NOT_READY) {
        /* If we don't currently have ns access, we didn't actually initialize
         * `tr_state_ns`. Trying to init any other ns-dependent fs would fail,
         * so skip them. */
        assert(!block_device_tipc_has_ns(self));
        return 0;
    } else if (ret < 0) {
        goto err_init_ns_fs;
    }

#if HAS_FS_TDP
    ret = init_tdp_fs(self, fs_key, tdp_partition);
    if (ret < 0) {
        goto err_init_tdp_fs;
    }
#endif

#if HAS_FS_NSP
    ret = init_nsp_fs(self, fs_key);
    if (ret < 0) {
        goto err_init_nsp_fs;
    }
#endif

    return 0;

#if HAS_FS_NSP
err_init_nsp_fs:
#endif
#if HAS_FS_TDP
    block_device_ns_disconnect(&self->dev_ns_tdp);
    destroy_tdp_fs(self);
err_init_tdp_fs:
#endif
    block_device_ns_disconnect(&self->dev_ns);
    destroy_ns_fs(self);
err_init_ns_fs:
    return ret;
}

/**
 * rpmb_span_end() - Calculates the first block past the end of @self.
 */
static uint16_t rpmb_span_end(struct rpmb_span self) {
    return self.start + self.block_count;
}

/**
 * calculate_rpmb_spans() - Determines the starts and sizes of RPMB partitions.
 */
static void calculate_rpmb_spans(struct rpmb_spans* out) {
    out->key.block_count = 1;
    /* Used to store superblocks */
    out->ns.block_count = 2;
#if HAS_FS_TDP
    out->tdp.block_count = out->ns.block_count;
#else
    out->tdp.block_count = 0;
#endif

    out->key.start = 0;
    out->ns.start = rpmb_span_end(out->key);
    out->tdp.start = rpmb_span_end(out->ns);
    out->rpmb_start = rpmb_span_end(out->tdp);
}

int block_device_tipc_init(struct block_device_tipc* state,
                           handle_t ipc_handle,
                           const struct key* fs_key,
                           const struct rpmb_key* rpmb_key,
                           hwkey_session_t hwkey_session) {
    int ret;
    struct rpmb_spans partitions;
    calculate_rpmb_spans(&partitions);

    state->ipc_handle = ipc_handle;

    /* init rpmb */
    ret = rpmb_init(&state->rpmb_state, &state->ipc_handle);
    if (ret < 0) {
        SS_ERR("%s: rpmb_init failed (%d)\n", __func__, ret);
        goto err_rpmb_init;
    }

    ret = block_device_tipc_init_rpmb_key(state->rpmb_state, rpmb_key,
                                          partitions.key.start, hwkey_session);
    if (ret < 0) {
        SS_ERR("%s: block_device_tipc_init_rpmb_key failed (%d)\n", __func__,
               ret);
        goto err_init_rpmb_key;
    }

    ret = init_rpmb_fs(state, fs_key, partitions.rpmb_start);
    if (ret < 0) {
        goto err_init_rpmb_fs;
    }

    ret = init_ns_backed_filesystems(state, fs_key, partitions.ns,
                                     partitions.tdp);
    if (ret < 0) {
        goto err_init_ns_fs;
    }

    return 0;

err_init_ns_fs:
    destroy_rpmb_fs(state);
err_init_rpmb_fs:
err_init_rpmb_key:
    rpmb_uninit(state->rpmb_state);
err_rpmb_init:
    return ret;
}

void block_device_tipc_destroy(struct block_device_tipc* state) {
    if (block_device_tipc_has_ns(state)) {
#if HAS_FS_NSP
        destroy_nsp_fs(state);
#endif
#if HAS_FS_TDP
        destroy_tdp_fs(state);
#endif
        destroy_ns_fs(state);
    }

    destroy_rpmb_fs(state);
    rpmb_uninit(state->rpmb_state);
}

bool block_device_tipc_fs_connected(struct block_device_tipc* self,
                                    enum storage_filesystem_type fs_type) {
    switch (fs_type) {
    case STORAGE_TP:
        return self->ipc_handle != INVALID_IPC_HANDLE;
    case STORAGE_TDEA:
        return self->ipc_handle != INVALID_IPC_HANDLE;
    case STORAGE_TD:
        return block_device_tipc_has_ns(self) &&
               self->dev_ns.ipc_handle != INVALID_IPC_HANDLE;
    case STORAGE_TDP:
#if HAS_FS_TDP
        return block_device_tipc_has_ns(self) &&
               self->dev_ns_tdp.ipc_handle != INVALID_IPC_HANDLE;
#else
        return block_device_tipc_fs_connected(self, STORAGE_TP);
#endif
    case STORAGE_NSP:
#if HAS_FS_NSP
        return block_device_tipc_has_ns(self) &&
               self->dev_ns_nsp.ipc_handle != INVALID_IPC_HANDLE;
#else
        return block_device_tipc_fs_connected(self, STORAGE_TDP);
#endif
    case STORAGE_FILESYSTEMS_COUNT:
    default:
        SS_ERR("%s: Tried to check fs of unrecognized storage_filesystem type: (%d)\n",
               __func__, fs_type);
        return false;
    }
}

struct fs* block_device_tipc_get_fs(struct block_device_tipc* self,
                                    enum storage_filesystem_type fs_type) {
    assert(block_device_tipc_fs_connected(self, fs_type));

    switch (fs_type) {
    case STORAGE_TP:
        return &self->tr_state_rpmb;
    case STORAGE_TDEA:
        return &self->tr_state_rpmb;
    case STORAGE_TD:
        return &self->tr_state_ns;
    case STORAGE_TDP:
#if HAS_FS_TDP
        return &self->tr_state_ns_tdp;
#else
        return block_device_tipc_get_fs(self, STORAGE_TP);
#endif
    case STORAGE_NSP:
#if HAS_FS_NSP
        return &self->tr_state_ns_nsp;
#else
        return block_device_tipc_get_fs(self, STORAGE_TDP);
#endif
    case STORAGE_FILESYSTEMS_COUNT:
    default:
        SS_ERR("%s: Tried to init fs of unrecognized storage_filesystem type: (%d)\n",
               __func__, fs_type);
        return NULL;
    }
}

int block_device_tipc_reconnect(struct block_device_tipc* self,
                                handle_t ipc_handle,
                                const struct key* fs_key) {
    int ret;

    assert(self->ipc_handle == INVALID_IPC_HANDLE);
    /* rpmb_state keeps a pointer to this handle, so updating here will cause
     * all the rpmb connections to use the new handle. */
    self->ipc_handle = ipc_handle;

    bool has_ns = block_device_tipc_has_ns(self);
    if (!has_ns) {
        struct rpmb_spans partitions;
        calculate_rpmb_spans(&partitions);
        ret = init_ns_backed_filesystems(self, fs_key, partitions.ns,
                                         partitions.tdp);
        if (ret < 0) {
            SS_ERR("%s: failed to init NS backed filesystems (%d)\n", __func__,
                   ret);
            return ret;
        }
        return 0;
    }

    bool alternate_data_partition;
    self->dev_ns.ipc_handle = ipc_handle;
    ret = block_device_ns_open_file_with_alternate(&self->dev_ns, ns_filename,
                                                   ns_alternate_filename, false,
                                                   &alternate_data_partition);
    if (ret < 0) {
        /* NS not available right now; leave NS filesystems disconnected. */
        self->dev_ns.ipc_handle = INVALID_IPC_HANDLE;
        SS_ERR("%s: failed to reconnect ns filesystem (%d)\n", __func__, ret);
        return 0;
    }
    assert(alternate_data_partition == self->tr_state_ns.alternate_data);
#if HAS_FS_TDP
    self->dev_ns_tdp.ipc_handle = ipc_handle;
    ret = block_device_ns_open_file(&self->dev_ns_tdp, tdp_filename, false);
    if (ret < 0) {
        SS_ERR("%s: failed to reconnect tdp filesystem (%d)\n", __func__, ret);
        self->dev_ns_tdp.ipc_handle = INVALID_IPC_HANDLE;
        goto err_reconnect_tdp;
    }
#endif
#if HAS_FS_NSP
    self->dev_ns_nsp.ipc_handle = ipc_handle;
    ret = block_device_ns_open_file(&self->dev_ns_nsp, nsp_filename, false);
    if (ret < 0) {
        SS_ERR("%s: failed to reconnect nsp filesystem (%d)\n", __func__, ret);
        self->dev_ns_nsp.ipc_handle = INVALID_IPC_HANDLE;
        goto err_reconnect_nsp;
    }
#endif

    return 0;
#if HAS_FS_NSP
err_reconnect_nsp:
#endif
#if HAS_FS_TDP
    block_device_ns_disconnect(&self->dev_ns_tdp);
err_reconnect_tdp:
#endif
    block_device_ns_disconnect(&self->dev_ns);
    return ret;
}

void block_device_tipc_disconnect(struct block_device_tipc* self) {
    /* Must currently be connected to disconnect */
    assert(self->ipc_handle != INVALID_IPC_HANDLE);
    /* Disconnects rpmb */
    self->ipc_handle = INVALID_IPC_HANDLE;

    if (block_device_tipc_has_ns(self)) {
        block_device_ns_disconnect(&self->dev_ns);
#if HAS_FS_TDP
        block_device_ns_disconnect(&self->dev_ns_tdp);
#endif
#if HAS_FS_NSP
        block_device_ns_disconnect(&self->dev_ns_nsp);
#endif
    }
}
