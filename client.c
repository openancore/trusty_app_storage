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
#include "client.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <interface/storage/storage.h>
#include <lib/system_state/system_state.h>
#include <lk/list.h>

#include "client_session.h"
#include "file.h"
#include "session.h"
#include "storage_limits.h"

// macros to help manage debug output
#define SS_ERR(args...) fprintf(stderr, "ss: " args)

#if 0
// this can generate a lot of spew on debug builds
#define SS_INFO(args...) fprintf(stderr, "ss: " args)
#else
#define SS_INFO(args...) \
    do {                 \
    } while (0)
#endif

/**
 * checkpoint_update_allowed - Is checkpoint modification currently allowed?
 * @transaction:    Transaction object.
 *
 * Check if the given transaction is allowed to create a new or update the
 * existing checkpoint for its file system. Checkpoint updates may only be
 * requested by client while the device is in provisioning mode.
 *
 * Returns %true if a transaction may update the current checkpoint state,
 * %false otherwise.
 */
static bool checkpoint_update_allowed(struct transaction* tr) {
    return system_state_provisioning_allowed();
}

/*
 * Legal secure storage directory and file names contain only
 * characters from the following set: [a-z][A-Z][0-9][.-_]
 *
 * It is not null terminated.
 */
static int is_valid_name(const char* name, size_t name_len) {
    size_t i;

    if (!name_len)
        return 0;

    for (i = 0; i < name_len; i++) {
        if ((name[i] >= 'a') && (name[i] <= 'z'))
            continue;
        if ((name[i] >= 'A') && (name[i] <= 'Z'))
            continue;
        if ((name[i] >= '0') && (name[i] <= '9'))
            continue;
        if ((name[i] == '.') || (name[i] == '-') || (name[i] == '_'))
            continue;

        // not a legal character so reject this name
        return 0;
    }

    return 1;
}

static int get_path(char* path_out,
                    size_t path_out_size,
                    const uuid_t* uuid,
                    const char* file_name,
                    size_t file_name_len) {
    unsigned int rc;

    rc = snprintf(path_out, path_out_size,
                  "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x/",
                  uuid->time_low, uuid->time_mid, uuid->time_hi_and_version,
                  uuid->clock_seq_and_node[0], uuid->clock_seq_and_node[1],
                  uuid->clock_seq_and_node[2], uuid->clock_seq_and_node[3],
                  uuid->clock_seq_and_node[4], uuid->clock_seq_and_node[5],
                  uuid->clock_seq_and_node[6], uuid->clock_seq_and_node[7]);

    if (rc + file_name_len >= path_out_size) {
        return STORAGE_ERR_NOT_VALID;
    }

    memcpy(path_out + rc, file_name, file_name_len);
    path_out[rc + file_name_len] = '\0';

    return STORAGE_NO_ERROR;
}

static enum storage_err file_op_result_to_storage_err(
        enum file_op_result result) {
    switch (result) {
    case FILE_OP_SUCCESS:
        return STORAGE_NO_ERROR;
    case FILE_OP_ERR_FAILED:
        // TODO: Consider returning STORAGE_ERR_TRANSACT consistently
        return STORAGE_ERR_GENERIC;
    case FILE_OP_ERR_EXIST:
        return STORAGE_ERR_EXIST;
    case FILE_OP_ERR_ALREADY_OPEN:
        return STORAGE_ERR_NOT_ALLOWED;
    case FILE_OP_ERR_NOT_FOUND:
        return STORAGE_ERR_NOT_FOUND;
    case FILE_OP_ERR_FS_REPAIRED:
        return STORAGE_ERR_FS_REPAIRED;
    }

    SS_ERR("%s: Unknown file_op_result: %d\n", __func__, result);
    return STORAGE_ERR_GENERIC;
}

static enum storage_err session_set_files_count(
        struct storage_client_session* session,
        size_t files_count) {
    struct file_handle** files;

    if (files_count > STORAGE_MAX_OPEN_FILES) {
        SS_ERR("%s: too many open files\n", __func__);
        return STORAGE_ERR_NOT_VALID;
    }

    if (!files_count) {
        free(session->files);
        session->files = NULL;
    } else {
        files = realloc(session->files, sizeof(files[0]) * files_count);
        if (!files) {
            SS_ERR("%s: out of memory\n", __func__);
            return STORAGE_ERR_GENERIC;
        }
        if (files_count > session->files_count)
            memset(files + session->files_count, 0,
                   sizeof(files[0]) * (files_count - session->files_count));

        session->files = files;
    }
    session->files_count = files_count;

    SS_INFO("%s: new file table size, 0x%zx\n", __func__, files_count);

    return STORAGE_NO_ERROR;
}

static void session_shrink_files(struct storage_client_session* session) {
    uint32_t handle;

    handle = session->files_count;
    while (handle > 0 && !session->files[handle - 1])
        handle--;

    if (handle < session->files_count)
        session_set_files_count(session, handle);
}

static void session_close_all_files(struct storage_client_session* session) {
    uint32_t f_handle;
    struct file_handle* file;

    for (f_handle = 0; f_handle < session->files_count; f_handle++) {
        file = session->files[f_handle];
        if (file) {
            file_close(file);
            free(file);
        }
    }
    if (session->files) {
        free(session->files);
    }
    session->files_count = 0;
}

static enum storage_err create_file_handle(
        struct storage_client_session* session,
        uint32_t* handlep,
        struct file_handle** file_p) {
    enum storage_err result;
    uint32_t handle;
    struct file_handle* file;

    for (handle = 0; handle < session->files_count; handle++)
        if (!session->files[handle])
            break;

    if (handle >= session->files_count) {
        result = session_set_files_count(session, handle + 1);
        if (result != STORAGE_NO_ERROR)
            return result;
    }

    file = calloc(1, sizeof(*file));
    if (!file) {
        SS_ERR("%s: out of memory\n", __func__);
        return STORAGE_ERR_GENERIC;
    }

    session->files[handle] = file;

    SS_INFO("%s: created file handle 0x%" PRIx32 "\n", __func__, handle);
    *handlep = handle;
    *file_p = file;
    return STORAGE_NO_ERROR;
}

static void free_file_handle(struct storage_client_session* session,
                             uint32_t handle) {
    if (handle >= session->files_count) {
        SS_ERR("%s: invalid handle, 0x%" PRIx32 "\n", __func__, handle);
        return;
    }
    if (session->files[handle] == NULL) {
        SS_ERR("%s: closed handle, 0x%" PRIx32 "\n", __func__, handle);
        return;
    }
    free(session->files[handle]);
    session->files[handle] = NULL;

    SS_INFO("%s: deleted file handle 0x%" PRIx32 "\n", __func__, handle);

    session_shrink_files(session);
}

static struct file_handle* get_file_handle(
        struct storage_client_session* session,
        uint32_t handle) {
    struct file_handle* file;
    if (handle >= session->files_count) {
        SS_ERR("%s: invalid handle, 0x%" PRIx32 "\n", __func__, handle);
        return NULL;
    }
    file = session->files[handle];
    if (!file) {
        SS_ERR("%s: closed handle, 0x%" PRIx32 "\n", __func__, handle);
        return NULL;
    }
    return file;
}

static enum storage_err assert_checkpoint_flag_valid(
        struct storage_client_session* session,
        struct storage_op_flags flags,
        const char* func_name) {
    if (flags.update_checkpoint) {
        if (!(flags.complete_transaction)) {
            SS_ERR("%s: STORAGE_MSG_FLAG_TRANSACT_CHECKPOINT cannot "
                   "be used without STORAGE_MSG_FLAG_TRANSACT_COMPLETE\n",
                   func_name);
            return STORAGE_ERR_NOT_VALID;
        }

        if (!checkpoint_update_allowed(&session->tr)) {
            SS_ERR("%s: Checkpoint requested but not currently allowed.\n",
                   func_name);
            return STORAGE_ERR_NOT_ALLOWED;
        }
    }
    return STORAGE_NO_ERROR;
}

static enum storage_err ensure_active_transaction(
        struct storage_client_session* session,
        struct storage_op_flags flags) {
    if (session->tr.failed) {
        if (flags.complete_transaction) {
            /* last command in current transaction:
             * reset failed state and return error */
            session->tr.failed = false;
        }
        return STORAGE_ERR_TRANSACT;
    }

    if (!transaction_is_active(&session->tr)) {
        /* previous transaction complete */
        transaction_activate(&session->tr);
    }
    return STORAGE_NO_ERROR;
}

void storage_client_session_init(struct storage_client_session* session,
                                 struct fs* fs,
                                 const uuid_t* peer) {
    session->magic = STORAGE_CLIENT_SESSION_MAGIC;
    session->files = NULL;
    session->files_count = 0;

    transaction_init(&session->tr, fs, false);

    /* cache identity information */
    memcpy(&session->uuid, peer, sizeof(*peer));
}

void storage_client_session_destroy(struct storage_client_session* session) {
    if (list_in_list(&session->tr.allocated.node) && !session->tr.failed) {
        /* discard partial transaction */
        transaction_fail(&session->tr);
    }
    session_close_all_files(session);
    transaction_free(&session->tr);
}

/* abort transaction and clear sticky transaction error */
enum storage_err storage_transaction_end(struct storage_client_session* session,
                                         struct storage_op_flags flags) {
    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    if (flags.complete_transaction) {
        /* Allow checkpoint creation without an active transaction */
        if (flags.update_checkpoint && !transaction_is_active(&session->tr)) {
            transaction_activate(&session->tr);
        }
        /* try to complete current transaction */
        if (transaction_is_active(&session->tr)) {
            transaction_complete_etc(&session->tr, flags.update_checkpoint);
        }
        if (session->tr.failed) {
            SS_ERR("%s: failed to complete transaction\n", __func__);
            /* clear transaction failed state */
            session->tr.failed = false;
            return STORAGE_ERR_TRANSACT;
        }
        return STORAGE_NO_ERROR;
    }

    /* discard current transaction */
    if (transaction_is_active(&session->tr)) {
        transaction_fail(&session->tr);
    }
    /* clear transaction failed state */
    session->tr.failed = false;
    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_delete(struct storage_client_session* session,
                                     const char* fname,
                                     size_t fname_len,
                                     struct storage_op_flags flags) {
    enum file_op_result delete_res;
    char path_buf[FS_PATH_MAX];

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    /* make sure filename is legal */
    if (!is_valid_name(fname, fname_len)) {
        SS_ERR("%s: invalid filename\n", __func__);
        return STORAGE_ERR_NOT_VALID;
    }

    result = get_path(path_buf, sizeof(path_buf), &session->uuid, fname,
                      fname_len);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    SS_INFO("%s: path %s\n", __func__, path_buf);

    delete_res = file_delete(&session->tr, path_buf, flags.allow_repaired);

    if (delete_res != FILE_OP_SUCCESS) {
        return file_op_result_to_storage_err(delete_res);
    }

    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
        if (session->tr.failed) {
            SS_ERR("%s: transaction commit failed\n", __func__);
            return STORAGE_ERR_GENERIC;
        }
    }

    return STORAGE_NO_ERROR;
}

/**
 * storage_file_check_name - Check if file handle matches path
 * @tr:         Transaction object.
 * @file:       File handle object.
 * @path:       Path to check.
 *
 * Return: %true if @file matches @path, %false otherwise.
 */
static bool storage_file_check_name(struct transaction* tr,
                                    const struct file_handle* file,
                                    const char* path) {
    bool ret;
    const struct file_info* file_info;
    struct obj_ref ref = OBJ_REF_INITIAL_VALUE(ref);

    file_info = file_get_info(tr, &file->block_mac, &ref);
    if (!file_info) {
        printf("can't read file entry at %" PRIu64 "\n",
               block_mac_to_block(tr, &file->block_mac));
        return false;
    }
    assert(file_info);
    ret = strcmp(file_info->path, path) == 0;
    file_info_put(file_info, &ref);

    return ret;
}

enum storage_err storage_file_move(struct storage_client_session* session,
                                   uint32_t handle,
                                   bool src_already_opened,
                                   const char* src_name,
                                   size_t src_name_len,
                                   const char* dst_name,
                                   size_t dst_name_len,
                                   enum file_create_mode dst_file_create_mode,
                                   struct storage_op_flags flags) {
    enum file_op_result open_result;
    enum file_op_result move_result;
    struct file_handle* file = NULL;
    char path_buf[FS_PATH_MAX];
    struct file_handle tmp_file;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    /* make sure filenames are legal */
    if (!is_valid_name(src_name, src_name_len)) {
        SS_ERR("%s: invalid src filename\n", __func__);
        return STORAGE_ERR_NOT_VALID;
    }
    if (!is_valid_name(dst_name, dst_name_len)) {
        SS_ERR("%s: invalid dst filename\n", __func__);
        return STORAGE_ERR_NOT_VALID;
    }

    if (src_already_opened) {
        file = get_file_handle(session, handle);
        if (!file)
            return STORAGE_ERR_NOT_VALID;
    }

    result = get_path(path_buf, sizeof(path_buf), &session->uuid, src_name,
                      src_name_len);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    SS_INFO("%s: src path %s\n", __func__, path_buf);

    if (file) {
        if (!storage_file_check_name(&session->tr, file, path_buf)) {
            return STORAGE_ERR_NOT_VALID;
        }
    } else {
        open_result = file_open(&session->tr, path_buf, &tmp_file,
                                FILE_OPEN_NO_CREATE, flags.allow_repaired);
        if (open_result != FILE_OP_SUCCESS) {
            return file_op_result_to_storage_err(open_result);
        }
        file = &tmp_file;
    }

    result = get_path(path_buf, sizeof(path_buf), &session->uuid, dst_name,
                      dst_name_len);
    if (result != STORAGE_NO_ERROR) {
        if (file == &tmp_file) {
            file_close(&tmp_file);
        }
        return result;
    }
    SS_INFO("%s: dst path %s\n", __func__, path_buf);

    move_result = file_move(&session->tr, file, path_buf, dst_file_create_mode,
                            flags.allow_repaired);
    if (file == &tmp_file) {
        file_close(&tmp_file);
    }

    if (move_result != FILE_OP_SUCCESS) {
        return file_op_result_to_storage_err(move_result);
    }

    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
        if (session->tr.failed) {
            SS_ERR("%s: transaction commit failed\n", __func__);
            return STORAGE_ERR_GENERIC;
        }
    }

    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_open(struct storage_client_session* session,
                                   const char* fname,
                                   size_t fname_len,
                                   enum file_create_mode file_create_mode,
                                   bool truncate,
                                   struct storage_op_flags flags,
                                   uint32_t* handle) {
    enum file_op_result open_result;
    struct file_handle* file = NULL;
    uint32_t f_handle;
    char path_buf[FS_PATH_MAX];

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    /* make sure filename is legal */
    if (!is_valid_name(fname, fname_len)) {
        SS_ERR("%s: invalid filename\n", __func__);
        return STORAGE_ERR_NOT_VALID;
    }

    result = get_path(path_buf, sizeof(path_buf), &session->uuid, fname,
                      fname_len);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    SS_INFO("%s: path %s (create_mode: %d, truncate: %d)\n", __func__, path_buf,
            file_create_mode, truncate);

    SS_INFO("%s: call create_file_handle\n", __func__);
    /* alloc file info struct */
    result = create_file_handle(session, &f_handle, &file);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    open_result = file_open(&session->tr, path_buf, file, file_create_mode,
                            flags.allow_repaired);
    if (open_result != FILE_OP_SUCCESS) {
        result = file_op_result_to_storage_err(open_result);
        goto err_open_file;
    }

    if (truncate && file->size) {
        file_set_size(&session->tr, file, 0);
    }

    if (session->tr.failed) {
        SS_ERR("%s: transaction failed\n", __func__);
        result = STORAGE_ERR_GENERIC;
        goto err_transaction_failed;
    }

    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
        if (session->tr.failed) {
            SS_ERR("%s: transaction commit failed\n", __func__);
            result = STORAGE_ERR_GENERIC;
            goto err_transaction_failed;
        }
    }

    *handle = f_handle;
    return STORAGE_NO_ERROR;

err_transaction_failed:
    file_close(file);
err_open_file:
    free_file_handle(session, f_handle);
    return result;
}

enum storage_err storage_file_close(struct storage_client_session* session,
                                    uint32_t handle,
                                    struct storage_op_flags flags) {
    struct file_handle* file;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    file = get_file_handle(session, handle);
    if (!file) {
        return STORAGE_ERR_NOT_VALID;
    }

    file_close(file);
    free_file_handle(session, handle);

    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
        if (session->tr.failed) {
            SS_ERR("%s: transaction commit failed\n", __func__);
            return STORAGE_ERR_GENERIC;
        }
    }

    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_read(struct storage_client_session* session,
                                   uint32_t handle,
                                   uint32_t size,
                                   uint64_t offset,
                                   struct storage_op_flags flags,
                                   uint8_t* resp,
                                   size_t* resp_len) {
    void* bufp = resp;
    size_t buflen;
    size_t bytes_left, len;
    struct file_handle* file;
    size_t block_size = get_file_block_size(session->tr.fs);
    data_block_t block_num;
    const uint8_t* block_data;
    struct obj_ref block_data_ref = OBJ_REF_INITIAL_VALUE(block_data_ref);
    size_t block_offset;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    file = get_file_handle(session, handle);
    if (!file) {
        SS_ERR("%s: invalid file handle (%" PRIx32 ")\n", __func__, handle);
        return STORAGE_ERR_NOT_VALID;
    }

    buflen = size;
    if (buflen > *resp_len) {
        SS_ERR("can't read more than %zu bytes, requested %zu\n", *resp_len,
               buflen);
        return STORAGE_ERR_NOT_VALID;
    }

    if (offset > file->size) {
        SS_ERR("can't read past end of file (%" PRIu64 " > %" PRIu64 ")\n",
               offset, file->size);
        return STORAGE_ERR_NOT_VALID;
    }

    /* calc number of bytes to read */
    if ((offset + buflen) > file->size) {
        bytes_left = (size_t)(file->size - offset);
    } else {
        bytes_left = buflen;
    }
    buflen = bytes_left; /* save to return it to caller */

    SS_INFO("%s: start 0x%" PRIx64 " cnt %zu\n", __func__, offset, bytes_left);

    while (bytes_left) {
        block_num = offset / block_size;
        block_data =
                file_get_block(&session->tr, file, block_num, &block_data_ref);
        block_offset = offset % block_size;
        len = (block_offset + bytes_left > block_size)
                      ? block_size - block_offset
                      : bytes_left;
        if (!block_data) {
            if (session->tr.failed) {
                SS_ERR("error reading block %" PRIu64 "\n", block_num);
                return STORAGE_ERR_GENERIC;
            }
            memset(bufp, 0, len);
        } else {
            memcpy(bufp, block_data + block_offset, len);
            file_block_put(block_data, &block_data_ref);
        }

        bytes_left -= len;
        offset += len;
        bufp += len;
    }

    *resp_len = buflen;
    return STORAGE_NO_ERROR;
}

static enum storage_err storage_create_gap(
        struct storage_client_session* session,
        struct file_handle* file) {
    size_t block_size = get_file_block_size(session->tr.fs);
    data_block_t block_num;
    size_t block_offset;
    uint8_t* block_data;
    struct obj_ref block_data_ref = OBJ_REF_INITIAL_VALUE(block_data_ref);

    block_num = file->size / block_size;
    block_offset = file->size % block_size;

    if (block_offset) {
        /*
         * The file does not currently end on a block boundary.
         * We don't clear data in partial blocks when truncating
         * a file, so the last block could contain data that
         * should not be readable. We unconditionally clear the
         * exposed data when creating gaps in the file, as we
         * don't know if that data is already clear.
         */
        block_data = file_get_block_write(&session->tr, file, block_num, true,
                                          &block_data_ref);
        if (!block_data) {
            SS_ERR("error getting block %" PRIu64 "\n", block_num);
            return STORAGE_ERR_GENERIC;
        }

        memset(block_data + block_offset, 0, block_size - block_offset);
        file_block_put_dirty(&session->tr, file, block_num, block_data,
                             &block_data_ref);

        SS_INFO("%s: clear block at old size 0x%" PRIx64
                ", block_offset 0x%zx\n",
                __func__, file->size, block_offset);
    }
    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_write(struct storage_client_session* session,
                                    uint32_t handle,
                                    uint64_t offset,
                                    const uint8_t* data,
                                    size_t data_len,
                                    struct storage_op_flags flags) {
    size_t len;
    struct file_handle* file;
    size_t block_size = get_file_block_size(session->tr.fs);
    data_block_t block_num;
    uint8_t* block_data;
    struct obj_ref block_data_ref = OBJ_REF_INITIAL_VALUE(block_data_ref);
    size_t block_offset;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    file = get_file_handle(session, handle);
    if (!file) {
        SS_ERR("%s: invalid file handle (%" PRIx32 ")\n", __func__, handle);
        return STORAGE_ERR_NOT_VALID;
    }

    if (offset > file->size) {
        result = storage_create_gap(session, file);
        if (result != STORAGE_NO_ERROR) {
            goto err_write;
        }
    }

    /* transfer data one ss block at a time */
    while (data_len) {
        block_num = offset / block_size;
        block_offset = offset % block_size;
        len = (block_offset + data_len > block_size) ? block_size - block_offset
                                                     : data_len;

        block_data = file_get_block_write(&session->tr, file, block_num,
                                          len != block_size, &block_data_ref);
        if (!block_data) {
            SS_ERR("error getting block %" PRIu64 "\n", block_num);
            result = STORAGE_ERR_GENERIC;
            goto err_write;
        }

        memcpy(block_data + block_offset, data, len);
        file_block_put_dirty(&session->tr, file, block_num, block_data,
                             &block_data_ref);

#if TLOG_LVL >= TLOG_LVL_DEBUG
        SS_INFO("%s: data %p offset 0x%" PRIx64 " len 0x%zx\n", __func__, data,
                offset, len);
#endif
        offset += len;
        data += len;
        data_len -= len;
    }

    if (offset > file->size) {
        file_set_size(&session->tr, file, offset);
    }

    if (session->tr.failed) {
        SS_ERR("%s: transaction failed\n", __func__);
        return STORAGE_ERR_GENERIC;
    }

    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
        if (session->tr.failed) {
            SS_ERR("%s: transaction commit failed\n", __func__);
            return STORAGE_ERR_GENERIC;
        }
    }

    return STORAGE_NO_ERROR;

err_write:
    if (!session->tr.failed) {
        transaction_fail(&session->tr);
    }
err_transaction_complete:
    return result;
}

struct storage_file_list_state {
    struct file_iterate_state iter;
    char prefix[34];
    size_t prefix_len;
    uint8_t max_count;
    uint8_t count;
    bool (*can_record_path)(void* callback_data, size_t max_path_len);
    void (*record_path)(void* callback_data,
                        enum storage_file_list_flag flags,
                        const char* path,
                        size_t path_len);
    void* callback_data;
};

static bool storage_file_list_buf_full(struct storage_file_list_state* miter) {
    if (miter->max_count && miter->count >= miter->max_count) {
        return true;
    }

    return !miter->can_record_path(miter->callback_data,
                                   FS_PATH_MAX - miter->prefix_len);
}

static void storage_file_list_add(struct storage_file_list_state* miter,
                                  enum storage_file_list_flag flags,
                                  const char* path) {
    assert(!storage_file_list_buf_full(miter));
    size_t path_len = path ? strlen(path) : 0;
    assert(path_len <= FS_PATH_MAX - miter->prefix_len);
    miter->record_path(miter->callback_data, flags, path, path_len);
    miter->count++;
}

static bool storage_file_list_iter(struct file_iterate_state* iter,
                                   struct transaction* tr,
                                   const struct block_mac* block_mac,
                                   bool added,
                                   bool removed) {
    struct storage_file_list_state* miter =
            containerof(iter, struct storage_file_list_state, iter);
    const struct file_info* file_info;
    struct obj_ref ref = OBJ_REF_INITIAL_VALUE(ref);

    file_info = file_get_info(tr, block_mac, &ref);

    if (strncmp(file_info->path, miter->prefix, miter->prefix_len) == 0) {
        storage_file_list_add(miter,
                              added     ? STORAGE_FILE_LIST_ADDED
                              : removed ? STORAGE_FILE_LIST_REMOVED
                                        : STORAGE_FILE_LIST_COMMITTED,
                              file_info->path + miter->prefix_len);
    }

    file_info_put(file_info, &ref);

    return storage_file_list_buf_full(miter);
}

enum storage_err storage_file_list(
        struct storage_client_session* session,
        uint8_t max_count,
        enum storage_file_list_flag last_state,
        const char* last_fname,
        size_t last_fname_len,
        struct storage_op_flags flags,
        bool (*can_record_path)(void* callback_data, size_t max_path_len),
        void (*record_path)(void* callback_data,
                            enum storage_file_list_flag flags,
                            const char* path,
                            size_t path_len),
        void* callback_data) {
    enum file_op_result iterate_res;
    const char* last_name;
    char path_buf[FS_PATH_MAX];

    struct storage_file_list_state state = {
            .iter.file = storage_file_list_iter,
            .max_count = max_count,
            .record_path = record_path,
            .can_record_path = can_record_path,
            .callback_data = callback_data,
    };

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    result =
            get_path(state.prefix, sizeof(state.prefix), &session->uuid, "", 0);
    if (result != STORAGE_NO_ERROR) {
        SS_ERR("%s: internal error, get_path failed\n", __func__);
        return STORAGE_ERR_GENERIC;
    }
    state.prefix_len = strlen(state.prefix);

    if (last_state == STORAGE_FILE_LIST_END) {
        SS_ERR("%s: invalid request state (%" PRIx8 ")\n", __func__,
               last_state);
        return STORAGE_ERR_NOT_VALID;
    }

    if (last_state == STORAGE_FILE_LIST_START) {
        last_name = NULL;
    } else {
        /* make sure filename is legal */
        if (!is_valid_name(last_fname, last_fname_len)) {
            SS_ERR("%s: invalid filename\n", __func__);
            return STORAGE_ERR_NOT_VALID;
        }

        result = get_path(path_buf, sizeof(path_buf), &session->uuid,
                          last_fname, last_fname_len);
        if (result != STORAGE_NO_ERROR) {
            return result;
        }

        last_name = path_buf;
    }

    if (last_state != STORAGE_FILE_LIST_ADDED) {
        iterate_res = file_iterate(&session->tr, last_name, false, &state.iter,
                                   flags.allow_repaired);
        last_name = NULL;
    } else {
        iterate_res = FILE_OP_SUCCESS;
    }
    if (iterate_res == FILE_OP_SUCCESS && !storage_file_list_buf_full(&state)) {
        iterate_res = file_iterate(&session->tr, last_name, true, &state.iter,
                                   flags.allow_repaired);
    }
    if (iterate_res != FILE_OP_SUCCESS) {
        SS_ERR("%s: file_iterate failed\n", __func__);
        return file_op_result_to_storage_err(iterate_res);
    }

    if (!storage_file_list_buf_full(&state)) {
        storage_file_list_add(&state, STORAGE_FILE_LIST_END, NULL);
    }

    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_get_size(struct storage_client_session* session,
                                       uint32_t handle,
                                       struct storage_op_flags flags,
                                       uint64_t* size) {
    bool valid;
    struct file_handle* file;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    file = get_file_handle(session, handle);
    if (!file) {
        SS_ERR("%s: invalid file handle (%" PRIx32 ")\n", __func__, handle);
        return STORAGE_ERR_NOT_VALID;
    }

    valid = file_get_size(&session->tr, file, size);
    if (!valid) {
        return STORAGE_ERR_NOT_VALID;
    }

    return STORAGE_NO_ERROR;
}

enum storage_err storage_file_set_size(struct storage_client_session* session,
                                       uint32_t handle,
                                       uint64_t new_size,
                                       struct storage_op_flags flags) {
    struct file_handle* file;

    enum storage_err result =
            assert_checkpoint_flag_valid(session, flags, __func__);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }
    result = ensure_active_transaction(session, flags);
    if (result != STORAGE_NO_ERROR) {
        return result;
    }

    file = get_file_handle(session, handle);
    if (!file) {
        SS_ERR("%s: invalid file handle (%" PRIx32 ")\n", __func__, handle);
        return STORAGE_ERR_NOT_VALID;
    }

    SS_INFO("%s: new size 0x%" PRIx64 ", old size 0x%" PRIx64 "\n", __func__,
            new_size, file->size);

    /* for now we only support shrinking the file */
    if (new_size > file->size) {
        result = storage_create_gap(session, file);
        if (result != STORAGE_NO_ERROR) {
            return result;
        }
        storage_create_gap(session, file);
    }

    /* check for nop */
    if (new_size != file->size) {
        /* update size */
        file_set_size(&session->tr, file, new_size);
    }

    /* try to commit */
    if (flags.complete_transaction) {
        transaction_complete_etc(&session->tr, flags.update_checkpoint);
    }

    if (session->tr.failed) {
        SS_ERR("%s: transaction failed\n", __func__);
        return STORAGE_ERR_GENERIC;
    }

    return STORAGE_NO_ERROR;
}