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

#include <stdint.h>

#include <interface/storage/storage.h>
#include <lk/compiler.h>
#include <uapi/trusty_uuid.h>

#include "client_session.h"
#include "file.h"

/**
 * struct storage_op_flags - Flags shared by all storage operations
 * @allow_repaired: If true, encountering a repaired filesystem will _not_
 * result in an error.
 * @complete_transaction: If true, complete the currently active transaction
 * after performing this operation.
 * @update_checkpoint: If true, update the checkpoint with the post-operation
 * filesystem state.
 */
struct storage_op_flags {
    bool allow_repaired;
    bool complete_transaction;
    bool update_checkpoint;
};

__BEGIN_CDECLS

/**
 * storage_client_session_init() - Initialize a new &struct
 * storage_client_session.
 * @session: The session to be initialized.
 * @fs: The filesystem this session will modify.
 * @peer: Id of the peer this session was created for.
 */
void storage_client_session_init(struct storage_client_session* session,
                                 struct fs* fs,
                                 const uuid_t* peer);

/**
 * storage_client_session_destroy() - Destroy a &struct storage_client_session.
 * @session: The session to be destroyed.
 */
void storage_client_session_destroy(struct storage_client_session* session);

/**
 * storage_transaction_end() - End the currently active transaction and start a
 * new one. If @flags.complete_transaction is true, try to complete the current
 * transaction. Otherwise, abandon it.
 * @session: The session to perform the operation.
 * @flags: Flags for performing this operation. @flags.complete_transaction
 * controls whether the transaction will be completed or abandoned; see above.
 * See &struct storage_op_flags for further details.
 */
enum storage_err storage_transaction_end(struct storage_client_session* session,
                                         struct storage_op_flags flags);

/**
 * storage_file_delete() - Delete a file.
 * @session: The session to perform the operation.
 * @fname: The string containing the name of the file to be deleted.
 * @fname_len: The length of the name of the file to be deleted.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 */
enum storage_err storage_file_delete(struct storage_client_session* session,
                                     const char* fname,
                                     size_t fname_len,
                                     struct storage_op_flags flags);

/**
 * storage_file_move() - Move a file from ``src`` to location ``dst``.
 * @session: The session to perform the operation.
 * @handle: The opened file handle for the ``src`` file. Ignored if
 * @src_already_opened is false.
 * @src_already_opened: True if the ``src`` file is already opened and @handle
 * conatins its file handle.
 * @src_name: The string containing the name of the ``src`` file. If
 * @src_already_opened is true, this must match the name of the file @handle
 * points to.
 * @src_name_len: The length of the @src_name.
 * @dst_name: The string containing the name of the file's destination.
 * @dst_name_len: The length of @dst_name.
 * @dst_file_create_mode: Creation behavior for the ``dst`` file.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 */
enum storage_err storage_file_move(struct storage_client_session* session,
                                   uint32_t handle,
                                   bool src_already_opened,
                                   const char* src_name,
                                   size_t src_name_len,
                                   const char* dst_name,
                                   size_t dst_name_len,
                                   enum file_create_mode dst_file_create_mode,
                                   struct storage_op_flags flags);

/**
 * storage_file_open() - Open a file and provide a handle to it.
 * @session: The session to perform the operation.
 * @fname: The string containing the name of the file to open.
 * @fname_len: The length of the name of the file to open.
 * @file_create_mode: Creation behavior for the file.
 * @truncate: If true, clear the file's contents while opening it.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 * @handle: Out-param that will contain the opened file's handle. Only populated
 * on success.
 */
enum storage_err storage_file_open(struct storage_client_session* session,
                                   const char* fname,
                                   size_t fname_len,
                                   enum file_create_mode file_create_mode,
                                   bool truncate,
                                   struct storage_op_flags flags,
                                   uint32_t* handle);

/**
 * storage_file_close() - Close a previously opened file.
 * @session: The session to perform the operation.
 * @handle: The file handle previously created by storage_file_open().
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 */
enum storage_err storage_file_close(struct storage_client_session* session,
                                    uint32_t handle,
                                    struct storage_op_flags flags);

/**
 * storage_file_read() - Read a sequence of bytes from an open file.
 * @session: The session to perform the operation.
 * @handle: The file handle previously created by storage_file_open().
 * @size: The size of the byte sequence to read.
 * @offset: The offset from the beginning of the file at which to start reading.
 * The bytes read will be ``file[offset..offset + size]``.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 * @resp: Out-param. The buffer into which the read bytes will be written.
 * @resp_len: Before the calling ``*resp_len`` should contain the length of the
 * &resp buffer. After a successful call returns, ``*resp_len`` will contain the
 * total number of bytes written to &resp.
 */
enum storage_err storage_file_read(struct storage_client_session* session,
                                   uint32_t handle,
                                   uint32_t size,
                                   uint64_t offset,
                                   struct storage_op_flags flags,
                                   uint8_t* resp,
                                   size_t* resp_len);

/**
 * storage_file_write() - Write a sequence of bytes to an open file.
 * @session: The session to perform the operation.
 * @handle: The file handle previously created by storage_file_open().
 * @offset: The offset from the beginning of the file at which to start writing.
 * The bytes will be written to ``file[offset..offset + data.len]``.
 * @data: Buffer containing the data to write.
 * @data_len: Length of the data to write, in bytes.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 */
enum storage_err storage_file_write(struct storage_client_session* session,
                                    uint32_t handle,
                                    uint64_t offset,
                                    const uint8_t* data,
                                    size_t data_len,
                                    struct storage_op_flags flags);

/**
 * storage_file_list() - Lists the names of files.
 * @session: The session to perform the operation.
 * @max_count: The maximum number of file path entries to be recorded with
 * @record_path.
 * @last_state: Either %STORAGE_FILE_LIST_START or the @flags arg of the last
 * call to @record_path during the previous call to storage_file_list().
 * @last_fname: Ignored if @last_state is %STORAGE_FILE_LIST_START. Otherwise,
 * @last_fname should contain the @path arg of the last call to @record_path
 * during the previous call to storage_file_list().
 * @last_fname_len: The length of @last_fname if @last_fname is present. Ignored
 * otherwise.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 * @can_record_path: Checks whether a path (with a length less than or equal to
 * @can_record_path.max_path_len) can be recorded using the @record_path
 * callback.
 * @record_path: Records a @record_path.path that is @record_path.path_len bytes
 * long. @record_path.path may be null if @record_path.flags is
 * %STORAGE_FILE_LIST_END.
 * @callback_data: Will be passed as the first argument to calls to
 * @can_record_path and @record_path.
 */
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
        void* callback_data);

/**
 * storage_file_get_size() - Gets the size of a file.
 * @session: The session to perform the operation.
 * @handle: The file handle previously created by storage_file_open().
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 * @size: Out-param. After a successful call, contains the file's size.
 */
enum storage_err storage_file_get_size(struct storage_client_session* session,
                                       uint32_t handle,
                                       struct storage_op_flags flags,
                                       uint64_t* size);

/**
 * storage_file_set_size() - Sets the size of a file. Truncates if the file is
 * larger than @new_size.
 * @session: The session to perform the operation.
 * @handle: The file handle previously created by storage_file_open().
 * @new_size: The file's target size.
 * @flags: Flags for performing this operation. See &struct storage_op_flags for
 * details.
 */
enum storage_err storage_file_set_size(struct storage_client_session* session,
                                       uint32_t handle,
                                       uint64_t new_size,
                                       struct storage_op_flags flags);

__END_CDECLS