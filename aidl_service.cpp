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

#include "aidl_service.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

#include <trusty_ipc.h>

#include <interface/storage/storage_aidl/ports.h>

#include <binder/RpcServerTrusty.h>
#include <binder/Status.h>
#include <utils/Errors.h>

#include <android/hardware/security/see/storage/BnDir.h>
#include <android/hardware/security/see/storage/BnFile.h>
#include <android/hardware/security/see/storage/BnSecureStorage.h>
#include <android/hardware/security/see/storage/BnStorageSession.h>
#include <android/hardware/security/see/storage/CreationMode.h>
#include <android/hardware/security/see/storage/DeleteOptions.h>
#include <android/hardware/security/see/storage/FileAvailability.h>
#include <android/hardware/security/see/storage/FileIntegrity.h>
#include <android/hardware/security/see/storage/FileMode.h>
#include <android/hardware/security/see/storage/FileProperties.h>
#include <android/hardware/security/see/storage/IDir.h>
#include <android/hardware/security/see/storage/IFile.h>
#include <android/hardware/security/see/storage/ISecureStorage.h>
#include <android/hardware/security/see/storage/IStorageSession.h>
#include <android/hardware/security/see/storage/OpenOptions.h>
#include <android/hardware/security/see/storage/ReadIntegrity.h>
#include <android/hardware/security/see/storage/RenameOptions.h>

#include "client.h"
#include "client_session.h"
#include "file.h"
#include "storage_limits.h"

using ::android::RpcServerTrusty;
using ::android::RpcSession;
using ::android::sp;
using ::android::wp;
using ::android::binder::Status;
using ::android::hardware::security::see::storage::BnDir;
using ::android::hardware::security::see::storage::BnFile;
using ::android::hardware::security::see::storage::BnSecureStorage;
using ::android::hardware::security::see::storage::BnStorageSession;
using ::android::hardware::security::see::storage::CreationMode;
using ::android::hardware::security::see::storage::DeleteOptions;
using ::android::hardware::security::see::storage::FileAvailability;
using ::android::hardware::security::see::storage::FileIntegrity;
using ::android::hardware::security::see::storage::FileMode;
using ::android::hardware::security::see::storage::FileProperties;
using ::android::hardware::security::see::storage::IDir;
using ::android::hardware::security::see::storage::IFile;
using ::android::hardware::security::see::storage::ISecureStorage;
using ::android::hardware::security::see::storage::IStorageSession;
using ::android::hardware::security::see::storage::OpenOptions;
using ::android::hardware::security::see::storage::ReadIntegrity;
using ::android::hardware::security::see::storage::RenameOptions;

#define SS_ERR(args...) fprintf(stderr, "ss-aidl: " args)

namespace storage_service {
namespace {

constexpr uint32_t kAclFlags =
#if TEST_BUILD
        IPC_PORT_ALLOW_TA_CONNECT | IPC_PORT_ALLOW_NS_CONNECT;
#else
        IPC_PORT_ALLOW_TA_CONNECT;
#endif

constexpr size_t kMaxBufferSize = STORAGE_MAX_BUFFER_SIZE;

static Status status_from_storage_err(storage_err err) {
    switch (err) {
    case storage_err::STORAGE_NO_ERROR:
        return Status::ok();
    case storage_err::STORAGE_ERR_GENERIC:
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    case storage_err::STORAGE_ERR_NOT_VALID:
        return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
    case storage_err::STORAGE_ERR_UNIMPLEMENTED:
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    case storage_err::STORAGE_ERR_ACCESS:
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    case storage_err::STORAGE_ERR_NOT_FOUND:
        return Status::fromServiceSpecificError(ISecureStorage::ERR_NOT_FOUND);
    case storage_err::STORAGE_ERR_EXIST:
        return Status::fromServiceSpecificError(
                ISecureStorage::ERR_ALREADY_EXISTS);
    case storage_err::STORAGE_ERR_TRANSACT:
        return Status::fromServiceSpecificError(
                ISecureStorage::ERR_BAD_TRANSACTION);
    case storage_err::STORAGE_ERR_NOT_ALLOWED:
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    case storage_err::STORAGE_ERR_CORRUPTED:
        return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE);
    case storage_err::STORAGE_ERR_FS_REPAIRED:
        // TODO: Distinguish rolled back vs reset; catch other tampering
        return Status::fromServiceSpecificError(
                ISecureStorage::ERR_FS_ROLLED_BACK);
    default:
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION,
                                         "Unknown error code.");
    }
}

static file_create_mode create_mode(CreationMode mode) {
    switch (mode) {
    case CreationMode::CREATE_EXCLUSIVE:
        return file_create_mode::FILE_OPEN_CREATE_EXCLUSIVE;
    case CreationMode::CREATE:
        return file_create_mode::FILE_OPEN_CREATE;
    case CreationMode::NO_CREATE:
        return file_create_mode::FILE_OPEN_NO_CREATE;
    }
}

static Status get_fs(const FileProperties& properties,
                     storage_aidl_filesystem* out) {
    switch (properties.integrity) {
    case FileIntegrity::TAMPER_PROOF_AT_REST: {
        // TP is persistent and available before userdata
        *out = STORAGE_AIDL_TP;
        break;
    }
    case FileIntegrity::TAMPER_DETECT:
    case FileIntegrity::TAMPER_DETECT_IGNORE_RESET: {
        switch (properties.availability) {
        case FileAvailability::BEFORE_USERDATA: {
            if (properties.persistent) {
                return Status::fromExceptionCode(
                        Status::EX_UNSUPPORTED_OPERATION,
                        "Unsupported FileProperties: TDEA does not guarantee persistence");
            }
            *out = STORAGE_AIDL_TDEA;
            break;
        }
        case FileAvailability::AFTER_USERDATA: {
            *out = properties.persistent ? STORAGE_AIDL_TDP : STORAGE_AIDL_TD;
            break;
        }
        default:
            return Status::fromExceptionCode(
                    Status::EX_UNSUPPORTED_OPERATION,
                    "Unsupported FileProperties: Unknown FileAvailability value");
        }
        break;
    }
    default:
        return Status::fromExceptionCode(
                Status::EX_UNSUPPORTED_OPERATION,
                "Unsupported FileProperties: Unknown FileIntegrity value");
    }
    return Status::ok();
}

class StorageClientSession {
public:
    StorageClientSession(struct fs* fs,
                         storage_aidl_filesystem fs_type,
                         const uuid_t* peer)
            : inner_(), fs_type_(fs_type), active_(false) {
        storage_client_session_init(&inner_, fs, peer);
        active_ = true;
    }
    ~StorageClientSession() { Deactivate(); }

    storage_client_session* get() { return active_ ? &inner_ : nullptr; }
    storage_aidl_filesystem fs_type() { return fs_type_; }

    void Deactivate() {
        active_ = false;
        storage_client_session_destroy(&inner_);
    }

private:
    storage_client_session inner_;
    storage_aidl_filesystem fs_type_;
    bool active_;
};

class Dir : public BnDir {
public:
    Dir(std::weak_ptr<StorageClientSession> session, ReadIntegrity integrity)
            : session_(std::move(session)),
              integrity_(integrity),
              last_state_(storage_file_list_flag::STORAGE_FILE_LIST_START),
              last_name_() {}

    Status readNextFilenames(int32_t max_count,
                             std::vector<std::string>* out) final {
        constexpr size_t kMaxFilenames = STORAGE_MAX_BUFFER_SIZE / FS_PATH_MAX;

        if (max_count < 0) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "maxCount must not be negative.");
        }
        size_t max_names = (max_count == 0)
                                   ? kMaxFilenames
                                   : std::min(kMaxFilenames,
                                              static_cast<size_t>(max_count));

        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IDir cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        if (last_state_ == storage_file_list_flag::STORAGE_FILE_LIST_END) {
            return Status::ok();
        }

        ListCallbackData data = {
                .out = out,
                .curr_flags = last_state_,
        };

        storage_err result = storage_file_list(
                client_session, max_names, last_state_, last_name_.data(),
                last_name_.size(), op_flags(),
                [](void* callback_data, size_t max_path_len) { return true; },
                [](void* callback_data, enum storage_file_list_flag flags,
                   const char* path, size_t path_len) {
                    auto& data = *static_cast<ListCallbackData*>(callback_data);

                    data.curr_flags = flags;
                    if (flags ==
                        storage_file_list_flag::STORAGE_FILE_LIST_END) {
                        return;
                    }

                    data.out->emplace_back(path, path_len);

                    // TODO: Do we need to tell the caller whether the file is
                    // committed, added, removed?
                },
                &data);

        last_state_ = data.curr_flags;
        last_name_ = out->empty() ? "" : out->back();

        return status_from_storage_err(result);
    }

private:
    struct ListCallbackData {
        std::vector<std::string>* out;
        enum storage_file_list_flag curr_flags;
    };

    storage_op_flags op_flags() {
        return storage_op_flags{
                // TODO: support acking reset only
                .allow_repaired = integrity_ == ReadIntegrity::IGNORE_ROLLBACK,
                .complete_transaction = false,
                .update_checkpoint = false,
        };
    }

    std::weak_ptr<StorageClientSession> session_;
    ReadIntegrity integrity_;

    enum storage_file_list_flag last_state_;
    std::string last_name_;
};

class File : public BnFile {
public:
    File(std::weak_ptr<StorageClientSession> session,
         uint32_t file_handle,
         FileMode access_mode,
         ReadIntegrity integrity,
         bool allow_writes_during_ab_update)
            : session_(std::move(session)),
              file_handle_(file_handle),
              access_mode_(access_mode),
              integrity_(integrity),
              allow_writes_during_ab_update_(allow_writes_during_ab_update) {
        assert(!allow_writes_during_ab_update_);
    }

    ~File() {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return;
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return;
        }

        (void)storage_file_close(client_session, file_handle_, op_flags());
    }

    Status read(int64_t size, int64_t offset, std::vector<uint8_t>* out) final {
        if (access_mode_ != FileMode::READ_ONLY &&
            access_mode_ != FileMode::READ_WRITE) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "File not opened for reading.");
        }
        if (size < 0) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "Size must not be negative.");
        }
        if (size > std::numeric_limits<uint32_t>::max()) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "Size would overflow");
        }
        if (offset < 0) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "Offset must not be negative.");
        }
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        out->resize(
                std::min(size, static_cast<int64_t>(STORAGE_MAX_BUFFER_SIZE)));
        size_t out_len = out->size();

        storage_err result =
                storage_file_read(client_session, file_handle_, size, offset,
                                  op_flags(), out->data(), &out_len);

        out->resize(out_len);
        return status_from_storage_err(result);
    }

    Status write(int64_t offset,
                 const std::vector<uint8_t>& buffer,
                 int64_t* out) final {
        if (access_mode_ != FileMode::WRITE_ONLY &&
            access_mode_ != FileMode::READ_WRITE) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "File not opened for writing.");
        }
        if (offset < 0) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "Offset must not be negative.");
        }
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        storage_err result =
                storage_file_write(session->get(), file_handle_, offset,
                                   buffer.data(), buffer.size(), op_flags());
        if (result != storage_err::STORAGE_NO_ERROR) {
            return status_from_storage_err(result);
        }

        *out = buffer.size();
        return Status::ok();
    }

    Status getSize(int64_t* out) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        uint64_t size;
        storage_err result = storage_file_get_size(session->get(), file_handle_,
                                                   op_flags(), &size);
        if (result != storage_err::STORAGE_NO_ERROR) {
            return status_from_storage_err(result);
        }

        if (size > std::numeric_limits<int64_t>::max()) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_STATE,
                                             "Size would overflow");
        }
        *out = static_cast<int64_t>(size);
        return Status::ok();
    }

    Status setSize(int64_t new_size) final {
        if (access_mode_ != FileMode::WRITE_ONLY &&
            access_mode_ != FileMode::READ_WRITE) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "File not opened for writing.");
        }
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        storage_err result = storage_file_set_size(session->get(), file_handle_,
                                                   new_size, op_flags());
        return status_from_storage_err(result);
    }

    Status rename(const std::string& new_name, CreationMode dest_create_mode) {
        if (access_mode_ != FileMode::WRITE_ONLY &&
            access_mode_ != FileMode::READ_WRITE) {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT,
                                             "File not opened for writing.");
        }
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        storage_client_session* client_session = session->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        storage_err result = storage_file_move(
                session->get(), file_handle_, true, nullptr, 0, new_name.data(),
                new_name.size(), create_mode(dest_create_mode), op_flags());
        return status_from_storage_err(result);
    }

private:
    storage_op_flags op_flags() {
        return storage_op_flags{
                // TODO: support acking reset only
                .allow_repaired = integrity_ == ReadIntegrity::IGNORE_ROLLBACK,
                .complete_transaction = false,
                .update_checkpoint = false,
        };
    }

    std::weak_ptr<StorageClientSession> session_;
    uint32_t file_handle_;
    FileMode access_mode_;
    ReadIntegrity integrity_;
    bool allow_writes_during_ab_update_;
};

class StorageSession : public BnStorageSession {
public:
    StorageSession(std::shared_ptr<StorageClientSession> session)
            : session_(std::move(session)) {}

    Status commitChanges() final { return endTransactions(true); }
    Status abandonChanges() final { return endTransactions(false); }

    Status openFile(const std::string& file_name,
                    const OpenOptions& options,
                    sp<IFile>* out) final {
        if (options.allowWritesDuringAbUpdate) {
            return Status::fromExceptionCode(
                    Status::EX_UNSUPPORTED_OPERATION,
                    "Unsupported option: allowWritesDuringAbUpdate");
        }
        storage_client_session* client_session = session_->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        uint32_t file_handle;
        storage_err err = storage_file_open(
                client_session, file_name.data(), file_name.size(),
                create_mode(options.createMode), options.truncateOnOpen,
                storage_op_flags{
                        // TODO: support acking reset only
                        .allow_repaired = options.readIntegrity ==
                                          ReadIntegrity::IGNORE_ROLLBACK,
                        .complete_transaction = false,
                        .update_checkpoint = false,
                },
                &file_handle);
        if (err != storage_err::STORAGE_NO_ERROR) {
            return status_from_storage_err(err);
        }

        *out = sp<File>::make(session_, file_handle, options.accessMode,
                              options.readIntegrity,
                              options.allowWritesDuringAbUpdate);
        return Status::ok();
    }

    Status deleteFile(const std::string& file_name,
                      const DeleteOptions& options) final {
        if (options.allowWritesDuringAbUpdate) {
            return Status::fromExceptionCode(
                    Status::EX_UNSUPPORTED_OPERATION,
                    "Unsupported option: allowWritesDuringAbUpdate");
        }
        storage_client_session* client_session = session_->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        storage_err err = storage_file_delete(
                client_session, file_name.data(), file_name.size(),
                storage_op_flags{
                        // TODO: support acking reset only
                        .allow_repaired = options.readIntegrity ==
                                          ReadIntegrity::IGNORE_ROLLBACK,
                        .complete_transaction = false,
                        .update_checkpoint = false,
                });
        return status_from_storage_err(err);
    }

    Status renameFile(const std::string& file_name,
                      const std::string& new_name,
                      const RenameOptions& options) final {
        if (options.allowWritesDuringAbUpdate) {
            return Status::fromExceptionCode(
                    Status::EX_UNSUPPORTED_OPERATION,
                    "Unsupported option: allowWritesDuringAbUpdate");
        }
        storage_client_session* client_session = session_->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        storage_err err = storage_file_move(
                client_session, 0, false, file_name.data(), file_name.size(),
                new_name.data(), new_name.size(),
                create_mode(options.destCreateMode),
                storage_op_flags{
                        // TODO: support acking reset only
                        .allow_repaired = options.readIntegrity ==
                                          ReadIntegrity::IGNORE_ROLLBACK,
                        .complete_transaction = false,
                        .update_checkpoint = false,
                });
        return status_from_storage_err(err);
    }

    Status openDir(const std::string& file_name,
                   ReadIntegrity integrity,
                   sp<IDir>* out) final {
        if (!file_name.empty()) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_ARGUMENT,
                    "Service currently only supports opening the root dir.");
        }
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        // TODO: Catch tampering?
        *out = sp<Dir>::make(session_, integrity);
        return Status::ok();
    }

private:
    Status endTransactions(bool commit_changes) {
        storage_op_flags flags = {
                .allow_repaired = false,
                .complete_transaction = commit_changes,
                // TODO: Allow updating checkpoint
                .update_checkpoint = false,
        };

        storage_client_session* client_session = session_->get();
        if (client_session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        storage_err result = storage_transaction_end(client_session, flags);
        return status_from_storage_err(result);
    }

    std::shared_ptr<StorageClientSession> session_;
};

class StorageService {
public:
    Status MakeSession(const FileProperties& file_properties,
                       const uuid_t* peer,
                       std::shared_ptr<StorageClientSession>* out) {
        storage_aidl_filesystem fs_type;
        Status result = get_fs(file_properties, &fs_type);
        if (!result.isOk()) {
            return result;
        }

        struct fs* fs = filesystems_[fs_type];
        if (fs == nullptr) {
            return Status::fromStatusT(android::WOULD_BLOCK);
        }

        std::erase_if(sessions_,
                      [](const std::weak_ptr<StorageClientSession>& session) {
                          return session.expired();
                      });

        *out = std::make_shared<StorageClientSession>(fs, fs_type, peer);
        sessions_.emplace_back(*out);
        return Status::ok();
    }

    void DeactivateFilesystem(storage_aidl_filesystem fs_type) {
        if (filesystems_[fs_type] == nullptr) {
            SS_ERR("Deactivating fs that's already inactive: %d", fs_type);
            return;
        }

        filesystems_[fs_type] = nullptr;

        for (auto it = sessions_.begin(); it != sessions_.end();) {
            auto session = it->lock();
            if (session == nullptr) {
                it = sessions_.erase(it);
                continue;
            }

            if (session->fs_type() == fs_type) {
                session->Deactivate();
            }
            ++it;
        }
    }

    void ActivateFilesystem(struct fs* fs, storage_aidl_filesystem fs_type) {
        if (filesystems_[fs_type] != nullptr) {
            SS_ERR("Reactivating fs that's already active: %d", fs_type);
            DeactivateFilesystem(fs_type);
        }

        filesystems_[fs_type] = fs;

        std::erase_if(sessions_,
                      [](const std::weak_ptr<StorageClientSession>& session) {
                          return session.expired();
                      });
    }

private:
    std::array<struct fs*, STORAGE_AIDL_FILESYSTEMS_COUNT> filesystems_;
    std::vector<std::weak_ptr<StorageClientSession>> sessions_;
};

class SecureStorage : public BnSecureStorage {
public:
    SecureStorage(StorageService* service, uuid_t peer)
            : service_(service), peer_(peer) {}

    Status startSession(const FileProperties& file_properties,
                        sp<IStorageSession>* out) final {
        std::shared_ptr<StorageClientSession> session;
        Status result =
                service_->MakeSession(file_properties, &peer_, &session);
        if (!result.isOk()) {
            return result;
        }

        *out = sp<StorageSession>::make(std::move(session));
        return Status::ok();
    }

private:
    StorageService* service_;
    uuid_t peer_;
};

}  // namespace
}  // namespace storage_service

struct storage_service_aidl_context_inner {
    sp<RpcServerTrusty> aidl_srv;
    storage_service::StorageService service;
};

int storage_aidl_create_service(struct storage_service_aidl_context* ctx,
                                struct tipc_hset* hset) {
    auto result = std::make_unique<storage_service_aidl_context_inner>();
    auto& service = result->service;

    auto port_acl =
            RpcServerTrusty::PortAcl{.flags = storage_service::kAclFlags};
    auto aidl_srv = RpcServerTrusty::make(
            hset, STORAGE_ISECURE_STORAGE_PORT,
            std::make_shared<const RpcServerTrusty::PortAcl>(port_acl),
            storage_service::kMaxBufferSize);
    if (aidl_srv == nullptr) {
        return EXIT_FAILURE;
    }

    aidl_srv->setPerSessionRootObject([&service](wp<RpcSession> session,
                                                 const void* peer,
                                                 size_t peer_size)
                                              -> sp<storage_service::
                                                            SecureStorage> {
        if (peer_size != sizeof(uuid_t)) {
            SS_ERR("Creating binder root object, but peer id had unexpected size %zu (expected %zu)",
                   peer_size, sizeof(uuid_t));
            return nullptr;
        }
        uuid_t peer_uuid = *static_cast<const uuid_t*>(peer);

        return sp<storage_service::SecureStorage>::make(&service,
                                                        std::move(peer_uuid));
    });
    result->aidl_srv = std::move(aidl_srv);

    // Caller now owns underlying storage_service_aidl_context
    ctx->inner = result.release();
    return EXIT_SUCCESS;
}

void storage_aidl_delete_service(struct storage_service_aidl_context* ctx) {
    delete ctx->inner;
    ctx->inner = nullptr;
}

void storage_aidl_enable_filesystem(struct storage_service_aidl_context* ctx,
                                    struct fs* fs,
                                    enum storage_aidl_filesystem fs_type) {
    ctx->inner->service.ActivateFilesystem(fs, fs_type);
}

void storage_aidl_disable_filesystem(struct storage_service_aidl_context* ctx,
                                     enum storage_aidl_filesystem fs_type) {
    ctx->inner->service.DeactivateFilesystem(fs_type);
}
