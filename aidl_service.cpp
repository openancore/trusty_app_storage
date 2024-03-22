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

#include <cstdlib>
#include <memory>
#include <vector>

#include <trusty_ipc.h>

#include <interface/storage/storage_aidl/ports.h>

#include <binder/RpcServerTrusty.h>
#include <binder/Status.h>

#include <android/hardware/security/see/storage/BnDir.h>
#include <android/hardware/security/see/storage/BnFile.h>
#include <android/hardware/security/see/storage/BnSecureStorage.h>
#include <android/hardware/security/see/storage/BnStorageSession.h>
#include <android/hardware/security/see/storage/CreationMode.h>
#include <android/hardware/security/see/storage/DeleteOptions.h>
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
    Dir(std::weak_ptr<StorageClientSession> session)
            : session_(std::move(session)) {}

    Status readNextFilenames(int32_t max_count,
                             std::vector<std::string>* out) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IDir cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

private:
    std::weak_ptr<StorageClientSession> session_;
};

class File : public BnFile {
public:
    File(std::weak_ptr<StorageClientSession> session)
            : session_(std::move(session)) {}

    Status read(int64_t size, int64_t offset, std::vector<uint8_t>* out) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status write(int64_t offset,
                 const std::vector<uint8_t>& buffer,
                 int64_t* out) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        *out = 0;
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status getSize(int64_t* out) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        *out = 0;
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status setSize(int64_t new_size) final {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status rename(const std::string& new_name, CreationMode dest_create_mode) {
        std::shared_ptr<StorageClientSession> session = session_.lock();
        if (session == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "IFile cannot be used after its parent session has been destroyed.");
        }
        if (session->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

private:
    std::weak_ptr<StorageClientSession> session_;
};

class StorageSession : public BnStorageSession {
public:
    StorageSession(std::shared_ptr<StorageClientSession> session)
            : session_(std::move(session)) {}

    Status commitChanges() final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status abandonChanges() final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status openFile(const std::string& file_name,
                    const OpenOptions& options,
                    sp<IFile>* out) final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        *out = sp<File>::make(session_);
        return Status::ok();
    }
    Status deleteFile(const std::string& file_name,
                      const DeleteOptions& options) final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status renameFile(const std::string& file_name,
                      const std::string& new_name,
                      const RenameOptions& options) final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status openDir(const std::string& file_name,
                   ReadIntegrity integrity,
                   sp<IDir>* out) final {
        if (session_->get() == nullptr) {
            return Status::fromExceptionCode(
                    Status::EX_ILLEGAL_STATE,
                    "Connection to underlying filesystem lost. Start a new session.");
        }

        *out = sp<Dir>::make(session_);
        return Status::ok();
    }

private:
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
