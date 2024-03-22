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

class Dir : public BnDir {
public:
    Status readNextFilenames(int32_t max_count,
                             std::vector<std::string>* out) final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
};

class File : public BnFile {
public:
    Status read(int64_t size, int64_t offset, std::vector<uint8_t>* out) final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
    Status write(int64_t offset,
                 const std::vector<uint8_t>& buffer,
                 int64_t* out) final {
        *out = 0;
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
    Status getSize(int64_t* out) final {
        *out = 0;
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
    Status setSize(int64_t new_size) final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status rename(const std::string& new_name, CreationMode dest_create_mode) {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
};

class StorageSession : public BnStorageSession {
public:
    Status commitChanges() final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
    Status abandonChanges() final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status openFile(const std::string& file_name,
                    const OpenOptions& options,
                    sp<IFile>* out) final {
        *out = sp<File>::make();
        return Status::ok();
    }
    Status deleteFile(const std::string& file_name,
                      const DeleteOptions& options) final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }
    Status renameFile(const std::string& file_name,
                      const std::string& new_name,
                      const RenameOptions& options) final {
        return Status::fromExceptionCode(Status::EX_UNSUPPORTED_OPERATION);
    }

    Status openDir(const std::string& file_name,
                   ReadIntegrity integrity,
                   sp<IDir>* out) final {
        *out = sp<Dir>::make();
        return Status::ok();
    }
};

class SecureStorage : public BnSecureStorage {
public:
    Status startSession(const FileProperties& file_properties,
                        sp<IStorageSession>* out) final {
        *out = sp<StorageSession>::make();
        return Status::ok();
    }
};

}  // namespace
}  // namespace storage_service

struct storage_service_aidl_context_inner {
    sp<RpcServerTrusty> aidl_srv;
};

int storage_aidl_create_service(struct storage_service_aidl_context* ctx,
                                struct tipc_hset* hset) {
    auto result = std::make_unique<storage_service_aidl_context_inner>();

    auto port_acl =
            RpcServerTrusty::PortAcl{.flags = storage_service::kAclFlags};
    auto aidl_srv = RpcServerTrusty::make(
            hset, STORAGE_ISECURE_STORAGE_PORT,
            std::make_shared<const RpcServerTrusty::PortAcl>(port_acl),
            storage_service::kMaxBufferSize);
    if (aidl_srv == nullptr) {
        return EXIT_FAILURE;
    }

    aidl_srv->setPerSessionRootObject([](wp<RpcSession> session,
                                         const void* peer, size_t peer_size)
                                              -> sp<storage_service::
                                                            SecureStorage> {
        if (peer_size != sizeof(uuid_t)) {
            SS_ERR("Creating binder root object, but peer id had unexpected size %zu (expected %zu)",
                   peer_size, sizeof(uuid_t));
            return nullptr;
        }

        return sp<storage_service::SecureStorage>::make();
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
                                    enum storage_aidl_filesystem fs_type) {}

void storage_aidl_disable_filesystem(struct storage_service_aidl_context* ctx,
                                     enum storage_aidl_filesystem fs_type) {}
