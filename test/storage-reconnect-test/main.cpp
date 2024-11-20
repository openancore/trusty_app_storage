#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include <lib/storage/storage.h>
#include <lib/tipc/tipc.h>
#include <lib/unittest/unittest.h>
#include <trusty/time.h>
#include <trusty_unittest.h>

#include <binder/IBinder.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcTransportTipcTrusty.h>

#include <android/hardware/security/see/storage/Availability.h>
#include <android/hardware/security/see/storage/CreationMode.h>
#include <android/hardware/security/see/storage/FileMode.h>
#include <android/hardware/security/see/storage/Filesystem.h>
#include <android/hardware/security/see/storage/IFile.h>
#include <android/hardware/security/see/storage/ISecureStorage.h>
#include <android/hardware/security/see/storage/IStorageSession.h>
#include <android/hardware/security/see/storage/Integrity.h>
#include <android/hardware/security/see/storage/OpenOptions.h>

// Needs to be included after AIDL files; definition of ERR_NOT_FOUND macro
// breaks the AIDL definitions.
#include <uapi/err.h>
static const int err_not_found = ERR_NOT_FOUND;
#undef ERR_NOT_FOUND

using ::android::IBinder;
using ::android::RpcSession;
using ::android::RpcTransportCtxFactoryTipcTrusty;
using ::android::sp;
using ::android::status_t;
using ::android::binder::Status;
using ::android::binder::unique_fd;
using ::android::hardware::security::see::storage::Availability;
using ::android::hardware::security::see::storage::CreationMode;
using ::android::hardware::security::see::storage::FileMode;
using ::android::hardware::security::see::storage::Filesystem;
using ::android::hardware::security::see::storage::IFile;
using ::android::hardware::security::see::storage::Integrity;
using ::android::hardware::security::see::storage::ISecureStorage;
using ::android::hardware::security::see::storage::IStorageSession;
using ::android::hardware::security::see::storage::OpenOptions;

enum class FsType {
    TP,
    TDEA,
    TD,
    TDP,
    NSP,
};

struct FsConnection {
    storage_session_t tipc_session = STORAGE_INVALID_SESSION;
    sp<IStorageSession> aidl_session = nullptr;
};

static const char aidl_port[] = "com.android.hardware.security.see.storage";
static sp<ISecureStorage> aidl_storage = nullptr;
static std::array<FsConnection, 5> connections;

static FsType storage_test_client_fs;

static const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7};

static const char tipc_commit_file[] = "test_reconnect_committed_tipc";
static const char tipc_nocommit_file[] = "test_reconnect_uncommitted_tipc";
static const char aidl_commit_file[] = "test_reconnect_committed_aidl";
static const char aidl_nocommit_file[] = "test_reconnect_uncommitted_aidl";

#define TLOG_TAG "ss-reconnecttest"

static const char* client_port(FsType fs_type) {
    switch (fs_type) {
    case FsType::TP:
        return STORAGE_CLIENT_TP_PORT;
    case FsType::TDEA:
        return STORAGE_CLIENT_TDEA_PORT;
    case FsType::TD:
        return STORAGE_CLIENT_TD_PORT;
    case FsType::TDP:
        return STORAGE_CLIENT_TDP_PORT;
    case FsType::NSP:
        return STORAGE_CLIENT_NSP_PORT;
    }
}

static bool client_fs(FsType fs_type, Filesystem* out) {
    switch (fs_type) {
    case FsType::TP:
        *out = Filesystem();
        out->integrity = Integrity::TAMPER_PROOF_AT_REST;
        out->availability = Availability::AFTER_USERDATA;
        out->persistent = false;
        return true;
    case FsType::TDEA:
        *out = Filesystem();
        out->integrity = Integrity::TAMPER_DETECT;
        out->availability = Availability::BEFORE_USERDATA;
        out->persistent = false;
        return true;
    case FsType::TD:
        *out = Filesystem();
        out->integrity = Integrity::TAMPER_DETECT;
        out->availability = Availability::AFTER_USERDATA;
        out->persistent = false;
        return true;
    case FsType::TDP:
        *out = Filesystem();
        out->integrity = Integrity::TAMPER_DETECT;
        out->availability = Availability::AFTER_USERDATA;
        out->persistent = true;
        return true;
    case FsType::NSP:
        // AIDL service never accesses NSP currently
        return false;
    }
}

TEST(StorageReconnectBeforeTest, TipcWrite) {
    int rc;
    file_handle_t handle;
    storage_session_t& session =
            connections[static_cast<size_t>(storage_test_client_fs)]
                    .tipc_session;

    if (session != STORAGE_INVALID_SESSION) {
        storage_close_session(session);
        session = STORAGE_INVALID_SESSION;
    }

    rc = storage_open_session(&session, client_port(storage_test_client_fs));
    ASSERT_EQ(0, rc);

    // Ensure files doesn't exist.
    rc = storage_delete_file(session, tipc_commit_file, STORAGE_OP_COMPLETE);
    rc = (rc == err_not_found) ? 0 : rc;
    ASSERT_EQ(0, rc);
    rc = storage_delete_file(session, tipc_nocommit_file, STORAGE_OP_COMPLETE);
    rc = (rc == err_not_found) ? 0 : rc;
    ASSERT_EQ(0, rc);

    // Write to file.
    rc = storage_open_file(
            session, &handle, tipc_commit_file,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE, 0);
    ASSERT_EQ(0, rc);

    rc = storage_write(handle, 0, &data, sizeof(data), STORAGE_OP_COMPLETE);
    EXPECT_EQ(sizeof(data), rc);
    storage_close_file(handle);

    // Write to file, but don't commit.
    rc = storage_open_file(
            session, &handle, tipc_nocommit_file,
            STORAGE_FILE_OPEN_CREATE | STORAGE_FILE_OPEN_CREATE_EXCLUSIVE, 0);
    ASSERT_EQ(0, rc);

    rc = storage_write(handle, 0, &data, sizeof(data), 0);
    EXPECT_EQ(sizeof(data), rc);
    storage_close_file(handle);

test_abort:;
}

TEST(StorageReconnectDuringTest, TipcCheckSessionInvalid) {
    int rc;
    storage_session_t& session =
            connections[static_cast<size_t>(storage_test_client_fs)]
                    .tipc_session;

    // StorageReconnectBeforeTest should have already run
    ASSERT_NE(STORAGE_INVALID_SESSION, session);

    // Can't commit; storageproxyd disconnected
    rc = storage_end_transaction(session, true);
    EXPECT_EQ(ERR_CHANNEL_CLOSED, rc);

test_abort:;
}

TEST(StorageReconnectAfterTest, TipcCheckWritten) {
    int rc;
    file_handle_t handle;
    storage_session_t& session =
            connections[static_cast<size_t>(storage_test_client_fs)]
                    .tipc_session;

    // StorageReconnectBeforeTest should have already run
    ASSERT_NE(STORAGE_INVALID_SESSION, session);

    // Wait so that storage has time to reconnect to storageproxyd
    storage_session_t temp_session;
    rc = storage_open_session(&temp_session,
                              client_port(storage_test_client_fs));

    // Attempt to commit write from StorageReconnectBeforeTest
    rc = storage_end_transaction(session, true);
    // Fails because storageproxy rebooted and this session was abandoned
    EXPECT_EQ(ERR_CHANNEL_CLOSED, rc);

    session = temp_session;

    // Read written file and check contents match data
    static uint8_t buf[sizeof(data)];
    rc = storage_open_file(session, &handle, tipc_commit_file, 0, 0);
    ASSERT_EQ(0, rc);
    rc = storage_read(handle, 0, &buf, sizeof(buf));
    ASSERT_EQ(sizeof(data), rc);
    for (size_t i = 0; i < sizeof(data); ++i) {
        EXPECT_EQ(data[i], buf[i]);
    }

    // File doesn't exist because creation never committed
    rc = storage_delete_file(session, tipc_nocommit_file, STORAGE_OP_COMPLETE);
    EXPECT_EQ(err_not_found, rc);

    storage_close_session(session);
    session = STORAGE_INVALID_SESSION;
test_abort:;
}

static OpenOptions create_exclusive() {
    OpenOptions result;
    result.createMode = CreationMode::CREATE_EXCLUSIVE;
    result.accessMode = FileMode::READ_WRITE;
    result.truncateOnOpen = true;
    return result;
}
static OpenOptions no_create() {
    OpenOptions result;
    result.createMode = CreationMode::NO_CREATE;
    result.accessMode = FileMode::READ_WRITE;
    result.truncateOnOpen = false;
    return result;
}

TEST(StorageReconnectBeforeTest, AidlWrite) {
    auto vec_data = std::vector<uint8_t>(data, data + sizeof(data));
    sp<IFile> file;
    int64_t written;
    Status ret;

    Filesystem client;
    bool enable_test = client_fs(storage_test_client_fs, &client);
    if (!enable_test) {
        goto test_abort;
    }
    ASSERT_NE(nullptr, aidl_storage.get());

    {
        sp<IStorageSession>& aidl_session =
                connections[static_cast<size_t>(storage_test_client_fs)]
                        .aidl_session;

        if (aidl_session != nullptr) {
            aidl_session = nullptr;
        }

        ret = aidl_storage->startSession(client, &aidl_session);
        ASSERT_EQ(true, ret.isOk());

        // Ensure both files deleted
        ret = aidl_session->deleteFile(aidl_commit_file);
        ASSERT_EQ(true,
                  ret.isOk() ||
                          ret.exceptionCode() == Status::EX_SERVICE_SPECIFIC &&
                                  ret.serviceSpecificErrorCode() ==
                                          ISecureStorage::ERR_NOT_FOUND);
        ret = aidl_session->deleteFile(aidl_nocommit_file);
        ASSERT_EQ(true,
                  ret.isOk() ||
                          ret.exceptionCode() == Status::EX_SERVICE_SPECIFIC &&
                                  ret.serviceSpecificErrorCode() ==
                                          ISecureStorage::ERR_NOT_FOUND);

        // Write and commit
        ret = aidl_session->openFile(aidl_commit_file, create_exclusive(),
                                     &file);
        ASSERT_EQ(true, ret.isOk());
        ret = file->write(0, vec_data, &written);
        ASSERT_EQ(true, ret.isOk());
        ASSERT_EQ(vec_data.size(), written);
        ret = aidl_session->commitChanges();
        ASSERT_EQ(true, ret.isOk());

        // Write but leave uncommitted
        ret = aidl_session->openFile(aidl_nocommit_file, create_exclusive(),
                                     &file);
        ASSERT_EQ(true, ret.isOk());
        ret = file->write(0, vec_data, &written);
        ASSERT_EQ(true, ret.isOk());
        ASSERT_EQ(vec_data.size(), written);
    }
test_abort:;
}

TEST(StorageReconnectDuringTest, AidlCheckSessionInvalid) {
    Status ret;
    Filesystem client;
    bool enable_test = client_fs(storage_test_client_fs, &client);
    if (!enable_test) {
        goto test_abort;
    }
    ASSERT_NE(nullptr, aidl_storage.get());

    {
        sp<IStorageSession>& aidl_session =
                connections[static_cast<size_t>(storage_test_client_fs)]
                        .aidl_session;
        ASSERT_NE(nullptr, aidl_session.get());

        // Session invalid now
        ret = aidl_session->commitChanges();
        ASSERT_EQ(Status::EX_TRANSACTION_FAILED, ret.exceptionCode());
        ASSERT_EQ(android::WOULD_BLOCK, ret.transactionError());

        // Creating a new session on the same filesystem would block
        sp<IStorageSession> temp_storage;
        ret = aidl_storage->startSession(client, &temp_storage);
        ASSERT_EQ(Status::EX_TRANSACTION_FAILED, ret.exceptionCode());
        ASSERT_EQ(android::WOULD_BLOCK, ret.transactionError());
    }
test_abort:;
}

TEST(StorageReconnectAfterTest, AidlCheckWritten) {
    sp<IFile> file;
    Status ret;
    Filesystem client;
    std::vector<uint8_t> read_buf;
    bool enable_test = client_fs(storage_test_client_fs, &client);
    if (!enable_test) {
        goto test_abort;
    }
    ASSERT_NE(nullptr, aidl_storage.get());

    read_buf.reserve(sizeof(data));

    {
        // Session is reconnected; commit the uncommitted changes
        sp<IStorageSession>& aidl_session =
                connections[static_cast<size_t>(storage_test_client_fs)]
                        .aidl_session;
        ASSERT_NE(nullptr, aidl_session.get());
        ret = aidl_session->commitChanges();
        ASSERT_EQ(true, ret.isOk());

        // Read what was committed in AidlWrite
        ret = aidl_session->openFile(aidl_commit_file, no_create(), &file);
        ASSERT_EQ(true, ret.isOk());
        ret = file->read(sizeof(data), 0, &read_buf);
        ASSERT_EQ(true, ret.isOk());
        ASSERT_EQ(sizeof(data), read_buf.size());
        for (size_t i = 0; i < sizeof(data); ++i) {
            EXPECT_EQ(data[i], read_buf[i]);
        }

        // Read what was just committed
        read_buf.clear();
        ret = aidl_session->openFile(aidl_nocommit_file, no_create(), &file);
        ASSERT_EQ(true, ret.isOk());
        ret = file->read(sizeof(data), 0, &read_buf);
        ASSERT_EQ(true, ret.isOk());
        ASSERT_EQ(sizeof(data), read_buf.size());
        for (size_t i = 0; i < sizeof(data); ++i) {
            EXPECT_EQ(data[i], read_buf[i]);
        }
    }
test_abort:;
}

struct storage_unittest {
    struct unittest unittest;
    FsType client;
    const char* run_mode;
};

static bool run_test(struct unittest* test) {
    struct storage_unittest* storage_test =
            containerof(test, struct storage_unittest, unittest);
    storage_test_client_fs = storage_test->client;
    return RUN_ALL_SUITE_TESTS(storage_test->run_mode);
}

#define PORT_BASE "com.android.storage-reconnect-test."

#define DEFINE_STORAGE_UNIT_TEST(fs, fs_name, run_mode_val, run_mode_name) \
    {                                                                      \
        .unittest =                                                        \
                {                                                          \
                        .port_name = PORT_BASE fs_name run_mode_name,      \
                        .run_test = run_test,                              \
                },                                                         \
        .client = (fs), .run_mode = (run_mode_val),                        \
    }

#define DEFINE_STORAGE_UNIT_TESTS_FS(fs, fs_name)                              \
    DEFINE_STORAGE_UNIT_TEST((fs), fs_name, "StorageReconnectBeforeTest",      \
                             ".before"),                                       \
            DEFINE_STORAGE_UNIT_TEST((fs), fs_name,                            \
                                     "StorageReconnectDuringTest", ".during"), \
            DEFINE_STORAGE_UNIT_TEST((fs), fs_name,                            \
                                     "StorageReconnectAfterTest", ".after")

int main(void) {
    static struct storage_unittest storage_unittests[] = {
            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::NSP, "nsp"),
            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TD, "td"),
            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TDP, "tdp"),
            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TDEA, "tdea"),
            DEFINE_STORAGE_UNIT_TESTS_FS(FsType::TP, "tp"),
    };
    static struct unittest* unittests[countof(storage_unittests)];

    for (size_t i = 0; i < countof(storage_unittests); i++) {
        unittests[i] = &storage_unittests[i].unittest;
    }

    int rc = connect(aidl_port, IPC_CONNECT_WAIT_FOR_PORT);
    if (rc < 0) {
        TLOGE("Couldn't connect to IStorageService port (%s)\n", aidl_port);
        return rc;
    }
    sp<android::RpcSession> sess =
            RpcSession::make(RpcTransportCtxFactoryTipcTrusty::make());
    if (sess == nullptr) {
        TLOGE("Failed to make RPC session.\n");
        return ERR_GENERIC;
    }
    unique_fd chan_fd;
    chan_fd.reset(rc);
    status_t status = sess->setupPreconnectedClient(
            std::move(chan_fd), []() { return unique_fd(); });
    if (status != android::OK) {
        TLOGE("Error (%d) during setupPreconnectedClient\n", status);
        return ERR_GENERIC;
    }
    sp<IBinder> root = sess->getRootObject();
    if (root == nullptr) {
        TLOGE("Couldn't get root object.\n");
        return ERR_GENERIC;
    }

    aidl_storage = ISecureStorage::asInterface(root);
    return unittest_main(unittests, countof(unittests));
}