/*
 * Copyright (C) 2013-2016 The Android Open Source Project
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

#include "client_tipc.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <interface/storage/storage.h>
#include <lib/tipc/tipc.h>
#include <openssl/mem.h>
#include <uapi/err.h>

#include "client.h"
#include "client_session.h"
#include "client_session_tipc.h"
#include "ipc.h"
#include "storage_limits.h"
#include "tipc_service.h"

/* macros to help manage debug output */
#define SS_ERR(args...) fprintf(stderr, "ss: " args)
#define SS_DBG_IO(args...) \
    do {                   \
    } while (0)

#if 0
/* this can generate alot of spew on debug builds */
#define SS_INFO(args...) fprintf(stderr, "ss: " args)
#else
#define SS_INFO(args...) \
    do {                 \
    } while (0)
#endif

static int client_handle_msg(struct ipc_channel_context* ctx,
                             void* msg,
                             size_t msg_size);
static void client_disconnect(struct ipc_channel_context* context);
static int send_response(struct storage_tipc_client_session* tipc_session,
                         enum storage_err result,
                         struct storage_msg* msg,
                         void* out,
                         size_t out_size);
static int send_result(struct storage_tipc_client_session* tipc_session,
                       struct storage_msg* msg,
                       enum storage_err result);

static struct storage_op_flags extract_storage_op_flags(uint32_t msg_flags) {
    return (struct storage_op_flags){
            .allow_repaired = msg_flags & STORAGE_MSG_FLAG_FS_REPAIRED_ACK,
            .complete_transaction =
                    msg_flags & STORAGE_MSG_FLAG_TRANSACT_COMPLETE,
            .update_checkpoint =
                    msg_flags & STORAGE_MSG_FLAG_TRANSACT_CHECKPOINT,
    };
}

static enum storage_err storage_tipc_file_delete(
        struct storage_client_session* session,
        struct storage_msg* msg,
        struct storage_file_delete_req* req,
        size_t req_size) {
    if (req_size < sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return STORAGE_ERR_NOT_VALID;
    }

    if ((req->flags & ~STORAGE_FILE_DELETE_MASK) != 0) {
        SS_ERR("%s: unexpected flags (0x%" PRIx32 ")\n", __func__, req->flags);
        return STORAGE_ERR_NOT_VALID;
    }

    return storage_file_delete(session, req->name, req_size - sizeof(*req),
                               extract_storage_op_flags(msg->flags));
}

static enum storage_err storage_tipc_file_move(
        struct storage_client_session* session,
        struct storage_msg* msg,
        struct storage_file_move_req* req,
        size_t req_size) {
    if (req_size < sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return STORAGE_ERR_NOT_VALID;
    }

    if ((req->flags & ~STORAGE_FILE_MOVE_MASK) != 0) {
        SS_ERR("invalid move flags 0x%" PRIx32 "\n", req->flags);
        return STORAGE_ERR_NOT_VALID;
    }

    size_t names_combined_len = req_size - sizeof(*req);
    size_t src_len = req->old_name_len;
    if (src_len >= names_combined_len) {
        SS_ERR("%s: invalid src filename length %zu >= %zu\n", __func__,
               src_len, names_combined_len);
        return STORAGE_ERR_NOT_VALID;
    }

    enum file_create_mode file_create_mode;
    if (req->flags & STORAGE_FILE_MOVE_CREATE) {
        file_create_mode = req->flags & STORAGE_FILE_MOVE_CREATE_EXCLUSIVE
                                   ? FILE_OPEN_CREATE_EXCLUSIVE
                                   : FILE_OPEN_CREATE;
    } else {
        file_create_mode = FILE_OPEN_NO_CREATE;
    }

    return storage_file_move(
            session, req->handle, req->flags & STORAGE_FILE_MOVE_OPEN_FILE,
            req->old_new_name, src_len, req->old_new_name + src_len,
            names_combined_len - src_len, file_create_mode,
            extract_storage_op_flags(msg->flags));
}

static enum storage_err storage_tipc_file_open(
        struct storage_tipc_client_session* tipc_session,
        struct storage_msg* msg,
        struct storage_file_open_req* req,
        size_t req_size) {
    if (req_size < sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return send_result(tipc_session, msg, STORAGE_ERR_NOT_VALID);
    }

    if ((req->flags & ~STORAGE_FILE_OPEN_MASK) != 0) {
        SS_ERR("%s: invalid flags 0x%" PRIx32 "\n", __func__, req->flags);
        return send_result(tipc_session, msg, STORAGE_ERR_NOT_VALID);
    }

    enum file_create_mode file_create_mode;
    if (req->flags & STORAGE_FILE_OPEN_CREATE) {
        file_create_mode = req->flags & STORAGE_FILE_OPEN_CREATE_EXCLUSIVE
                                   ? FILE_OPEN_CREATE_EXCLUSIVE
                                   : FILE_OPEN_CREATE;
    } else {
        file_create_mode = FILE_OPEN_NO_CREATE;
    }

    struct storage_file_open_resp resp;
    enum storage_err result = storage_file_open(
            &tipc_session->session, req->name, req_size - sizeof(*req),
            file_create_mode, req->flags & STORAGE_FILE_OPEN_TRUNCATE,
            extract_storage_op_flags(msg->flags), &resp.handle);
    if (result != STORAGE_NO_ERROR) {
        return send_result(tipc_session, msg, result);
    }
    return send_response(tipc_session, result, msg, &resp, sizeof(resp));
}

static enum storage_err storage_tipc_file_close(
        struct storage_client_session* session,
        struct storage_msg* msg,
        struct storage_file_close_req* req,
        size_t req_size) {
    if (req_size != sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return STORAGE_ERR_NOT_VALID;
    }
    return storage_file_close(session, req->handle,
                              extract_storage_op_flags(msg->flags));
}

static enum storage_err storage_tipc_file_write(
        struct storage_client_session* session,
        struct storage_msg* msg,
        struct storage_file_write_req* req,
        size_t req_size) {
    if (req_size <= sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return STORAGE_ERR_NOT_VALID;
    }
    return storage_file_write(session, req->handle, req->offset, req->data,
                              req_size - sizeof(*req),
                              extract_storage_op_flags(msg->flags));
}

static enum storage_err storage_tipc_file_read(
        struct storage_tipc_client_session* tipc_session,
        struct storage_msg* msg,
        struct storage_file_read_req* req,
        size_t req_size) {
    if (req_size != sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return send_result(tipc_session, msg, STORAGE_ERR_NOT_VALID);
    }

    /*
     * After getting the args out of req, we still need `*msg`, but won't need
     * the rest of the buffer anymore. We can reuse that space to hold the
     * response.
     */
    uint8_t* resp = (uint8_t*)(msg + 1);
    size_t resp_len = STORAGE_MAX_BUFFER_SIZE - sizeof(*msg);

    enum storage_err result = storage_file_read(
            &tipc_session->session, req->handle, req->size, req->offset,
            extract_storage_op_flags(msg->flags), resp, &resp_len);
    if (result != STORAGE_NO_ERROR) {
        return send_result(tipc_session, msg, result);
    }
    return send_response(tipc_session, result, msg, resp, resp_len);
}

struct storage_tipc_file_iter_data {
    char resp_buf[1024];
    size_t buf_used;
};

static bool buf_has_space(void* self, size_t max_path_len) {
    struct storage_tipc_file_iter_data* this = self;
    /* One extra byte for flags plus one for the path's nul terminator */
    size_t max_resp_size = max_path_len + 2;
    return this->buf_used + max_resp_size <= sizeof(this->resp_buf);
}

static void write_to_buf(void* self,
                         enum storage_file_list_flag flags,
                         const char* path,
                         size_t path_len) {
    struct storage_tipc_file_iter_data* this = self;
    struct storage_file_list_resp* resp =
            (void*)(this->resp_buf + this->buf_used);

    resp->flags = flags;
    this->buf_used++;

    if (path) {
        strncpy(resp->name, path, path_len);
        resp->name[path_len] = '\0';
        this->buf_used += path_len + 1;
    }
}

static enum storage_err storage_tipc_file_list(
        struct storage_tipc_client_session* tipc_session,
        struct storage_msg* msg,
        struct storage_file_list_req* req,
        size_t req_size) {
    if (req_size < sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return send_result(tipc_session, msg, STORAGE_ERR_NOT_VALID);
    }

    struct storage_tipc_file_iter_data callback_data = {
            .buf_used = 0,
    };

    enum storage_err result = storage_file_list(
            &tipc_session->session, req->max_count,
            req->flags & STORAGE_FILE_LIST_STATE_MASK, req->name,
            req_size - sizeof(*req), extract_storage_op_flags(msg->flags),
            buf_has_space, write_to_buf, &callback_data);
    if (result != STORAGE_NO_ERROR) {
        return send_result(tipc_session, msg, result);
    }
    return send_response(tipc_session, result, msg, callback_data.resp_buf,
                         callback_data.buf_used);
}

static enum storage_err storage_tipc_file_get_size(
        struct storage_tipc_client_session* tipc_session,
        struct storage_msg* msg,
        struct storage_file_get_size_req* req,
        size_t req_size) {
    if (req_size != sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return send_result(tipc_session, msg, STORAGE_ERR_NOT_VALID);
    }

    struct storage_file_get_size_resp resp;
    enum storage_err result = storage_file_get_size(
            &tipc_session->session, req->handle,
            extract_storage_op_flags(msg->flags), &resp.size);
    if (result != STORAGE_NO_ERROR) {
        return send_result(tipc_session, msg, result);
    }
    return send_response(tipc_session, result, msg, &resp, sizeof(resp));
}

static enum storage_err storage_tipc_file_set_size(
        struct storage_client_session* session,
        struct storage_msg* msg,
        struct storage_file_set_size_req* req,
        size_t req_size) {
    if (req_size != sizeof(*req)) {
        SS_ERR("%s: invalid request size (%zu)\n", __func__, req_size);
        return STORAGE_ERR_NOT_VALID;
    }
    return storage_file_set_size(session, req->handle, req->size,
                                 extract_storage_op_flags(msg->flags));
}

static struct storage_tipc_client_session* chan_context_to_client_session(
        struct ipc_channel_context* ctx) {
    assert(ctx != NULL);
    struct storage_tipc_client_session* tipc_session;

    tipc_session =
            containerof(ctx, struct storage_tipc_client_session, chan_ctx);
    assert(tipc_session->session.magic == STORAGE_CLIENT_SESSION_MAGIC);
    return tipc_session;
}

static struct client_port_context* port_context_to_client_port_context(
        struct ipc_port_context* context) {
    assert(context != NULL);

    return containerof(context, struct client_port_context, client_ctx);
}

static void client_channel_ops_init(struct ipc_channel_ops* ops) {
    ops->on_handle_msg = client_handle_msg;
    ops->on_disconnect = client_disconnect;
}

static struct ipc_channel_context* client_connect(
        struct ipc_port_context* parent_ctx,
        const uuid_t* peer_uuid,
        handle_t chan_handle) {
    struct client_port_context* client_port_context;
    struct storage_tipc_client_session* client_tipc_session;

    client_port_context = port_context_to_client_port_context(parent_ctx);

    client_tipc_session = calloc(1, sizeof(*client_tipc_session));
    if (client_tipc_session == NULL) {
        SS_ERR("out of memory allocating client session\n");
        return NULL;
    }

    struct storage_client_session* client_session =
            &client_tipc_session->session;
    storage_client_session_init(client_session, client_port_context->tr_state,
                                peer_uuid);

    client_channel_ops_init(&client_tipc_session->chan_ctx.ops);
    return &client_tipc_session->chan_ctx;
}

static void client_disconnect(struct ipc_channel_context* context) {
    struct storage_tipc_client_session* tipc_session =
            chan_context_to_client_session(context);

    storage_client_session_destroy(&tipc_session->session);
    OPENSSL_cleanse(tipc_session, sizeof(struct storage_tipc_client_session));
    free(tipc_session);
}

static int send_response(struct storage_tipc_client_session* tipc_session,
                         enum storage_err result,
                         struct storage_msg* msg,
                         void* out,
                         size_t out_size) {
    size_t resp_buf_count = 1;
    if (result == STORAGE_NO_ERROR && out != NULL && out_size != 0) {
        ++resp_buf_count;
    }

    struct iovec resp_bufs[2];

    msg->cmd |= STORAGE_RESP_BIT;
    msg->flags = 0;
    msg->size = sizeof(struct storage_msg) + out_size;
    msg->result = result;

    resp_bufs[0].iov_base = msg;
    resp_bufs[0].iov_len = sizeof(struct storage_msg);

    if (resp_buf_count == 2) {
        resp_bufs[1].iov_base = out;
        resp_bufs[1].iov_len = out_size;
    }

    struct ipc_msg resp_ipc_msg = {
            .iov = resp_bufs,
            .num_iov = resp_buf_count,
    };

    return send_msg(tipc_session->chan_ctx.common.handle, &resp_ipc_msg);
}

static int send_result(struct storage_tipc_client_session* tipc_session,
                       struct storage_msg* msg,
                       enum storage_err result) {
    return send_response(tipc_session, result, msg, NULL, 0);
}

static int client_handle_msg(struct ipc_channel_context* ctx,
                             void* msg_buf,
                             size_t msg_size) {
    struct storage_tipc_client_session* tipc_session;
    struct storage_client_session* session;
    struct storage_msg* msg = msg_buf;
    size_t payload_len;
    enum storage_err result;
    void* payload;

    tipc_session = chan_context_to_client_session(ctx);
    session = &tipc_session->session;

    if (msg_size < sizeof(struct storage_msg)) {
        SS_ERR("%s: invalid message of size (%zu)\n", __func__, msg_size);
        struct storage_msg err_msg = {.cmd = STORAGE_RESP_MSG_ERR};
        send_result(tipc_session, &err_msg, STORAGE_ERR_NOT_VALID);
        return ERR_NOT_VALID; /* would force to close connection */
    }

    payload_len = msg_size - sizeof(struct storage_msg);
    payload = msg->payload;

    switch (msg->cmd) {
    case STORAGE_FILE_DELETE:
        result = storage_tipc_file_delete(session, msg, payload, payload_len);
        break;
    case STORAGE_FILE_MOVE:
        result = storage_tipc_file_move(session, msg, payload, payload_len);
        break;
    case STORAGE_FILE_OPEN:
        return storage_tipc_file_open(tipc_session, msg, payload, payload_len);
    case STORAGE_FILE_CLOSE:
        result = storage_tipc_file_close(session, msg, payload, payload_len);
        break;
    case STORAGE_FILE_WRITE:
        result = storage_tipc_file_write(session, msg, payload, payload_len);
        break;
    case STORAGE_FILE_READ:
        return storage_tipc_file_read(tipc_session, msg, payload, payload_len);
    case STORAGE_FILE_LIST:
        return storage_tipc_file_list(tipc_session, msg, payload, payload_len);
    case STORAGE_FILE_GET_SIZE:
        return storage_tipc_file_get_size(tipc_session, msg, payload,
                                          payload_len);
    case STORAGE_FILE_SET_SIZE:
        result = storage_tipc_file_set_size(session, msg, payload, payload_len);
        break;
    case STORAGE_END_TRANSACTION:
        result = storage_transaction_end(session,
                                         extract_storage_op_flags(msg->flags));
        break;
    default:
        SS_ERR("%s: unsupported command 0x%" PRIx32 "\n", __func__, msg->cmd);
        result = STORAGE_ERR_UNIMPLEMENTED;
        break;
    }

    return send_result(tipc_session, msg, result);
}

int client_create_port(struct tipc_hset* hset,
                       struct ipc_port_context* client_ctx,
                       const char* port_name) {
    int ret;
    uint32_t flags = IPC_PORT_ALLOW_TA_CONNECT;
#if TEST_BUILD
    flags |= IPC_PORT_ALLOW_NS_CONNECT;
#endif

    /* start accepting client connections */
    client_ctx->ops.on_connect = client_connect;
    ret = ipc_port_create(hset, client_ctx, port_name, 1,
                          STORAGE_MAX_BUFFER_SIZE, flags);
    if (ret < 0) {
        SS_ERR("%s: failure initializing client port (%d)\n", __func__, ret);
        return ret;
    }
    return 0;
}
