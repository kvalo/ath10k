/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _HTC_PRIV_H
#define _HTC_PRIV_H

#include <linux/semaphore.h>
#include <linux/timer.h>

#include "htc.h"
#include "hif.h"

/*
 * HTC - host-target control protocol
 *
 * tx packets are generally <htc_hdr><payload>
 * rx packets are more complex: <htc_hdr><payload><trailer>
 *
 * The payload + trailer length is stored in len.
 * To get payload-only length one needs to payload - trailer_len.
 *
 * Trailer contains (possibly) multiple <htc_record>.
 * Each record is a id-len-value.
 *
 * HTC header flags, control_byte0, control_byte1
 * have different meaning depending whether its tx
 * or rx.
 *
 * Alignment: htc_hdr, payload and trailer are
 * 4-byte aligned.
 */

enum htc_tx_flags {
	HTC_FLAG_NEED_CREDIT_UPDATE = 0x01,
	HTC_FLAG_SEND_BUNDLE        = 0x02
};

enum htc_rx_flags {
	HTC_FLAG_TRAILER_PRESENT = 0x02,
	HTC_FLAG_BUNDLE_MASK     = 0xF0
};

struct htc_hdr {
	u8 eid; /* @enum htc_endpoint_id */
	u8 flags; /* @enum htc_tx_flags, htc_rx_flags */
	__le16 len;
	union {
		u8 trailer_len; /* for rx */
		u8 control_byte0;
	} __packed;
	union {
		u8 seq_no; /* for tx */
		u8 control_byte1;
	} __packed;
	u8 pad0;
	u8 pad1;
} __packed __aligned(4);

#define HTC_MAX_LEN 4096
#define HTC_MAX_CTRL_MSG_LEN 256

enum htc_msg_id {
	HTC_MSG_READY_ID                = 1,
	HTC_MSG_CONNECT_SERVICE_ID      = 2,
	HTC_MSG_CONNECT_SERVICE_RESP_ID = 3,
	HTC_MSG_SETUP_COMPLETE_ID       = 4,
	HTC_MSG_SETUP_COMPLETE_EX_ID    = 5,
	HTC_MSG_SEND_SUSPEND_COMPLETE   = 6
};

enum htc_version {
	HTC_VERSION_2P0 = 0x00, /* 2.0 */
	HTC_VERSION_2P1 = 0x01, /* 2.1 */
};

enum htc_connect_flags {
	HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_ONE_FOURTH    = 0x0,
	HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_ONE_HALF      = 0x1,
	HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_THREE_FOURTHS = 0x2,
	HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_UNITY         = 0x3,
#define HTC_CONNECT_FLAGS_THRESHOLD_LEVEL_MASK 0x3
	HTC_CONNECT_FLAGS_REDUCE_CREDIT_DRIBBLE    = 1 << 2,
	HTC_CONNECT_FLAGS_DISABLE_CREDIT_FLOW_CTRL = 1 << 3
#define HTC_CONNECT_FLAGS_RECV_ALLOC_MASK 0xFF00
#define HTC_CONNECT_FLAGS_RECV_ALLOC_LSB  8
};

enum htc_connect_service_status {
	HTC_SERVICE_SUCCESS      = 0,
	HTC_SERVICE_NOT_FOUND    = 1,
	HTC_SERVICE_FAILED       = 2,
	HTC_SERVICE_NO_RESOURCES = 3,
	HTC_SERVICE_NO_MORE_EP   = 4
};

struct htc_msg_hdr {
	__le16 message_id; /* @enum htc_message_id */
} __packed;

struct htc_unknown {
	u8 pad0;
	u8 pad1;
} __packed;

struct htc_ready {
	__le16 credit_count;
	__le16 credit_size;
	u8 max_endpoints;
	u8 pad0;
} __packed;

struct htc_ready_extended {
	struct htc_ready base;
	u8 htc_version;
	u8 max_msgs_per_htc_bundle;
	u8 pad0;
	u8 pad1;
} __packed;

struct htc_connect_service {
	__le16 service_id;
	__le16 flags; /* @enum htc_connect_flags */
	u8 pad0;
	u8 pad1;
} __packed;

struct htc_connect_service_response {
	__le16 service_id;
	u8 status; /* @enum htc_connect_service_status */
	u8 eid;
	__le16 max_msg_size;
} __packed;

struct htc_setup_complete_extended {
	u8 pad0;
	u8 pad1;
	__le32 flags; /* @enum htc_setup_complete_flags */
	u8 max_msgs_per_bundled_recv;
	u8 pad2;
	u8 pad3;
	u8 pad4;
} __packed;

struct htc_msg {
	struct htc_msg_hdr hdr;
	union {
		/* host-to-target */
		struct htc_connect_service connect_service;
		struct htc_ready ready;
		struct htc_ready_extended ready_ext;
		struct htc_unknown unknown;
		struct htc_setup_complete_extended setup_complete_ext;

		/* target-to-host */
		struct htc_connect_service_response connect_service_response;
	};
} __packed __aligned(4);

enum htc_record_id {
	HTC_RECORD_NULL    = 0,
	HTC_RECORD_CREDITS = 1
};

struct htc_record_hdr {
	u8 id; /* @enum htc_record_id */
	u8 len;
	u8 pad0;
	u8 pad1;
} __packed;

struct htc_credit_report {
	u8 eid; /* @enum htc_endpoint_id */
	u8 credits;
	u8 pad0;
	u8 pad1;
} __packed;

struct htc_record {
	struct htc_record_hdr hdr;
	union {
		struct htc_credit_report credit_report[0];
		u8 pauload[0];
	};
} __packed __aligned(4);

/*
 * note: the trailer offset is dynamic depending
 * on payload length. this is only a struct layout draft
 */
struct htc_frame {
	struct htc_hdr hdr;
	union {
		struct htc_msg msg;
		u8 payload[0];
	};
	struct htc_record trailer[0];
} __packed __aligned(4);

/* HTC operational parameters */
#define NUM_CONTROL_TX_BUFFERS 2

/* TODO, this is just a temporary max packet size */
#define MAX_MESSAGE_SIZE 1536

#define HTC_WAIT_TIMEOUT_HZ (1*HZ)
#define HTC_CONTROL_BUFFER_SIZE (HTC_MAX_CTRL_MSG_LEN + sizeof(struct htc_hdr))
#define HTC_CONN_SVC_TIMEOUT_HZ (1*HZ)

struct htc_endpoint {
	struct htc_target *target;
	enum htc_endpoint_id ep_id;
	enum htc_service_id service_id;
	struct htc_ep_callbacks ep_callbacks;

	int max_tx_queue_depth;
	int max_ep_message_len;
	u8 ul_pipe_id;
	u8 dl_pipe_id;
	int ul_is_polled; /* call HIF to get tx completions */
	int dl_is_polled; /* call HIF to fetch rx (not implemented) */

	struct sk_buff_head tx_queue;
	int tx_queue_len;
	bool tx_queue_stopped;

	u8 seq_no; /* for debugging */
	int tx_credits;
	int tx_credit_size;
	int tx_credits_per_max_message;
	bool tx_credit_flow_enabled;

	struct work_struct send_work;
};

struct htc_service_tx_creadit_alloc {
	u16 service_id;
	u8  credit_allocation;
};

struct htc_target {
	struct ath10k *ar;
	struct htc_endpoint endpoint[HTC_EP_COUNT];

	spinlock_t htc_tx_lock;

	struct htc_target_cb htc_cb;

	u8 control_resp_buffer[HTC_MAX_CTRL_MSG_LEN];
	int control_resp_len;

	struct completion ctl_resp;

	int total_transmit_credits;
	struct htc_service_tx_creadit_alloc service_tx_alloc[HTC_EP_COUNT];
	int target_credit_size;
};

#endif	/* _HTC_PRIV_H_ */
