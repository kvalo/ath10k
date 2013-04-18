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

enum ath10k_htc_tx_flags {
	ATH10K_HTC_FLAG_NEED_CREDIT_UPDATE = 0x01,
	ATH10K_HTC_FLAG_SEND_BUNDLE        = 0x02
};

enum ath10k_htc_rx_flags {
	ATH10K_HTC_FLAG_TRAILER_PRESENT = 0x02,
	ATH10K_HTC_FLAG_BUNDLE_MASK     = 0xF0
};

struct ath10k_htc_hdr {
	u8 eid; /* @enum ath10k_htc_ep_id */
	u8 flags; /* @enum ath10k_htc_tx_flags, ath10k_htc_rx_flags */
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

enum ath10k_ath10k_htc_msg_id {
	ATH10K_HTC_MSG_READY_ID                = 1,
	ATH10K_HTC_MSG_CONNECT_SERVICE_ID      = 2,
	ATH10K_HTC_MSG_CONNECT_SERVICE_RESP_ID = 3,
	ATH10K_HTC_MSG_SETUP_COMPLETE_ID       = 4,
	ATH10K_HTC_MSG_SETUP_COMPLETE_EX_ID    = 5,
	ATH10K_HTC_MSG_SEND_SUSPEND_COMPLETE   = 6
};

enum ath10k_htc_version {
	ATH10K_HTC_VERSION_2P0 = 0x00, /* 2.0 */
	ATH10K_HTC_VERSION_2P1 = 0x01, /* 2.1 */
};

enum ath10k_htc_conn_flags {
	ATH10K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_ONE_FOURTH    = 0x0,
	ATH10K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_ONE_HALF      = 0x1,
	ATH10K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_THREE_FOURTHS = 0x2,
	ATH10K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_UNITY         = 0x3,
#define ATH10K_HTC_CONN_FLAGS_THRESHOLD_LEVEL_MASK 0x3
	ATH10K_HTC_CONN_FLAGS_REDUCE_CREDIT_DRIBBLE    = 1 << 2,
	ATH10K_HTC_CONN_FLAGS_DISABLE_CREDIT_FLOW_CTRL = 1 << 3
#define ATH10K_HTC_CONN_FLAGS_RECV_ALLOC_MASK 0xFF00
#define ATH10K_HTC_CONN_FLAGS_RECV_ALLOC_LSB  8
};

enum ath10k_htc_conn_svc_status {
	ATH10K_HTC_CONN_SVC_STATUS_SUCCESS      = 0,
	ATH10K_HTC_CONN_SVC_STATUS_NOT_FOUND    = 1,
	ATH10K_HTC_CONN_SVC_STATUS_FAILED       = 2,
	ATH10K_HTC_CONN_SVC_STATUS_NO_RESOURCES = 3,
	ATH10K_HTC_CONN_SVC_STATUS_NO_MORE_EP   = 4
};

struct ath10k_ath10k_htc_msg_hdr {
	__le16 message_id; /* @enum htc_message_id */
} __packed;

struct ath10k_htc_unknown {
	u8 pad0;
	u8 pad1;
} __packed;

struct ath10k_htc_ready {
	__le16 credit_count;
	__le16 credit_size;
	u8 max_endpoints;
	u8 pad0;
} __packed;

struct ath10k_htc_ready_extended {
	struct ath10k_htc_ready base;
	u8 htc_version; /* @enum ath10k_htc_version */
	u8 max_msgs_per_htc_bundle;
	u8 pad0;
	u8 pad1;
} __packed;

struct ath10k_htc_conn_svc {
	__le16 service_id;
	__le16 flags; /* @enum ath10k_htc_conn_flags */
	u8 pad0;
	u8 pad1;
} __packed;

struct ath10k_htc_conn_svc_response {
	__le16 service_id;
	u8 status; /* @enum ath10k_htc_conn_svc_status */
	u8 eid;
	__le16 max_msg_size;
} __packed;

struct ath10k_htc_setup_complete_extended {
	u8 pad0;
	u8 pad1;
	__le32 flags; /* @enum htc_setup_complete_flags */
	u8 max_msgs_per_bundled_recv;
	u8 pad2;
	u8 pad3;
	u8 pad4;
} __packed;

struct ath10k_htc_msg {
	struct ath10k_ath10k_htc_msg_hdr hdr;
	union {
		/* host-to-target */
		struct ath10k_htc_conn_svc connect_service;
		struct ath10k_htc_ready ready;
		struct ath10k_htc_ready_extended ready_ext;
		struct ath10k_htc_unknown unknown;
		struct ath10k_htc_setup_complete_extended setup_complete_ext;

		/* target-to-host */
		struct ath10k_htc_conn_svc_response connect_service_response;
	};
} __packed __aligned(4);

enum ath10k_ath10k_htc_record_id {
	ATH10K_HTC_RECORD_NULL    = 0,
	ATH10K_HTC_RECORD_CREDITS = 1
};

struct ath10k_ath10k_htc_record_hdr {
	u8 id; /* @enum ath10k_ath10k_htc_record_id */
	u8 len;
	u8 pad0;
	u8 pad1;
} __packed;

struct ath10k_htc_credit_report {
	u8 eid; /* @enum ath10k_htc_ep_id */
	u8 credits;
	u8 pad0;
	u8 pad1;
} __packed;

struct ath10k_htc_record {
	struct ath10k_ath10k_htc_record_hdr hdr;
	union {
		struct ath10k_htc_credit_report credit_report[0];
		u8 pauload[0];
	};
} __packed __aligned(4);

/*
 * note: the trailer offset is dynamic depending
 * on payload length. this is only a struct layout draft
 */
struct ath10k_htc_frame {
	struct ath10k_htc_hdr hdr;
	union {
		struct ath10k_htc_msg msg;
		u8 payload[0];
	};
	struct ath10k_htc_record trailer[0];
} __packed __aligned(4);

#define ATH10K_NUM_CONTROL_TX_BUFFERS 2
#define ATH10K_HTC_MAX_LEN 4096
#define ATH10K_HTC_MAX_CTRL_MSG_LEN 256
#define ATH10K_HTC_WAIT_TIMEOUT_HZ (1*HZ)
#define ATH10K_HTC_CONTROL_BUFFER_SIZE (ATH10K_HTC_MAX_CTRL_MSG_LEN + sizeof(struct ath10k_htc_hdr))
#define ATH10K_HTC_CONN_SVC_TIMEOUT_HZ (1*HZ)

struct ath10k_htc_ep {
	struct ath10k_htc *htc;
	enum ath10k_htc_ep_id eid;
	enum ath10k_htc_svc_id service_id;
	struct ath10k_htc_ep_ops ep_ops;

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

struct ath10k_htc_svc_tx_credits {
	u16 service_id;
	u8  credit_allocation;
};

struct ath10k_htc {
	struct ath10k *ar;
	struct ath10k_htc_ep endpoint[ATH10K_HTC_EP_COUNT];

	spinlock_t htc_tx_lock;

	struct ath10k_htc_ops htc_ops;

	u8 control_resp_buffer[ATH10K_HTC_MAX_CTRL_MSG_LEN];
	int control_resp_len;

	struct completion ctl_resp;

	int total_transmit_credits;
	struct ath10k_htc_svc_tx_credits service_tx_alloc[ATH10K_HTC_EP_COUNT];
	int target_credit_size;

	bool stopping;
};

#endif	/* _HTC_PRIV_H_ */
