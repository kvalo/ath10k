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

#ifndef _HTC_H
#define _HTC_H

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/skbuff.h>

struct ath10k;

enum ath10k_htc_svc_gid {
	ATH10K_HTC_SVC_GRP_RSVD = 0,
	ATH10K_HTC_SVC_GRP_WMI = 1,
	ATH10K_HTC_SVC_GRP_NMI = 2,
	ATH10K_HTC_SVC_GRP_HTT = 3,

	ATH10K_HTC_SVC_GRP_TEST = 254,
	ATH10K_HTC_SVC_GRP_LAST = 255,
};

#define SVC(group, idx) \
	(int)(((int)(group) << 8) | (int)(idx))

enum ath10k_htc_svc_id {
	/* NOTE: service ID of 0x0000 is reserved and should never be used */
	ATH10K_HTC_SVC_ID_RESERVED		= 0x0000,
	ATH10K_HTC_SVC_ID_UNUSED		= ATH10K_HTC_SVC_ID_RESERVED,

	ATH10K_HTC_SVC_ID_RSVD_CTRL		= SVC(ATH10K_HTC_SVC_GRP_RSVD, 1),
	ATH10K_HTC_SVC_ID_WMI_CONTROL		= SVC(ATH10K_HTC_SVC_GRP_WMI, 0),
	ATH10K_HTC_SVC_ID_WMI_DATA_BE		= SVC(ATH10K_HTC_SVC_GRP_WMI, 1),
	ATH10K_HTC_SVC_ID_WMI_DATA_BK		= SVC(ATH10K_HTC_SVC_GRP_WMI, 2),
	ATH10K_HTC_SVC_ID_WMI_DATA_VI		= SVC(ATH10K_HTC_SVC_GRP_WMI, 3),
	ATH10K_HTC_SVC_ID_WMI_DATA_VO		= SVC(ATH10K_HTC_SVC_GRP_WMI, 4),

	ATH10K_HTC_SVC_ID_NMI_CONTROL		= SVC(ATH10K_HTC_SVC_GRP_NMI, 0),
	ATH10K_HTC_SVC_ID_NMI_DATA		= SVC(ATH10K_HTC_SVC_GRP_NMI, 1),

	ATH10K_HTC_SVC_ID_HTT_DATA_MSG		= SVC(ATH10K_HTC_SVC_GRP_HTT, 0),

	/* raw stream service (i.e. flash, tcmd, calibration apps) */
	ATH10K_HTC_SVC_ID_TEST_RAW_STREAMS	= SVC(ATH10K_HTC_SVC_GRP_TEST, 0),
};

#undef SVC

enum ath10k_htc_ep_id {
	ATH10K_HTC_EP_UNUSED = -1,
	ATH10K_HTC_EP_0 = 0,
	ATH10K_HTC_EP_1 = 1,
	ATH10K_HTC_EP_2,
	ATH10K_HTC_EP_3,
	ATH10K_HTC_EP_4,
	ATH10K_HTC_EP_5,
	ATH10K_HTC_EP_6,
	ATH10K_HTC_EP_7,
	ATH10K_HTC_EP_8,
	ATH10K_HTC_EP_COUNT,
};

struct ath10k_htc_ops {
	void (*target_send_suspend_complete)(struct ath10k *ar);
};

struct ath10k_htc_ep_ops {
	void *context;
	void (*ep_tx_complete)(void *context, struct sk_buff *);
	void (*ep_rx_complete)(void *context, struct sk_buff *);
	void (*stop_queue)(void *context);
	void (*wake_queue)(void *context);
};

/* service connection information */
struct ath10k_htc_svc_conn_req {
	u16 service_id;
	struct ath10k_htc_ep_ops ep_ops;
	int max_send_queue_depth;
};

/* service connection response information */
struct ath10k_htc_svc_conn_resp {
	u8 buffer_len;
	u8 actual_len;
	enum ath10k_htc_ep_id eid;
	unsigned int max_msg_len;
	u8 connect_resp_code;
};

struct ath10k_htc *ath10k_htc_create(struct ath10k *ar,
				     struct ath10k_htc_ops *htc_ops);
int ath10k_htc_wait_target(struct ath10k_htc *htc);
int ath10k_htc_start(struct ath10k_htc *htc);
int ath10k_htc_connect_service(struct ath10k_htc *htc,
			       struct ath10k_htc_svc_conn_req  *conn_req,
			       struct ath10k_htc_svc_conn_resp *conn_resp);
int ath10k_htc_send(struct ath10k_htc *htc, enum ath10k_htc_ep_id eid,
		    struct sk_buff *packet);
void ath10k_htc_stop(struct ath10k_htc *htc);
void ath10k_htc_destroy(struct ath10k_htc *htc);
struct sk_buff *ath10k_htc_alloc_skb(int size);

#endif
