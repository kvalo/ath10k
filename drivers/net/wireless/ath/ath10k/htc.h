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
#include "core.h"


#define MAKE_SERVICE_ID(group, index) \
	(int)(((int)(group) << 8) | (int)(index))

enum htc_service_group_id {
	HTC_SVC_GROUP_RSVD = 0,
	HTC_SVC_GROUP_WMI = 1,
	HTC_SVC_GROUP_NMI = 2,
	HTC_SVC_GROUP_HTT = 3,

	HTC_SVC_GROUP_TEST = 254,
	HTC_SVC_GROUP_LAST = 255,
};

enum htc_service_id {
	/* NOTE: service ID of 0x0000 is reserved and should never be used */
	HTC_SVC_RESERVED	= 0x0000,
	HTC_SVC_UNUSED		= HTC_SVC_RESERVED,

	HTC_SVC_RSVD_CTRL	= MAKE_SERVICE_ID(HTC_SVC_GROUP_RSVD, 1),
	HTC_SVC_WMI_CONTROL	= MAKE_SERVICE_ID(HTC_SVC_GROUP_WMI, 0),
	HTC_SVC_WMI_DATA_BE	= MAKE_SERVICE_ID(HTC_SVC_GROUP_WMI, 1),
	HTC_SVC_WMI_DATA_BK	= MAKE_SERVICE_ID(HTC_SVC_GROUP_WMI, 2),
	HTC_SVC_WMI_DATA_VI	= MAKE_SERVICE_ID(HTC_SVC_GROUP_WMI, 3),
	HTC_SVC_WMI_DATA_VO	= MAKE_SERVICE_ID(HTC_SVC_GROUP_WMI, 4),

	HTC_SVC_NMI_CONTROL	= MAKE_SERVICE_ID(HTC_SVC_GROUP_NMI, 0),
	HTC_SVC_NMI_DATA	= MAKE_SERVICE_ID(HTC_SVC_GROUP_NMI, 1),

	HTC_SVC_HTT_DATA_MSG	= MAKE_SERVICE_ID(HTC_SVC_GROUP_HTT, 0),

	/* raw stream service (i.e. flash, tcmd, calibration apps) */
	HTC_SVC_TEST_RAW_STREAMS = MAKE_SERVICE_ID(HTC_SVC_GROUP_TEST, 0),
};

enum htc_endpoint_id {
	HTC_EP_UNUSED = -1,
	HTC_EP_0 = 0,
	HTC_EP_1 = 1,
	HTC_EP_2,
	HTC_EP_3,
	HTC_EP_4,
	HTC_EP_5,
	HTC_EP_6,
	HTC_EP_7,
	HTC_EP_8,
	HTC_EP_COUNT,
};

struct htc_target_cb {
	void (*target_failure)(struct ath10k *ar, int status);
	void (*target_send_suspend_complete)(struct ath10k *ar);
};

struct htc_ep_callbacks {
	void *context;
	void (*ep_rx_complete)(void *context, struct sk_buff *);
	void (*stop_queue)(void *context);
	void (*wake_queue)(void *context);
};

/* service connection information */
struct htc_service_connect_req {
	u16 service_id;
	struct htc_ep_callbacks ep_callbacks;
	int max_send_queue_depth;
};

/* service connection response information */
struct htc_service_connect_resp {
	u8 buffer_len;
	u8 actual_len;
	enum htc_endpoint_id ep_id;
	unsigned int max_msg_len;
	u8 connect_resp_code;
};

struct htc_target *ath10k_htc_create(struct ath10k *ar,
				     struct htc_target_cb *htc_cb);
int ath10k_htc_wait_target(struct htc_target *target);
int ath10k_htc_start(struct htc_target *target);
int ath10k_htc_connect_service(struct htc_target *target,
			       struct htc_service_connect_req  *connect_req,
			       struct htc_service_connect_resp *connect_resp);
int ath10k_htc_send(struct htc_target *target, enum htc_endpoint_id eid,
		    struct sk_buff *packet);
void ath10k_htc_stop(struct htc_target *target);
void ath10k_htc_destroy(struct htc_target *target);
struct sk_buff *ath10k_htc_alloc_skb(int extra_headroom);

#endif
