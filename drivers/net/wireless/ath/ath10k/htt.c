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

#include <linux/slab.h>

#include "htt.h"
#include "core.h"
#include "debug.h"

static void ath10k_htt_stop_queue(void *context)
{
	struct htt_struct *htt = context;
	ieee80211_stop_queues(htt->ar->hw);
}

static void ath10k_htt_wake_queue(void *context)
{
	struct htt_struct *htt = context;
	ieee80211_wake_queues(htt->ar->hw);
}

static int ath10k_htt_htc_attach(struct htt_struct *htt)
{
	struct htc_service_connect_req connect;
	struct htc_service_connect_resp response;
	int status;

	memset(&connect, 0, sizeof(connect));
	memset(&response, 0, sizeof(response));

	connect.ep_callbacks.context = htt;
	connect.ep_callbacks.ep_rx_complete = htt_t2h_msg_handler;
	connect.ep_callbacks.stop_queue = ath10k_htt_stop_queue;
	connect.ep_callbacks.wake_queue = ath10k_htt_wake_queue;

	/*
	 * Specify how deep to let a queue get before ath10k_htc_send will
	 * call the ep_send_full function due to excessive send queue depth.
	 */
	connect.max_send_queue_depth = HTT_MAX_SEND_QUEUE_DEPTH;

	/* connect to control service */
	connect.service_id = HTC_SVC_HTT_DATA_MSG;

	status = ath10k_htc_connect_service(htt->htc_target, &connect, &response);

	if (status)
		return status;

	htt->ep_id = response.ep_id;

	return 0;
}

struct htt_struct *ath10k_htt_attach(struct ath10k *ar, void *htc_target)
{
	struct htt_struct *htt;

	htt = kzalloc(sizeof(*htt), GFP_KERNEL);
	if (!htt)
		goto fail1;

	htt->ar = ar;
	htt->htc_target = htc_target;
	htt->cfg.max_throughput_mbps = 800;

	/*
	 * Connect to HTC service.
	 * This has to be done before calling htt_rx_attach,
	 * since htt_rx_attach involves sending a rx ring configure
	 * message to the target.
	 */
	if (ath10k_htt_htc_attach(htt))
		goto fail2;

	htt_tx_attach(htt);

	if (htt_rx_attach(htt))
		goto fail3;

	/*
	 * Prefetch enough data to satisfy target
	 * classification engine.
	 * This is for LL chips. HL chips will probably
	 * transfer all frame in the tx fragment.
	 */
	htt->prefetch_len =
		36 + /* 802.11 + qos + ht */
		4 + /* 802.1q */
		8 + /* llc snap */
		2; /* ip4 dscp or ip6 priority */

	return htt;

fail3:
	htt_tx_detach(htt);
fail2:
	kfree(htt);
fail1:
	return NULL;
}

#define HTT_TARGET_VERSION_TIMEOUT_HZ (3*HZ)

static int ath10k_htt_verify_version(struct htt_struct *htt)
{
	ath10k_dbg(ATH10K_DBG_HTT,
		   "htt target version %d.%d; host version %d.%d\n",
		    htt->target_version_major,
		    htt->target_version_minor,
		    HTT_CURRENT_VERSION_MAJOR,
		    HTT_CURRENT_VERSION_MINOR);

	if (htt->target_version_major != HTT_CURRENT_VERSION_MAJOR) {
		ath10k_err("htt major versions are incompatible!\n");
		return -ENOTSUPP;
	}

	if (htt->target_version_minor != HTT_CURRENT_VERSION_MINOR)
		ath10k_warn("htt minor version differ but still compatible\n");

	return 0;
}

int ath10k_htt_attach_target(struct htt_struct *htt)
{
	int status;

	init_completion(&htt->target_version_received);

	status = htt_h2t_ver_req_msg(htt);
	if (status)
		return status;

	status = wait_for_completion_timeout(&htt->target_version_received,
						HTT_TARGET_VERSION_TIMEOUT_HZ);
	if (status <= 0) {
		ath10k_warn("htt version request timed out\n");
		return -ETIMEDOUT;
	}

	status = ath10k_htt_verify_version(htt);
	if (status)
		return status;

	return htt_send_rx_ring_cfg_ll(htt);

}

void ath10k_htt_detach(struct htt_struct *htt)
{
	htt_rx_detach(htt);
	htt_tx_detach(htt);
	kfree(htt);
}
