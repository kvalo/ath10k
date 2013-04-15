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

#include "core.h"
#include "htc-priv.h"
#include "debug.h"

/********/
/* Send */
/********/

static inline void ath10k_htc_stop_queue(struct htc_endpoint *ep)
{
	if (ep->tx_queue_stopped)
		return;

	if (ep->ep_callbacks.stop_queue)
		ep->ep_callbacks.stop_queue(ep->ep_callbacks.context);

	ath10k_dbg(ATH10K_DBG_HTC, "ep %d stop\n", ep->ep_id);
	ep->tx_queue_stopped = true;
}

static inline void ath10k_htc_wake_queue(struct htc_endpoint *ep)
{
	if (!ep->tx_queue_stopped)
		return;

	if (ep->ep_callbacks.wake_queue)
		ep->ep_callbacks.wake_queue(ep->ep_callbacks.context);

	ath10k_dbg(ATH10K_DBG_HTC, "ep %d wake\n", ep->ep_id);
	ep->tx_queue_stopped = false;
}

static inline void ath10k_htc_recalc_queue(struct htc_endpoint *ep, int delta)
{
	ath10k_dbg(ATH10K_DBG_HTC, "ep %d queue len %d +%d max %d\n",
		   ep->ep_id, ep->tx_queue_len, delta, ep->max_tx_queue_depth);

	if (ep->max_tx_queue_depth == 0)
		return;

	ep->tx_queue_len += delta;

	if (ep->tx_queue_stopped) {
		if (ep->tx_queue_len <= ep->max_tx_queue_depth/2)
			ath10k_htc_wake_queue(ep);
	} else if (ep->tx_queue_len >= ep->max_tx_queue_depth)
		ath10k_htc_stop_queue(ep);
}

static inline void ath10k_htc_send_complete_check(struct htc_endpoint *ep,
						  int force)
{
	/*
	 * Check whether HIF has any prior sends that have finished,
	 * have not had the post-processing done.
	 */
	ath10k_hif_send_complete_check(ep->target->ar, ep->ul_pipe_id, force);
}

static void ath10k_htc_control_tx_complete(struct sk_buff *skb)
{
	kfree_skb(skb);
}

static struct sk_buff *ath10k_htc_build_tx_ctrl_skb(void *ar)
{
	struct sk_buff *skb;
	struct ath10k_skb_cb *skb_cb;

	skb = dev_alloc_skb(HTC_CONTROL_BUFFER_SIZE);
	if (!skb) {
		ath10k_warn("Unable to allocate ctrl skb\n");
		return NULL;
	}

	skb_reserve(skb, 20); /* FIXME: why 20 bytes? */
	WARN_ONCE((unsigned long)skb->data & 3, "unaligned skb");

	skb_cb = ATH10K_SKB_CB(skb);
	memset(skb_cb, 0, sizeof(*skb_cb));

	ath10k_dbg(ATH10K_DBG_HTC, "%s: skb %p\n", __func__, skb);
	return skb;
}

static inline void ath10k_htc_restore_tx_skb(struct htc_target *target,
				       struct sk_buff *skb)
{
	ath10k_skb_unmap(target->ar->dev, skb);
	skb_pull(skb, sizeof(struct htc_hdr));
}

static void ath10k_htc_notify_tx_completion(struct htc_endpoint *ep,
				     struct sk_buff *skb)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);

	ath10k_dbg(ATH10K_DBG_HTC, "%s: ep %d skb %p\n", __func__,
		   ep->ep_id, skb);

	ath10k_htc_restore_tx_skb(ep->target, skb);

	if (!skb_cb->htc.complete) {
		ath10k_warn("no tx handler for eid %d\n", ep->ep_id);
		dev_kfree_skb_any(skb);
		return;
	}

	skb_cb->htc.complete(skb);
}

/* assumes htc_tx_lock is held */
static bool ath10k_htc_ep_need_credit_update(struct htc_endpoint *ep)
{
	if (!ep->tx_credit_flow_enabled)
		return false;
	if (ep->tx_credits >= ep->tx_credits_per_max_message)
		return false;

	ath10k_dbg(ATH10K_DBG_HTC, "HTC: endpoint %d needs credit update\n",
		   ep->ep_id);
	return true;
}

static int ath10k_htc_prepare_tx_skb(struct htc_endpoint *ep,
				     struct sk_buff *skb)
{
	struct htc_hdr *hdr;

	hdr = (struct htc_hdr *)skb->data;
	memset(hdr, 0, sizeof(*hdr));

	hdr->eid = ep->ep_id;
	hdr->len = __cpu_to_le16(skb->len - sizeof(*hdr));

	spin_lock_bh(&ep->target->htc_tx_lock);
	hdr->seq_no = ep->seq_no++;
	hdr->flags |= ath10k_htc_ep_need_credit_update(ep)
			? HTC_FLAG_NEED_CREDIT_UPDATE
			: 0;
	spin_unlock_bh(&ep->target->htc_tx_lock);

	return 0;
}

static int ath10k_htc_issue_skb(struct htc_target *target,
				struct htc_endpoint *ep,
				struct sk_buff *skb)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);
	int ret;

	ath10k_dbg(ATH10K_DBG_HTC, "%s: ep %d skb %p\n", __func__,
		   ep->ep_id, skb);

	ret = ath10k_htc_prepare_tx_skb(ep, skb);
	if (ret)
		goto err;

	ret = ath10k_skb_map(target->ar->dev, skb);
	if (ret)
		goto err;

	ret = ath10k_hif_send_head(target->ar,
				   ep->ul_pipe_id,
				   ep->ep_id,
				   skb->len,
				   skb);
	if (unlikely(ret))
		goto err;

	return 0;
err:
	ath10k_warn("HTC issue failed: %d\n", ret);

	spin_lock_bh(&target->htc_tx_lock);
	ep->tx_credits += skb_cb->htc.credits_used;
	spin_unlock_bh(&target->htc_tx_lock);

	skb_cb->htc.cancelled = true;
	ath10k_htc_notify_tx_completion(ep, skb);

	return ret;
}

/* assumes htc_tx_lock is held */
static struct sk_buff *ath10k_htc_get_skb_credit_based(struct htc_target *target,
						       struct htc_endpoint *ep)
{
	struct sk_buff *skb;
	struct ath10k_skb_cb *skb_cb;
	int credits_required;
	int remainder;
	unsigned int transfer_len;

	skb = skb_dequeue(&ep->tx_queue);
	if (!skb)
		return NULL;

	skb_cb = ATH10K_SKB_CB(skb);
	ath10k_htc_recalc_queue(ep, -1);

	transfer_len = skb->len;

	if (transfer_len <= target->target_credit_size)
		credits_required = 1;
	else {
		/* figure out how many credits this message requires */
		credits_required = transfer_len / target->target_credit_size;
		remainder = transfer_len % target->target_credit_size;

		if (remainder)
			credits_required++;
	}

	ath10k_dbg(ATH10K_DBG_HTC, "%s: creds required %d got %d\n",
		   __func__, credits_required, ep->tx_credits);

	/*
	 * EP 0 is special, it always has a credit and does not require
	 * credit based flow control.
	 */
	if (ep->ep_id == HTC_EP_0)
		credits_required = 0;
	else {
		if (ep->tx_credits < credits_required) {
			skb_queue_head(&ep->tx_queue, skb);
			ath10k_htc_recalc_queue(ep, 1);
			return NULL;
		}

		ep->tx_credits -= credits_required;
	}

	/* shouldn't happen, but print a warning just in case */
	if (credits_required >= 1 << (8*sizeof(skb_cb->htc.credits_used)))
		ath10k_warn("credits_required value overflow (%d)\n", credits_required);

	skb_cb->htc.credits_used = credits_required;
	return skb;
}

/* assumes htc_tx_lock is held */
static struct sk_buff *ath10k_htc_get_skb(struct htc_target *target,
					  struct htc_endpoint *ep,
					  int resources)
{
	struct sk_buff *skb;
	struct ath10k_skb_cb *skb_cb;

	if (!resources)
		return NULL;

	skb = skb_dequeue(&ep->tx_queue);
	if (!skb)
		return NULL;

	skb_cb = ATH10K_SKB_CB(skb);
	ath10k_htc_recalc_queue(ep, -1);

	skb_cb->htc.credits_used = 0;
	return skb;
}

static void ath10k_htc_send_work(struct work_struct *work)
{
	struct htc_endpoint *ep = container_of((void *)work,
					struct htc_endpoint, send_work);
	struct htc_target *target = ep->target;
	struct sk_buff *skb;
	int tx_resources = 0;

	while (true) {
		if (!ep->tx_credit_flow_enabled)
			tx_resources = ath10k_hif_get_free_queue_number
					(target->ar, ep->ul_pipe_id);

		if (ep->ul_is_polled)
			ath10k_htc_send_complete_check(ep, 0);

		spin_lock_bh(&target->htc_tx_lock);

		if (ep->tx_credit_flow_enabled)
			skb = ath10k_htc_get_skb_credit_based(target, ep);
		else
			skb = ath10k_htc_get_skb(target, ep, tx_resources);

		spin_unlock_bh(&target->htc_tx_lock);

		if (!skb)
			break; /* tx_queue empty or out of resources */

		ath10k_htc_issue_skb(target, ep, skb);
	}
}

int ath10k_htc_send(struct htc_target *target,
		    enum htc_endpoint_id eid,
		    struct sk_buff *skb)
{
	struct htc_endpoint *ep = &target->endpoint[eid];

	if (eid >= HTC_EP_COUNT) {
		ath10k_warn("Invalid endpoint id: %d\n", eid);
		return -ENOENT;
	}

	skb_push(skb, sizeof(struct htc_hdr));

	spin_lock_bh(&target->htc_tx_lock);
	skb_queue_tail(&ep->tx_queue, skb);
	ath10k_htc_recalc_queue(ep, 1);
	spin_unlock_bh(&target->htc_tx_lock);

	queue_work(target->ar->workqueue, &ep->send_work);
	return 0;
}

static int ath10k_htc_tx_completion_handler(struct ath10k *ar,
					    struct sk_buff *skb,
					    unsigned int eid)
{
	struct htc_target *target = ar->htc_handle;
	struct htc_endpoint *ep = &target->endpoint[eid];
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);

	skb_cb->htc.cancelled = false;
	ath10k_htc_notify_tx_completion(ep, skb);
	/* the skb now belongs to the completion handler */

	if (!ep->tx_credit_flow_enabled)
		/*
		 * note: when using TX credit flow, the re-checking of
		 * queues happens when credits flow back from the target.
		 * in the non-TX credit case, we recheck after the packet
		 * completes
		 */
		queue_work(ar->workqueue, &ep->send_work);

	return 0;
}

/* flush endpoint TX queue */
static void ath10k_htc_flush_endpoint_tx(struct htc_target *target,
					 struct htc_endpoint *ep)
{
	struct sk_buff *skb;
	struct ath10k_skb_cb *skb_cb;

	spin_lock_bh(&target->htc_tx_lock);
	for (;;) {
		skb = skb_dequeue(&ep->tx_queue);
		if (!skb)
			break;

		skb_cb = ATH10K_SKB_CB(skb);
		skb_cb->htc.cancelled = true;
		ath10k_htc_notify_tx_completion(ep, skb);
	}
	spin_unlock_bh(&target->htc_tx_lock);
}

/***********/
/* Receive */
/***********/

static void ath10k_htc_fw_event_handler(struct ath10k *ar)
{
	struct htc_target *target = ar->htc_handle;
	struct htc_target_cb *htc_cb = &target->htc_cb;

	htc_cb->target_failure(ar, -EINVAL);
}

static void ath10k_htc_process_credit_report(struct htc_target *target,
					     const struct htc_credit_report *report,
					     int len,
					     enum htc_endpoint_id eid)
{
	struct htc_endpoint *ep;
	int total_credits = 0;
	int n_reports;
	int i;

	if (len % sizeof(*report))
		ath10k_warn("Uneven credit report len %d", len);

	n_reports = len / sizeof(*report);

	spin_lock_bh(&target->htc_tx_lock);
	for (i = 0; i < n_reports; i++, report++) {
		if (report->eid >= HTC_EP_COUNT)
			break;

		ath10k_dbg(ATH10K_DBG_HTC, "ep %d got %d credits\n",
			   report->eid, report->credits);

		ep = &target->endpoint[report->eid];
		ep->tx_credits += report->credits;

		if (ep->tx_credits && !skb_queue_empty(&ep->tx_queue))
			queue_work(target->ar->workqueue, &ep->send_work);

		total_credits += report->credits;
	}
	spin_unlock_bh(&target->htc_tx_lock);

	ath10k_dbg(ATH10K_DBG_HTC, "report indicated %d credits total\n",
		   total_credits);
}

static int ath10k_htc_process_trailer(struct htc_target *target,
				      u8 *buffer,
				      int length,
				      enum htc_endpoint_id src_ep_id)
{
	int status = 0;
	struct htc_record *record;
	u8 *orig_buffer;
	int orig_length;

	orig_buffer = buffer;
	orig_length = length;

	while (length > 0) {
		record = (struct htc_record *)buffer;

		if (length < sizeof(record->hdr)) {
			status = -EINVAL;
			break;
		}

		if (record->hdr.len > length) {
			/* no room left in buffer for record */
			ath10k_warn("Invalid record length: %d\n",
				    record->hdr.len);
			status = -EINVAL;
			break;
		}

		switch (record->hdr.id) {
		case HTC_RECORD_CREDITS:
			if (record->hdr.len < sizeof(struct htc_credit_report)) {
				ath10k_warn("Credit report too long\n");
				status = -EINVAL;
				break;
			}
			ath10k_htc_process_credit_report(target,
							 record->credit_report,
							 record->hdr.len,
							 src_ep_id);
			break;
		default:
			ath10k_warn("Unhandled record: id:%d length:%d\n",
				    record->hdr.id, record->hdr.len);
			break;
		}

		if (status)
			break;

		/* multiple records may be present in a trailer */
		buffer += sizeof(record->hdr) + record->hdr.len;
		length -= sizeof(record->hdr) + record->hdr.len;
	}

	if (status)
		ath10k_dbg_dump(ATH10K_DBG_HTC, "htc rx bad trailer", "",
				orig_buffer, orig_length);

	return status;
}

static int ath10k_htc_rx_completion_handler(struct ath10k *ar,
					    struct sk_buff *skb,
					    u8 pipe_id)
{
	int status = 0;
	struct htc_target *target = ar->htc_handle;
	struct htc_hdr *hdr;
	struct htc_endpoint *ep;
	struct ath10k_skb_cb *skb_cb;
	u16 payload_len;
	u32 trailer_len = 0;
	u8 htc_ep_id;
	bool trailer_present;

	hdr = (struct htc_hdr *)skb->data;
	skb_pull(skb, sizeof(*hdr));

	htc_ep_id = hdr->eid;

	if (htc_ep_id >= HTC_EP_COUNT) {
		ath10k_warn("HTC Rx: invalid ep_id %d\n", htc_ep_id);
		ath10k_dbg_dump(ATH10K_DBG_HTC, "htc bad header", "",
				hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	ep = &target->endpoint[htc_ep_id];

	/*
	 * If this endpoint that received a message from the target has
	 * a to-target HIF pipe whose send completions are polled rather
	 * than interrupt-driven, this is a good point to ask HIF to check
	 * whether it has any completed sends to handle.
	 */
	if (ep->ul_is_polled)
		ath10k_htc_send_complete_check(ep, 1);

	payload_len = __le16_to_cpu(hdr->len);

	if (payload_len + sizeof(*hdr) > HTC_MAX_LEN) {
		ath10k_warn("HTC rx frame too long, len: %zu\n",
			   payload_len + sizeof(*hdr));
		ath10k_dbg_dump(ATH10K_DBG_HTC, "htc bad rx pkt len", "",
				hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	if (skb->len < payload_len) {
		ath10k_dbg(ATH10K_DBG_HTC,
			"HTC Rx: insufficient length, got %d, expected %d\n",
			skb->len, payload_len);
		ath10k_dbg_dump(ATH10K_DBG_HTC, "htc bad rx pkt len",
				 "", hdr, sizeof(*hdr));
		status = -EINVAL;
		goto out;
	}

	/* get flags to check for trailer */
	trailer_present = hdr->flags & HTC_FLAG_TRAILER_PRESENT;
	if (trailer_present) {
		u8 *trailer;

		trailer_len = hdr->trailer_len;
		if ((trailer_len < sizeof(struct htc_record_hdr)) ||
		    (trailer_len > payload_len)) {
			ath10k_warn("Invalid trailer length: %d\n",
				   trailer_len);
			status = -EPROTO;
			goto out;
		}

		trailer = (u8 *)hdr;
		trailer += sizeof(*hdr);
		trailer += payload_len;
		trailer -= trailer_len;
		status = ath10k_htc_process_trailer(target, trailer,
						    trailer_len, hdr->eid);
		if (status)
			goto out;

		skb_trim(skb, skb->len - trailer_len);
	}

	if (((int)payload_len - (int)trailer_len) <= 0)
		/* zero length packet with trailer data, just drop these */
		goto out;

	if (htc_ep_id == HTC_EP_0) {
		struct htc_msg *msg = (struct htc_msg *)skb->data;

		switch (__le16_to_cpu(msg->hdr.message_id)) {
		default:
			/* handle HTC control message */
			if (completion_done(&target->ctl_resp)) {
				/*
				 * this is a fatal error, target should not be
				 * sending unsolicited messages on the ep 0
				 */
				ath10k_warn("HTC rx ctrl still processing\n");
				status = -EINVAL;
				complete(&target->ctl_resp);
				goto out;
			}

			target->control_resp_len =
			    min((int)skb->len, HTC_MAX_CTRL_MSG_LEN);
			memcpy(target->control_resp_buffer, skb->data,
			       target->control_resp_len);

			complete(&target->ctl_resp);
			break;
		case HTC_MSG_SEND_SUSPEND_COMPLETE:
			target->htc_cb.target_send_suspend_complete(ar);

		}
		goto out;
	}

	/*
	 * the current message based HIF architecture allocates net
	 * bufs for recv packets since this layer bridges that HIF to
	 * upper layers , which expects HTC packets, we form the
	 * packets here TODO_FIXME
	 */
	skb_cb = ATH10K_SKB_CB(skb);
	skb_cb->htc.cancelled = false;

	ath10k_dbg(ATH10K_DBG_HTC, "htc rx completion ep %d skb %p\n", htc_ep_id, skb);
	ep->ep_callbacks.ep_rx_complete(ep->ep_callbacks.context, skb);

	/* skb is now owned by the rx completion handler */
	skb = NULL;
out:
	if (skb != NULL)
		kfree_skb(skb);

	return status;
}

static void ath10k_htc_control_rx_complete(void *context, struct sk_buff *skb)
{
	/* TODO, can't receive HTC control messages yet */
	ath10k_dbg(ATH10K_DBG_HTC, "Invalid call to %s\n", __func__);
}

/***************/
/* Init/Deinit */
/***************/

static void ath10k_htc_reset_endpoint_states(struct htc_target *target)
{
	struct htc_endpoint *ep;
	int i;

	for (i = HTC_EP_0; i < HTC_EP_COUNT; i++) {
		ep = &target->endpoint[i];
		ep->service_id = HTC_SVC_UNUSED;
		ep->max_ep_message_len = 0;
		ep->max_tx_queue_depth = 0;
		ep->ep_id = i;
		skb_queue_head_init(&ep->tx_queue);
		ep->tx_queue_len = 0;
		ep->target = target;
		ep->tx_credit_flow_enabled = true;
	}
}

static void ath10k_htc_setup_target_buffer_assignments(struct htc_target *target)
{
	struct htc_service_tx_creadit_alloc *entry;

	entry = &target->service_tx_alloc[0];

	/*
	 * for PCIE allocate all credists/HTC buffers to WMI.
	 * no buffers are used/required for data. data always
	 * remains on host.
	 */
	entry++;
	entry->service_id = HTC_SVC_WMI_CONTROL;
	entry->credit_allocation = target->total_transmit_credits;
}

static u8 ath10k_htc_get_credit_allocation(struct htc_target *target,
					   u16 service_id)
{
	u8 allocation = 0;
	int i;

	for (i = 0; i < HTC_EP_COUNT; i++) {
		if (target->service_tx_alloc[i].service_id == service_id)
			allocation =
			    target->service_tx_alloc[i].credit_allocation;
	}

	return allocation;
}

int ath10k_htc_wait_target(struct htc_target *target)
{
	int status = 0;
	struct htc_service_connect_req connect;
	struct htc_service_connect_resp resp;
	struct htc_msg *msg;
	u16 message_id;
	u16 credit_count;
	u16 credit_size;

	INIT_COMPLETION(target->ctl_resp);

	ath10k_hif_start(target->ar);

	status = wait_for_completion_timeout(&target->ctl_resp,
					     HTC_WAIT_TIMEOUT_HZ);
	if (status <= 0) {
		if (status == 0)
			status = -ETIMEDOUT;

		ath10k_err("ctl_resp never came in (%d)\n", status);
		goto fail_wait_target;
	}

	if (target->control_resp_len < sizeof(msg->hdr) + sizeof(msg->ready)) {
		ath10k_err("Invalid HTC ready msg len:%d\n",
			   target->control_resp_len);

		status = -ECOMM;
		goto fail_wait_target;
	}

	msg = (struct htc_msg *)target->control_resp_buffer;
	message_id   = __le16_to_cpu(msg->hdr.message_id);
	credit_count = __le16_to_cpu(msg->ready.credit_count);
	credit_size  = __le16_to_cpu(msg->ready.credit_size);

	if (message_id != HTC_MSG_READY_ID) {
		ath10k_err("Invalid HTC ready msg: 0x%x\n", message_id);
		status = -ECOMM;
		goto fail_wait_target;
	}

	target->total_transmit_credits = credit_count;
	target->target_credit_size = credit_size;

	ath10k_dbg(ATH10K_DBG_HTC,
		   "Target ready! transmit resources: %d size:%d\n",
		   target->total_transmit_credits,
		   target->target_credit_size);

	if ((target->total_transmit_credits == 0) ||
	    (target->target_credit_size == 0)) {
		status = -ECOMM;
		ath10k_err("Invalid credit size received\n");
		goto fail_wait_target;
	}

	ath10k_htc_setup_target_buffer_assignments(target);

	/* setup our pseudo HTC control endpoint connection */
	memset(&connect, 0, sizeof(connect));
	memset(&resp, 0, sizeof(resp));
	connect.ep_callbacks.context = target;
	connect.ep_callbacks.ep_rx_complete = ath10k_htc_control_rx_complete;
	connect.max_send_queue_depth = NUM_CONTROL_TX_BUFFERS;
	connect.service_id = HTC_SVC_RSVD_CTRL;

	/* connect fake service */
	status = ath10k_htc_connect_service(target, &connect, &resp);

fail_wait_target:
	return status;
}

int ath10k_htc_connect_service(struct htc_target *target,
			       struct htc_service_connect_req *connect_req,
			       struct htc_service_connect_resp *connect_resp)
{
	struct htc_msg *msg;
	struct htc_connect_service *req_msg;
	struct htc_connect_service_response resp_msg_dummy;
	struct htc_connect_service_response *resp_msg = &resp_msg_dummy;
	enum htc_endpoint_id assigned_ep = HTC_EP_COUNT;
	struct htc_endpoint *ep;
	struct sk_buff *skb;
	struct ath10k_skb_cb *skb_cb;
	unsigned int max_msg_size = 0;
	int length, status;
	bool disable_credit_flow_ctrl = false;
	u16 message_id, service_id, flags = 0;
	u8 tx_alloc = 0;

	/* special case for HTC pseudo control service */
	if (connect_req->service_id == HTC_SVC_RSVD_CTRL) {
		assigned_ep = HTC_EP_0;
		max_msg_size = HTC_MAX_CTRL_MSG_LEN;
		memset(&resp_msg_dummy, 0, sizeof(resp_msg_dummy));
	} else {
		tx_alloc = ath10k_htc_get_credit_allocation(target,
							    connect_req->service_id);
		if (!tx_alloc)
			ath10k_warn("Service 0x%x does not"
				    " allocate target credits\n",
				    connect_req->service_id);

		skb = ath10k_htc_build_tx_ctrl_skb(target->ar);
		if (!skb) {
			ath10k_err("Failed to allocate HTC packet\n");
			return -ENOMEM;
		}

		length = sizeof(msg->hdr) + sizeof(msg->connect_service);
		skb_put(skb, length);
		memset(skb->data, 0, length);

		msg = (struct htc_msg *)skb->data;
		msg->hdr.message_id = __cpu_to_le16(HTC_MSG_CONNECT_SERVICE_ID);

		flags |= SM(tx_alloc, HTC_CONNECT_FLAGS_RECV_ALLOC);

		req_msg = &msg->connect_service;
		req_msg->flags = __cpu_to_le16(flags);
		req_msg->service_id = __cpu_to_le16(connect_req->service_id);

		/* Only enable credit flow control for WMI ctrl service */
		if (connect_req->service_id != HTC_SVC_WMI_CONTROL) {
			flags |= HTC_CONNECT_FLAGS_DISABLE_CREDIT_FLOW_CTRL;
			disable_credit_flow_ctrl = true;
		}

		skb_cb = ATH10K_SKB_CB(skb);
		skb_cb->htc.complete = ath10k_htc_control_tx_complete;
		skb_cb->htc.priv = target;

		INIT_COMPLETION(target->ctl_resp);

		status = ath10k_htc_send(target, HTC_EP_0, skb);
		if (status)
			return status;

		/* wait for response */
		status = wait_for_completion_timeout(&target->ctl_resp,
						     HTC_CONN_SVC_TIMEOUT_HZ);
		if (status <= 0) {
			if (status == 0)
				status = -ETIMEDOUT;
			ath10k_err("Service connect timeout: %d\n", status);
			return status;
		}

		/* we controlled the buffer creation, it's aligned */
		msg = (struct htc_msg *)target->control_resp_buffer;
		resp_msg = &msg->connect_service_response;
		message_id = __le16_to_cpu(msg->hdr.message_id);
		service_id = __le16_to_cpu(resp_msg->service_id);

		if ((message_id != HTC_MSG_CONNECT_SERVICE_RESP_ID) ||
		    (target->control_resp_len < sizeof(msg->hdr) +
		     sizeof(msg->connect_service_response))) {
			ath10k_err("Invalid resp message ID 0x%x", message_id);
			return -EPROTO;
		}

		ath10k_dbg(ATH10K_DBG_HTC, "Service 0x%x connect response"
			   " from target: status: 0x%x, assigned ep: 0x%x\n",
			   service_id, resp_msg->status, resp_msg->eid);

		connect_resp->connect_resp_code = resp_msg->status;

		/* check response status */
		if (resp_msg->status != HTC_SERVICE_SUCCESS) {
			ath10k_err("Service 0x%x connect request failed"
				   " with status: 0x%x)\n",
				   service_id, resp_msg->status);
			return -EPROTO;
		}

		assigned_ep = (enum htc_endpoint_id)resp_msg->eid;
		max_msg_size = __le16_to_cpu(resp_msg->max_msg_size);
	}

	if (assigned_ep >= HTC_EP_COUNT)
		return -EPROTO;

	if (max_msg_size == 0)
		return -EPROTO;

	ep = &target->endpoint[assigned_ep];
	ep->ep_id = assigned_ep;

	if (ep->service_id != HTC_SVC_UNUSED)
		return -EPROTO;

	INIT_WORK(&ep->send_work, ath10k_htc_send_work);

	/* return assigned endpoint to caller */
	connect_resp->ep_id = assigned_ep;
	connect_resp->max_msg_len = __le16_to_cpu(resp_msg->max_msg_size);

	/* setup the endpoint */
	ep->service_id = connect_req->service_id;
	ep->max_tx_queue_depth = connect_req->max_send_queue_depth;
	ep->max_ep_message_len = __le16_to_cpu(resp_msg->max_msg_size);
	ep->tx_credits = tx_alloc;
	ep->tx_credit_size = target->target_credit_size;
	ep->tx_credits_per_max_message = ep->max_ep_message_len /
					 target->target_credit_size;

	if (ep->max_ep_message_len % target->target_credit_size)
		ep->tx_credits_per_max_message++;

	/* copy all the callbacks */
	ep->ep_callbacks = connect_req->ep_callbacks;

	status = ath10k_hif_map_service_to_pipe(target->ar,
						ep->service_id,
						&ep->ul_pipe_id,
						&ep->dl_pipe_id,
						&ep->ul_is_polled,
						&ep->dl_is_polled);
	if (status)
		return status;

	ath10k_dbg(ATH10K_DBG_HTC, "HTC service: 0x%x"
		   " UL pipe: %d DL pipe: %d ep_id: %d ready\n",
		   ep->service_id, ep->ul_pipe_id,
		   ep->dl_pipe_id, ep->ep_id);

	if (disable_credit_flow_ctrl && ep->tx_credit_flow_enabled) {
		ep->tx_credit_flow_enabled = false;
		ath10k_dbg(ATH10K_DBG_HTC, "HTC service: 0x%x ep_id: %d"
			" TX flow control disabled\n",
			ep->service_id, assigned_ep);
	}

	return status;
}

struct sk_buff *ath10k_htc_alloc_skb(int size)
{
	struct sk_buff *skb;

	skb = dev_alloc_skb(size + sizeof(struct htc_hdr));
	if (!skb) {
		ath10k_warn("could not allocate HTC tx skb\n");
		return NULL;
	}

	skb_reserve(skb, sizeof(struct htc_hdr));

	/* FW/HTC requires 4-byte aligned streams */
	WARN_ONCE((unsigned long)skb->data & 0x3, "unaligned skb");
	return skb;
}

int ath10k_htc_start(struct htc_target *target)
{
	struct ath10k_skb_cb *skb_cb;
	struct sk_buff *skb;
	int status = 0;
	struct htc_msg *msg;

	skb = ath10k_htc_build_tx_ctrl_skb(target->ar);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, sizeof(msg->hdr) + sizeof(msg->setup_complete_ext));
	memset(skb->data, 0, skb->len);

	msg = (struct htc_msg *)skb->data;
	msg->hdr.message_id = __cpu_to_le16(HTC_MSG_SETUP_COMPLETE_EX_ID);

	ath10k_dbg(ATH10K_DBG_HTC, "HTC is using TX credit flow control\n");

	skb_cb = ATH10K_SKB_CB(skb);
	skb_cb->htc.complete = ath10k_htc_control_tx_complete;
	skb_cb->htc.priv = target;
	status = ath10k_htc_send(target, HTC_EP_0, skb);

	return status;
}

/*
 * stop HTC communications, i.e. stop interrupt reception, and flush all
 * queued buffers
 */
void ath10k_htc_stop(struct htc_target *target)
{
	int i;
	struct htc_endpoint *ep;

	/* cleanup endpoints */
	for (i = HTC_EP_0; i < HTC_EP_COUNT; i++) {
		ep = &target->endpoint[i];
		ath10k_htc_flush_endpoint_tx(target, ep);
	}

	ath10k_hif_stop(target->ar);

	/* ath10k_pci_buffer_cleanup may schedule ath10k_htc_send */
	for (i = HTC_EP_0; i < HTC_EP_COUNT; i++) {
		ep = &target->endpoint[i];

		if (ep->service_id == HTC_SVC_UNUSED)
			continue;

		cancel_work_sync(&ep->send_work);
	}

	ath10k_htc_reset_endpoint_states(target);
}

/* registered target arrival callback from the HIF layer */
struct htc_target *ath10k_htc_create(struct ath10k *ar,
				     struct htc_target_cb *htc_cb)
{
	struct ath10k_hif_cb htc_callbacks;
	struct htc_endpoint *ep = NULL;
	struct htc_target *target = NULL;

	/* FIXME: use struct ath10k instead */
	target = kzalloc(sizeof(struct htc_target), GFP_KERNEL);
	if (!target) {
		ath10k_err("%s: unable to allocate memory\n", __func__);
		return NULL;
	}

	spin_lock_init(&target->htc_tx_lock);

	memcpy(&target->htc_cb, htc_cb, sizeof(struct htc_target_cb));

	ath10k_htc_reset_endpoint_states(target);

	/* setup HIF layer callbacks */
	htc_callbacks.rx_completion_handler = ath10k_htc_rx_completion_handler;
	htc_callbacks.tx_completion_handler = ath10k_htc_tx_completion_handler;
	htc_callbacks.fw_event_handler      = ath10k_htc_fw_event_handler;
	target->ar = ar;

	/* Get HIF default pipe for HTC message exchange */
	ep = &target->endpoint[HTC_EP_0];

	ath10k_hif_post_init(ar, &htc_callbacks);
	ath10k_hif_get_default_pipe(ar, &ep->ul_pipe_id, &ep->dl_pipe_id);

	init_completion(&target->ctl_resp);

	return target;
}

void ath10k_htc_destroy(struct htc_target *target)
{
	kfree(target);
}
