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

#include <linux/skbuff.h>

#include "core.h"
#include "htc.h"
#include "debug.h"
#include "wmi.h"
#include "mac.h"

struct wmi_struct {
	struct ath10k *ar;

	enum htc_endpoint_id eid;
	struct completion service_ready;
	struct completion unified_ready;
	atomic_t pending_tx_count;
	wait_queue_head_t wq;

	struct sk_buff_head wmi_event_list;
	struct work_struct wmi_event_work;
};

void wmi_flush_tx(struct ath10k *ar)
{
	struct wmi_struct *wmi = ar->modules.wmi;
	int ret;

	ret = wait_event_timeout(wmi->wq,
				 atomic_read(&wmi->pending_tx_count) == 0,
				 5*HZ);
	if (atomic_read(&wmi->pending_tx_count) == 0)
		return;

	if (ret == 0)
		ret = -ETIMEDOUT;

	WARN(ret < 0, "%s failed %d\n", __func__, ret);
}

int wmi_wait_for_service_ready(struct ath10k *ar)
{
	struct wmi_struct *wmi = ar->modules.wmi;
	int ret;
	ret = wait_for_completion_timeout(&wmi->service_ready,
					  WMI_SERVICE_READY_TIMEOUT_HZ);
	return ret;
}

int wmi_wait_for_unified_ready(struct ath10k *ar)
{
	struct wmi_struct *wmi = ar->modules.wmi;
	int ret;
	ret = wait_for_completion_timeout(&wmi->unified_ready,
					  WMI_UNIFIED_READY_TIMEOUT_HZ);
	return ret;
}

static struct sk_buff *wmi_alloc_skb(u32 len)
{
	struct sk_buff *skb;
	u32 round_len = roundup(len, 4);

	skb = ath10k_htc_alloc_skb(WMI_SKB_HEADROOM + round_len);
	if (!skb)
		return NULL;

	skb_reserve(skb, WMI_SKB_HEADROOM);
	WARN_ONCE((unsigned long)skb->data & 0x3, "unaligned skb");

	skb_put(skb, round_len);
	memset(skb->data, 0, round_len);

	return skb;
}

static void wmi_htc_tx_complete(struct sk_buff *skb)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);
	struct wmi_struct *wmi = skb_cb->htc.priv;

	dev_kfree_skb(skb);

	if (atomic_sub_return(1, &wmi->pending_tx_count) == 0)
		wake_up(&wmi->wq);
}

/* WMI command API */
static int wmi_cmd_send(struct ath10k *ar, struct sk_buff *skb,
			enum wmi_cmd_id cmd_id)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);
	struct wmi_struct *wmi = ar->modules.wmi;
	struct wmi_cmd_hdr *cmd_hdr;
	int status;

	if (skb_push(skb, sizeof(struct wmi_cmd_hdr)) == NULL) {
		ath10k_warn("%s: skb_push failed\n", __func__);
		return -ENOMEM;
	}

	cmd_hdr = (struct wmi_cmd_hdr *)skb->data;
	cmd_hdr->cmd_id = __cpu_to_le16(cmd_id);

	if (atomic_add_return(1, &wmi->pending_tx_count) >
	    WMI_MAX_PENDING_TX_COUNT) {
		/* avoid using up memory when FW hangs */
		atomic_dec(&wmi->pending_tx_count);
		ath10k_warn("%s: too many tx packets pending\n", __func__);
		return -EBUSY;
	}

	memset(skb_cb, 0, sizeof(*skb_cb));
	skb_cb->htc.complete = wmi_htc_tx_complete;
	skb_cb->htc.priv = wmi;

	trace_ath10k_wmi_cmd(cmd_id, skb->data, skb->len);

	status = ath10k_htc_send(ar->htc_handle, wmi->eid, skb);
	if (status) {
		dev_kfree_skb_any(skb);
		atomic_dec(&wmi->pending_tx_count);
		ath10k_warn("%s(): htc send failed (%d)\n", __func__, status);
	}

	return status;
}

static int wmi_event_scan(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_scan_event *event = (struct wmi_scan_event *)skb->data;
	enum wmi_scan_event_type event_type;
	enum wmi_scan_completion_reason reason;
	u32 freq;
	u32 req_id;
	u32 scan_id;
	u32 vdev_id;

	event_type = __le32_to_cpu(event->event_type);
	reason     = __le32_to_cpu(event->reason);
	freq       = __le32_to_cpu(event->channel_freq);
	req_id     = __le32_to_cpu(event->scan_req_id);
	scan_id    = __le32_to_cpu(event->scan_id);
	vdev_id    = __le32_to_cpu(event->vdev_id);

	ath10k_dbg(ATH10K_DBG_WMI, "WMI_SCAN_EVENTID\n");
	ath10k_dbg(ATH10K_DBG_WMI,
		   "scan event type %d reason %d freq %d req_id %d "
		   "scan_id %d vdev_id %d\n",
		   event_type, reason, freq, req_id, scan_id, vdev_id);

	switch (event_type) {
	case WMI_SCAN_EVENT_STARTED:
		ath10k_dbg(ATH10K_DBG_WMI, "SCAN_EVENT_STARTED\n");

		if (ar->scan.is_roc)
			ieee80211_ready_on_channel(ar->hw);

		complete(&ar->scan.started);
		break;
	case WMI_SCAN_EVENT_COMPLETED:
		ath10k_dbg(ATH10K_DBG_WMI, "SCAN_EVENT_COMPLETED\n");
		switch (reason) {
		case WMI_SCAN_REASON_COMPLETED:
			ath10k_dbg(ATH10K_DBG_WMI, "SCAN_REASON_COMPLETED\n");
			break;
		case WMI_SCAN_REASON_CANCELLED:
			ath10k_dbg(ATH10K_DBG_WMI, "SCAN_REASON_CANCELED\n");
			break;
		case WMI_SCAN_REASON_PREEMPTED:
			ath10k_dbg(ATH10K_DBG_WMI, "SCAN_REASON_PREEMPTED\n");
			break;
		case WMI_SCAN_REASON_TIMEDOUT:
			ath10k_dbg(ATH10K_DBG_WMI, "SCAN_REASON_TIMEDOUT\n");
			break;
		default:
			break;
		}

		rcu_assign_pointer(ar->scan_channel, NULL);

		spin_lock_bh(&ar->scan.lock);
		if (!ar->scan.in_progress) {
			ath10k_warn("no scan requested, ignoring\n");
			spin_unlock_bh(&ar->scan.lock);
			break;
		}

		if (ar->scan.is_roc) {
			ath10k_offchan_tx_purge(ar);

			if (!ar->scan.aborting)
				ieee80211_remain_on_channel_expired(ar->hw);
		} else {
			ieee80211_scan_completed(ar->hw, ar->scan.aborting);
		}

		del_timer(&ar->scan.timeout);
		complete_all(&ar->scan.completed);
		ar->scan.in_progress = false;
		spin_unlock_bh(&ar->scan.lock);
		break;
	case WMI_SCAN_EVENT_BSS_CHANNEL:
		ath10k_dbg(ATH10K_DBG_WMI, "SCAN_EVENT_BSS_CHANNEL\n");
		rcu_assign_pointer(ar->scan_channel, NULL);
		break;
	case WMI_SCAN_EVENT_FOREIGN_CHANNEL:
		ath10k_dbg(ATH10K_DBG_WMI, "SCAN_EVENT_FOREIGN_CHANNEL\n");
		rcu_assign_pointer(ar->scan_channel,
				   ieee80211_get_channel(ar->hw->wiphy, freq));
		break;
	case WMI_SCAN_EVENT_DEQUEUED:
		ath10k_dbg(ATH10K_DBG_WMI, "SCAN_EVENT_DEQUEUED\n");
		break;
	case WMI_SCAN_EVENT_PREEMPTED:
		ath10k_dbg(ATH10K_DBG_WMI, "WMI_SCAN_EVENT_PREEMPTED\n");
		break;
	case WMI_SCAN_EVENT_START_FAILED:
		ath10k_dbg(ATH10K_DBG_WMI, "WMI_SCAN_EVENT_START_FAILED\n");
		break;
	default:
		break;
	}

	return 0;
}

static int wmi_event_mgmt_rx(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_mgmt_rx_event *event = (void *)skb->data;
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_hdr *hdr;
	u32 rx_status;
	u32 channel;
	u32 snr;
	u32 buf_len;
	u16 fc;

	channel   = __le32_to_cpu(event->hdr.channel);
	buf_len   = __le32_to_cpu(event->hdr.buf_len);
	rx_status = __le32_to_cpu(event->hdr.status);
	snr       = __le32_to_cpu(event->hdr.snr);

	memset(status, 0, sizeof(*status));

	ath10k_dbg(ATH10K_DBG_WMI, "event mgmt rx status %08x\n", rx_status);

	if (rx_status & WMI_RX_STATUS_ERR_DECRYPT) {
		dev_kfree_skb(skb);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_KEY_CACHE_MISS) {
		dev_kfree_skb(skb);
		return 0;
	}

	if (rx_status & WMI_RX_STATUS_ERR_CRC)
		status->flag |= RX_FLAG_FAILED_FCS_CRC;
	if (rx_status & WMI_RX_STATUS_ERR_MIC)
		status->flag |= RX_FLAG_MMIC_ERROR;

	/* FIXME: We probably should use event->phy_mode for that */
	if (channel > 14)
		status->band = IEEE80211_BAND_5GHZ;
	else
		status->band = IEEE80211_BAND_2GHZ;

	status->freq = ieee80211_channel_to_frequency(channel, status->band);
	status->signal = snr + ATH10K_DEFAULT_NOISE_FLOOR;

	skb_pull(skb, sizeof(event->hdr));

	hdr = (struct ieee80211_hdr *)skb->data;
	fc = le16_to_cpu(hdr->frame_control);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "event mgmt rx skb %p len %d ftype %02x stype %02x\n",
		   skb, skb->len,
		   fc & IEEE80211_FCTL_FTYPE, fc & IEEE80211_FCTL_STYPE);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "event mgmt rx freq %d band %d snr %d\n",
		   status->freq, status->band, status->signal);

	/*
	 * packets from HTC come aligned to 4byte boundaries
	 * because they can originally come in along with a trailer
	 */
	skb_trim(skb, buf_len);

	ieee80211_rx_irqsafe(ar->hw, skb);
	return 0;
}

static void wmi_event_chan_info(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_CHAN_INFO_EVENTID\n");
}

static void wmi_event_echo(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_ECHO_EVENTID\n");
}

static void wmi_event_debug_mesg(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_DEBUG_MESG_EVENTID\n");
}

static void wmi_event_update_stats(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_stats_event *ev = (void *)skb->data;

	ath10k_dbg(ATH10K_DBG_WMI, "WMI_UPDATE_STATS_EVENTID\n");

	ath10k_debug_read_target_stats(ar, ev);
}

static void wmi_event_vdev_start_resp(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_vdev_start_response_event *ev = (void *)skb->data;

	ath10k_dbg(ATH10K_DBG_WMI, "WMI_VDEV_START_RESP_EVENTID\n");

	if (WARN_ON(__le32_to_cpu(ev->status)))
		return;

	complete(&ar->vdev_setup_done);
}

static void wmi_event_vdev_standby_req(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_VDEV_STANDBY_REQ_EVENTID\n");
}

static void wmi_event_vdev_resume_req(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_VDEV_RESUME_REQ_EVENTID\n");
}

static void wmi_event_vdev_stopped(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_VDEV_STOPPED_EVENTID\n");
	complete(&ar->vdev_setup_done);
}

static void wmi_event_peer_sta_kickout(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PEER_STA_KICKOUT_EVENTID\n");
}

/*
 * FIXME
 *
 * We don't report to mac80211 sleep state of connected
 * stations. Due to this mac80211 can't fill in TIM IE
 * correctly.
 *
 * I know of no way of getting nullfunc frames that contain
 * sleep transition from connected stations - these do not
 * seem to be sent from the target to the host. There also
 * doesn't seem to be a dedicated event for that. So the
 * only way left to do this would be to read tim_bitmap
 * during SWBA.
 *
 * We could probably try using tim_bitmap from SWBA to tell
 * mac80211 which stations are asleep and which are not. The
 * problem here is calling mac80211 functions so many times
 * could take too long and make us miss the time to submit
 * the beacon to the target.
 *
 * So as a workaround we try to extend the TIM IE if there
 * is unicast buffered for stations with aid > 7 and fill it
 * in ourselves.
 */
static void wmi_update_tim(struct ath10k *ar, struct ath10k_vif *arvif,
			   struct sk_buff *bcn, struct wmi_bcn_info *bcn_info)
{
	struct ieee80211_hdr *hdr = (void *)bcn->data;
	struct ieee80211_tim_ie *tim;
	u8 *ies, *ie;
	u8 ie_len, pvm_len;

	/* if next SWBA has no tim_changed the tim_bitmap is garbage.
	 * we must copy the bitmap upon change and reuse it later */
	if (__le32_to_cpu(bcn_info->tim_info.tim_changed)) {
		int i;

		BUILD_BUG_ON(sizeof(arvif->u.ap.tim_bitmap) !=
			     sizeof(bcn_info->tim_info.tim_bitmap));

		for (i = 0; i < sizeof(arvif->u.ap.tim_bitmap); i++) {
			u32 v = __le32_to_cpu(bcn_info->tim_info.tim_bitmap[i / 4]);
			arvif->u.ap.tim_bitmap[i] = (v >> ((i % 4) * 8)) & 0xFF;
		}

		/* FW reports either length 0 or 16
		 * so we calculate this on our own */
		arvif->u.ap.tim_len = 0;
		for (i = 0; i < sizeof(arvif->u.ap.tim_bitmap); i++)
			if (arvif->u.ap.tim_bitmap[i])
				arvif->u.ap.tim_len = i;

		arvif->u.ap.tim_len++;
	}

	ies = bcn->data;
	ies += ieee80211_hdrlen(hdr->frame_control);
	ies += 12; /* fixed parameters */

	ie = (u8 *)cfg80211_find_ie(WLAN_EID_TIM, ies,
				    (u8 *)skb_tail_pointer(bcn) - ies);
	if (!ie) {
		/* highly unlikely for mac80211 */
		ath10k_warn("no tim ie found;\n");
		return;
	}

	tim = (void *)ie + 2;
	ie_len = ie[1];
	pvm_len = ie_len - 3; /* exclude dtim count, dtim period, bmap ctl */

	if (pvm_len < arvif->u.ap.tim_len) {
		int expand_size = sizeof(arvif->u.ap.tim_bitmap) - pvm_len;
		int move_size = skb_tail_pointer(bcn) - (ie + 2 + ie_len);
		void *next_ie = ie + 2 + ie_len;

		if (skb_put(bcn, expand_size)) {
			memmove(next_ie + expand_size, next_ie, move_size);

			ie[1] += expand_size;
			ie_len += expand_size;
			pvm_len += expand_size;
		} else
			ath10k_warn("tim expansion failed\n");
	}

	if (pvm_len > sizeof(arvif->u.ap.tim_bitmap)) {
		ath10k_warn("tim pvm length is too great (%d)\n", pvm_len);
		return;
	}

	tim->bitmap_ctrl = !!__le32_to_cpu(bcn_info->tim_info.tim_mcast);
	memcpy(tim->virtual_map, arvif->u.ap.tim_bitmap, pvm_len);

	ath10k_dbg(ATH10K_DBG_BEACON, "dtim %d/%d mcast %d pvmlen %d\n",
		   tim->dtim_count, tim->dtim_period,
		   tim->bitmap_ctrl, pvm_len);
}

static void p2p_fill_noa_ie(u8 *data, u32 len, struct wmi_p2p_noa_info *noa)
{
	struct ath10k_p2p_noa_attr *noa_attr;
	u8  ctwindow_oppps = (u8) __le32_to_cpu(noa->opp_ps_info);
	u8 ctwindow = ctwindow_oppps >> WMI_P2P_OPPPS_CTWINDOW_OFFSET;
	bool oppps = !!(ctwindow_oppps & WMI_P2P_OPPPS_ENABLE_BIT);
	__le16 *noa_attr_len;
	u16 attr_len;
	u32 noa_descriptors = __le32_to_cpu(noa->num_descriptors);
	int i;

	/* P2P IE */
	data[0] = WLAN_EID_VENDOR_SPECIFIC;
	data[1] = len - 2;
	data[2] = (WLAN_OUI_WFA >> 16) & 0xff;
	data[3] = (WLAN_OUI_WFA >> 8) & 0xff;
	data[4] = (WLAN_OUI_WFA >> 0) & 0xff;
	data[5] = WLAN_OUI_TYPE_WFA_P2P;

	/* NOA ATTR */
	data[6] = IEEE80211_P2P_ATTR_ABSENCE_NOTICE;
	noa_attr_len = (__le16 *) &data[7]; /* 2 bytes */
	noa_attr = (struct ath10k_p2p_noa_attr *) &data[9];

	noa_attr->index = __le32_to_cpu(noa->index);
	noa_attr->oppps_ctwindow = ctwindow;
	if (oppps)
		noa_attr->oppps_ctwindow |= ATH10K_P2P_OPPPS_ENABLE_BIT;

	for (i = 0; i < noa_descriptors; i++) {
		noa_attr->desc[i].count =
			__le32_to_cpu(noa->noa_descriptors[i].type_count);
		noa_attr->desc[i].duration = noa->noa_descriptors[i].duration;
		noa_attr->desc[i].interval = noa->noa_descriptors[i].interval;
		noa_attr->desc[i].start_time =
				noa->noa_descriptors[i].start_time;
	}

	attr_len = 2; /* index + oppps_ctwindow */
	attr_len += noa_descriptors * sizeof(struct ath10k_p2p_noa_desc);
	*noa_attr_len = __cpu_to_le16(attr_len);
}

static u32 p2p_calc_noa_ie_len(struct wmi_p2p_noa_info *noa)
{
	u32 len = 0;
	u32 noa_descriptors = __le32_to_cpu(noa->num_descriptors);
	u8 opp_ps_info = (u8) __le32_to_cpu(noa->opp_ps_info);
	bool opps_enabled = !!(opp_ps_info & WMI_P2P_OPPPS_ENABLE_BIT);


	if (!noa_descriptors && !opps_enabled)
		return len;

	len += 1 + 1 + 4; /* EID + len + OUI */
	len += 1 + 2; /* noa attr  + attr len */
	len += 1 + 1; /* index + oppps_ctwindow */
	len += noa_descriptors * sizeof(struct ath10k_p2p_noa_desc);

	return len;
}

static void wmi_update_noa(struct ath10k *ar, struct ath10k_vif *arvif,
			   struct sk_buff *bcn, struct wmi_bcn_info *bcn_info)
{
	struct wmi_p2p_noa_info *noa = &bcn_info->p2p_noa_info;
	u8 *new_data, *old_data = arvif->u.ap.noa_data;
	u32 new_len;

	if (arvif->vdev_subtype != WMI_VDEV_SUBTYPE_P2P_GO)
		return;

	ath10k_dbg(ATH10K_DBG_BEACON, "noa changed: %d\n", noa->p2p_noa_changed);
	if (noa->p2p_noa_changed) {
		new_len = p2p_calc_noa_ie_len(noa);
		if (!new_len)
			goto cleanup;

		new_data = kmalloc(new_len, GFP_ATOMIC);
		if (!new_data)
			goto cleanup;

		p2p_fill_noa_ie(new_data, new_len, noa);

		spin_lock_bh(&ar->data_lock);
		arvif->u.ap.noa_data = new_data;
		arvif->u.ap.noa_len = new_len;
		spin_unlock_bh(&ar->data_lock);
		kfree(old_data);
	}

	if (arvif->u.ap.noa_data)
		if (!pskb_expand_head(bcn, 0, arvif->u.ap.noa_len, GFP_ATOMIC))
			memcpy(skb_put(bcn, arvif->u.ap.noa_len),
			       arvif->u.ap.noa_data,
			       arvif->u.ap.noa_len);
	return;

cleanup:
	spin_lock_bh(&ar->data_lock);
	arvif->u.ap.noa_data = NULL;
	arvif->u.ap.noa_len = 0;
	spin_unlock_bh(&ar->data_lock);
	kfree(old_data);
}


static void wmi_event_host_swba(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_host_swba_event *ev = (void *)skb->data;
	u32 map = __le32_to_cpu(ev->vdev_map);
	int i = -1;
	struct wmi_bcn_info *bcn_info;
	struct ath10k_vif *arvif;
	struct wmi_bcn_tx_arg arg;
	struct sk_buff *bcn;
	int vdev_id = 0;
	int ret;

	ath10k_dbg(ATH10K_DBG_BEACON, "WMI_HOST_SWBA_EVENTID\n");

	ath10k_dbg(ATH10K_DBG_BEACON, "host swba:\n"
		   "-vdev map 0x%x\n",
		   ev->vdev_map);

	for (; map; map >>= 1, vdev_id++) {
		if (!(map & 0x1))
			continue;

		i++;

		if (i >= WMI_MAX_AP_VDEV) {
			ath10k_warn("%s: incorect vdev map\n", __func__);
			break;
		}

		bcn_info = &ev->bcn_info[i];

		ath10k_dbg(ATH10K_DBG_BEACON,
			   "-bcn_info[%d]:\n"
			   "--tim_len %d\n"
			   "--tim_mcast %d\n"
			   "--tim_changed %d\n"
			   "--tim_num_ps_pending %d\n"
			   "--tim_bitmap 0x%08x%08x%08x%08x\n",
			   i,
			   __le32_to_cpu(bcn_info->tim_info.tim_len),
			   __le32_to_cpu(bcn_info->tim_info.tim_mcast),
			   __le32_to_cpu(bcn_info->tim_info.tim_changed),
			   __le32_to_cpu(bcn_info->tim_info.tim_num_ps_pending),
			   __le32_to_cpu(bcn_info->tim_info.tim_bitmap[3]),
			   __le32_to_cpu(bcn_info->tim_info.tim_bitmap[2]),
			   __le32_to_cpu(bcn_info->tim_info.tim_bitmap[1]),
			   __le32_to_cpu(bcn_info->tim_info.tim_bitmap[0]));

		arvif = ath10k_get_arvif(ar, vdev_id);
		if (arvif == NULL) {
			ath10k_warn("%s: no vif for vdev_id %d\n",
				    __func__, vdev_id);
			continue;
		}

		bcn = ieee80211_beacon_get(ar->hw, arvif->vif);
		if (!bcn) {
			ath10k_warn("could not get mac80211 beacon\n");
			continue;
		}

		ath10k_tx_h_seq_no(bcn);
		wmi_update_tim(ar, arvif, bcn, bcn_info);
		wmi_update_noa(ar, arvif, bcn, bcn_info);

		arg.vdev_id = arvif->vdev_id;
		arg.tx_rate = 0;
		arg.tx_power = 0;
		arg.bcn = bcn->data;
		arg.bcn_len = bcn->len;

		ret = wmi_beacon_send(ar, &arg);
		if (ret)
			ath10k_warn("could not send beacon (%d)\n", ret);

		dev_kfree_skb_any(bcn);
	}
}

static void wmi_event_tbttoffset_update(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_TBTTOFFSET_UPDATE_EVENTID\n");
}

static void wmi_event_phyerr(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PHYERR_EVENTID\n");
}

static void wmi_event_roam(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_ROAM_EVENTID\n");
}

static void wmi_event_profile_match(struct ath10k *ar,
				    struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PROFILE_MATCH\n");
}

static void wmi_event_debug_print(struct ath10k *ar,
				  struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_DEBUG_PRINT_EVENTID\n");
}

static void wmi_event_pdev_qvit(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PDEV_QVIT_EVENTID\n");
}

static void wmi_event_wlan_profile_data(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_WLAN_PROFILE_DATA_EVENTID\n");
}

static void wmi_event_rtt_measurement_report(struct ath10k *ar,
					     struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_RTT_MEASUREMENT_REPORT_EVENTID\n");
}

static void wmi_event_tsf_measurement_report(struct ath10k *ar,
					     struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_TSF_MEASUREMENT_REPORT_EVENTID\n");
}

static void wmi_event_rtt_error_report(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_RTT_ERROR_REPORT_EVENTID\n");
}

static void wmi_event_wow_wakeup_host(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_WOW_WAKEUP_HOST_EVENTID\n");
}

static void wmi_event_dcs_interference(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_DCS_INTERFERENCE_EVENTID\n");
}

static void wmi_event_pdev_tpc_config(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PDEV_TPC_CONFIG_EVENTID\n");
}

static void wmi_event_pdev_ftm_intg(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_PDEV_FTM_INTG_EVENTID\n");
}

static void wmi_event_gtk_offload_status(struct ath10k *ar,
					 struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_GTK_OFFLOAD_STATUS_EVENTID\n");
}

static void wmi_event_gtk_rekey_fail(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_GTK_REKEY_FAIL_EVENTID\n");
}

static void wmi_event_delba_complete(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_TX_DELBA_COMPLETE_EVENTID\n");
}

static void wmi_event_addba_complete(struct ath10k *ar, struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_TX_ADDBA_COMPLETE_EVENTID\n");
}

static void wmi_event_vdev_install_key_complete(struct ath10k *ar,
						struct sk_buff *skb)
{
	ath10k_dbg(ATH10K_DBG_WMI, "WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID\n");
}

static void wmi_service_ready_event_rx(struct ath10k *ar, struct sk_buff *skb)
{
	struct ath_common *common = ath10k_common(ar);
	struct wmi_struct *wmi = ar->modules.wmi;
	struct wmi_service_ready_event *ev = (void *)skb->data;

	if (skb->len < sizeof(*ev)) {
		ath10k_warn("Service ready event was %d B but expected %zu B. Wrong firmware version?\n",
			    skb->len, sizeof(*ev));
		return;
	}

	ar->hw_min_tx_power = __le32_to_cpu(ev->hw_min_tx_power);
	ar->hw_max_tx_power = __le32_to_cpu(ev->hw_max_tx_power);
	ar->ht_cap_info = __le32_to_cpu(ev->ht_cap_info);
	ar->vht_cap_info = __le32_to_cpu(ev->vht_cap_info);
	ar->fw_version_major = (__le32_to_cpu(ev->sw_version) & 0xff000000) >> 24;
	ar->fw_version_minor = (__le32_to_cpu(ev->sw_version) & 0x00ffffff);
	ar->fw_version_release = (__le32_to_cpu(ev->sw_version_1) & 0xffff0000) >> 16;
	ar->fw_version_build = (__le32_to_cpu(ev->sw_version_1) & 0x0000ffff);
	ar->phy_capability = __le32_to_cpu(ev->phy_capability);

	common->regulatory.current_rd = __le32_to_cpu(ev->hal_reg_capabilities.eeprom_rd);

	ath10k_debug_read_service_map(ar, ev->wmi_service_bitmap,
				      sizeof(ev->wmi_service_bitmap));

	if (strlen(ar->hw->wiphy->fw_version) == 0) {
		snprintf(ar->hw->wiphy->fw_version,
			 sizeof(ar->hw->wiphy->fw_version),
			 "%u.%u.%u.%u",
			 ar->fw_version_major,
			 ar->fw_version_minor,
			 ar->fw_version_release,
			 ar->fw_version_build);
	}

	/* FIXME: it probably should be better to support this */
	if (__le32_to_cpu(ev->num_mem_reqs) > 0) {
		ath10k_warn("target requested %d memory chunks; ignoring\n",
			    __le32_to_cpu(ev->num_mem_reqs));
	}

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi event service ready sw_ver 0x%08x sw_ver1 0x%08x abi_ver %u phy_cap 0x%08x ht_cap 0x%08x vht_cap 0x%08x vht_supp_msc 0x%08x sys_cap_info 0x%08x mem_reqs %u\n",
		   __le32_to_cpu(ev->sw_version),
		   __le32_to_cpu(ev->sw_version_1),
		   __le32_to_cpu(ev->abi_version),
		   __le32_to_cpu(ev->phy_capability),
		   __le32_to_cpu(ev->ht_cap_info),
		   __le32_to_cpu(ev->vht_cap_info),
		   __le32_to_cpu(ev->vht_supp_mcs),
		   __le32_to_cpu(ev->sys_cap_info),
		   __le32_to_cpu(ev->num_mem_reqs));

	complete(&wmi->service_ready);
}

static int wmi_ready_event_rx(struct ath10k *ar, struct sk_buff *skb)
{
	struct wmi_ready_event *ev = (void *)skb->data;
	struct wmi_struct *wmi = ar->modules.wmi;

	if (WARN_ON(skb->len < sizeof(*ev)))
		return -EINVAL;

	memcpy(ar->mac_addr, ev->mac_addr.addr, ETH_ALEN);

	/* FIXME: FW should report possible addresses we can use. This is a
	 *        development workaround. wpa_supplicant generates addresses
	 *        that do not work with the FW without this. Once this is
	 *        submitted upstream we should either get rid of this either by
	 *        reducing functionality or forcing FW team to take action. */
	memcpy(ar->hw->wiphy->perm_addr, ev->mac_addr.addr, ETH_ALEN);
	memcpy(ar->hw->wiphy->addr_mask, "\x00\x00\x00\xFF\xFF\xFF", ETH_ALEN);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi event ready sw_version %u abi_version %u mac_addr %pM status %d\n",
		   __le32_to_cpu(ev->sw_version),
		   __le32_to_cpu(ev->abi_version),
		   ev->mac_addr.addr,
		   __le32_to_cpu(ev->status));

	complete(&wmi->unified_ready);
	return 0;
}

static void wmi_event_process(struct wmi_struct *wmi, struct sk_buff *skb)
{
	struct ath10k *ar = wmi->ar;
	struct wmi_cmd_hdr *cmd_hdr;
	u16 id;
	u8 *event;
	u16 len;

	cmd_hdr = (struct wmi_cmd_hdr *)skb->data;
	id = __le16_to_cpu(cmd_hdr->cmd_id);

	if (skb_pull(skb, sizeof(struct wmi_cmd_hdr)) == NULL)
		return;

	event = skb->data;
	len = skb->len;

	trace_ath10k_wmi_event(id, skb->data, skb->len);

	switch (id) {
	case WMI_MGMT_RX_EVENTID:
		wmi_event_mgmt_rx(ar, skb);
		/* mgmt_rx() owns the skb now! */
		return;
	case WMI_SCAN_EVENTID:
		wmi_event_scan(ar, skb);
		break;
	case WMI_CHAN_INFO_EVENTID:
		wmi_event_chan_info(ar, skb);
		break;
	case WMI_ECHO_EVENTID:
		wmi_event_echo(ar, skb);
		break;
	case WMI_DEBUG_MESG_EVENTID:
		wmi_event_debug_mesg(ar, skb);
		break;
	case WMI_UPDATE_STATS_EVENTID:
		wmi_event_update_stats(ar, skb);
		break;
	case WMI_VDEV_START_RESP_EVENTID:
		wmi_event_vdev_start_resp(ar, skb);
		break;
	case WMI_VDEV_STANDBY_REQ_EVENTID:
		wmi_event_vdev_standby_req(ar, skb);
		break;
	case WMI_VDEV_RESUME_REQ_EVENTID:
		wmi_event_vdev_resume_req(ar, skb);
		break;
	case WMI_VDEV_STOPPED_EVENTID:
		wmi_event_vdev_stopped(ar, skb);
		break;
	case WMI_PEER_STA_KICKOUT_EVENTID:
		wmi_event_peer_sta_kickout(ar, skb);
		break;
	case WMI_HOST_SWBA_EVENTID:
		wmi_event_host_swba(ar, skb);
		break;
	case WMI_TBTTOFFSET_UPDATE_EVENTID:
		wmi_event_tbttoffset_update(ar, skb);
		break;
	case WMI_PHYERR_EVENTID:
		wmi_event_phyerr(ar, skb);
		break;
	case WMI_ROAM_EVENTID:
		wmi_event_roam(ar, skb);
		break;
	case WMI_PROFILE_MATCH:
		wmi_event_profile_match(ar, skb);
		break;
	case WMI_DEBUG_PRINT_EVENTID:
		wmi_event_debug_print(ar, skb);
		break;
	case WMI_PDEV_QVIT_EVENTID:
		wmi_event_pdev_qvit(ar, skb);
		break;
	case WMI_WLAN_PROFILE_DATA_EVENTID:
		wmi_event_wlan_profile_data(ar, skb);
		break;
	case WMI_RTT_MEASUREMENT_REPORT_EVENTID:
		wmi_event_rtt_measurement_report(ar, skb);
		break;
	case WMI_TSF_MEASUREMENT_REPORT_EVENTID:
		wmi_event_tsf_measurement_report(ar, skb);
		break;
	case WMI_RTT_ERROR_REPORT_EVENTID:
		wmi_event_rtt_error_report(ar, skb);
		break;
	case WMI_WOW_WAKEUP_HOST_EVENTID:
		wmi_event_wow_wakeup_host(ar, skb);
		break;
	case WMI_DCS_INTERFERENCE_EVENTID:
		wmi_event_dcs_interference(ar, skb);
		break;
	case WMI_PDEV_TPC_CONFIG_EVENTID:
		wmi_event_pdev_tpc_config(ar, skb);
		break;
	case WMI_PDEV_FTM_INTG_EVENTID:
		wmi_event_pdev_ftm_intg(ar, skb);
		break;
	case WMI_GTK_OFFLOAD_STATUS_EVENTID:
		wmi_event_gtk_offload_status(ar, skb);
		break;
	case WMI_GTK_REKEY_FAIL_EVENTID:
		wmi_event_gtk_rekey_fail(ar, skb);
		break;
	case WMI_TX_DELBA_COMPLETE_EVENTID:
		wmi_event_delba_complete(ar, skb);
		break;
	case WMI_TX_ADDBA_COMPLETE_EVENTID:
		wmi_event_addba_complete(ar, skb);
		break;
	case WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID:
		wmi_event_vdev_install_key_complete(ar, skb);
		break;
	case WMI_SERVICE_READY_EVENTID:
		wmi_service_ready_event_rx(ar, skb);
		break;
	case WMI_READY_EVENTID:
		wmi_ready_event_rx(ar, skb);
		break;
	default:
		ath10k_warn("Unknown eventid: %d\n", id);
		break;
	}

	dev_kfree_skb(skb);
}

static void wmi_event_work(struct work_struct *work)
{
	struct wmi_struct *wmi = container_of(work, struct wmi_struct,
					      wmi_event_work);
	struct sk_buff *skb;

	for (;;) {
		skb = skb_dequeue(&wmi->wmi_event_list);
		if (!skb)
			break;

		wmi_event_process(wmi, skb);
	}
}

static void wmi_process_rx(void *ptr, struct sk_buff *skb)
{
	struct wmi_struct *wmi = ptr;
	struct wmi_cmd_hdr *cmd_hdr = (struct wmi_cmd_hdr *)skb->data;
	enum wmi_event_id event_id = __le16_to_cpu(cmd_hdr->cmd_id);

	if (!skb) {
		ath10k_warn("%s: missing skb\n", __func__);
		return;
	}

	/* some events require to be handled ASAP
	 * thus can't be defered to a worker thread */
	switch (event_id) {
	case WMI_HOST_SWBA_EVENTID:
		wmi_event_process(wmi, skb);
		return;
	default:
		break;
	}

	skb_queue_tail(&wmi->wmi_event_list, skb);
	queue_work(wmi->ar->workqueue, &wmi->wmi_event_work);
}

/* WMI Initialization functions */
int wmi_attach(struct ath10k *ar)
{
	struct wmi_struct *wmi;

	wmi = kzalloc(sizeof(*wmi), GFP_KERNEL);
	if (!wmi)
		return -ENOMEM;

	wmi->ar = ar;
	init_completion(&wmi->service_ready);
	init_completion(&wmi->unified_ready);
	init_waitqueue_head(&wmi->wq);

	skb_queue_head_init(&wmi->wmi_event_list);
	INIT_WORK(&wmi->wmi_event_work, wmi_event_work);

	ar->modules.wmi = wmi;
	return 0;
}

void wmi_detach(struct ath10k *ar)
{
	struct wmi_struct *wmi = ar->modules.wmi;
	struct sk_buff *skb;

	/* HTC should've drained the packets already */
	if (WARN_ON(atomic_read(&wmi->pending_tx_count) > 0))
		ath10k_warn("there are still pending packets\n");

	cancel_work_sync(&wmi->wmi_event_work);

	for (;;) {
		skb = skb_dequeue(&wmi->wmi_event_list);
		if (!skb)
			break;

		dev_kfree_skb_any(skb);
	}

	kfree(ar->modules.wmi);
}

int wmi_connect_htc_service(struct ath10k *ar)
{
	int status;
	struct htc_service_connect_req connect;
	struct htc_service_connect_resp response;
	struct wmi_struct *wmi = ar->modules.wmi;

	memset(&connect, 0, sizeof(connect));
	memset(&response, 0, sizeof(response));

	/* these fields are the same for all service endpoints */
	connect.ep_callbacks.context = wmi;
	connect.ep_callbacks.ep_rx_complete = wmi_process_rx;

	/* connect to control service */
	connect.service_id = HTC_SVC_WMI_CONTROL;

	status = ath10k_htc_connect_service(ar->htc_handle, &connect, &response);
	if (status) {
		ath10k_warn("failed to connect to WMI CONTROL"
			    " service status: %d\n", status);
		return status;
	}

	wmi->eid = response.ep_id;

	return 0;
}

int wmi_pdev_set_regdomain(struct ath10k *ar)
{
	struct wmi_pdev_set_regdomain_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;

	/* FIXME: do not use hardcoded values */
	/* TODO: provide correct values for reg domain */
	cmd->reg_domain                = __cpu_to_le32(0x3a); /* FCC3_FCCA */
	cmd->reg_domain_2G             = __cpu_to_le32(0x0a10); /* FCCA */
	cmd->reg_domain_5G             = __cpu_to_le32(0x160); /* FCC3 */
	cmd->conformance_test_limit_2G = __cpu_to_le32(0x12); /* FCC4-FCCA */
	cmd->conformance_test_limit_5G = __cpu_to_le32(0x10); /* FCC1-FCCA */

	return wmi_cmd_send(ar, skb, WMI_PDEV_SET_REGDOMAIN_CMDID);
}

int wmi_pdev_set_channel(struct ath10k *ar, const struct wmi_channel_arg *arg)
{
	struct wmi_set_channel_cmd *cmd;
	struct sk_buff *skb;

	if (arg->passive)
		return -EINVAL;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->chan.mhz               = __cpu_to_le32(arg->freq);
	cmd->chan.band_center_freq1 = __cpu_to_le32(arg->freq);
	cmd->chan.mode              = arg->mode;
	cmd->chan.min_power         = arg->min_power;
	cmd->chan.max_power         = arg->max_power;
	cmd->chan.reg_power         = arg->max_reg_power;
	cmd->chan.reg_classid       = arg->reg_class_id;
	cmd->chan.antenna_max       = arg->max_antenna_gain;

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi set channel mode %d freq %d\n",
		   arg->mode, arg->freq);

	return wmi_cmd_send(ar, skb, WMI_PDEV_SET_CHANNEL_CMDID);
}

#if defined(CONFIG_PM_SLEEP)
int wmi_pdev_suspend_target(struct ath10k *ar)
{
	struct wmi_pdev_suspend_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->suspend_opt = WMI_PDEV_SUSPEND;

	ath10k_dbg(ATH10K_DBG_WMI, "%s: called", __func__);

	return wmi_cmd_send(ar, skb, WMI_PDEV_SUSPEND_CMDID);
}
EXPORT_SYMBOL(wmi_pdev_suspend_target);


int wmi_pdev_resume_target(struct ath10k *ar)
{
	struct sk_buff *skb;

	ath10k_dbg(ATH10K_DBG_WMI, "%s: called", __func__);

	skb = wmi_alloc_skb(0);
	if (skb == NULL) {
		ath10k_warn("%s: wmi_alloc_skb() failed\n", __func__);
		return -ENOMEM;
	}

	return wmi_cmd_send(ar, skb, WMI_PDEV_RESUME_CMDID);
}
EXPORT_SYMBOL(wmi_pdev_resume_target);
#endif /* CONFIG_PM_SLEEP */

int wmi_pdev_set_param(struct ath10k *ar, enum wmi_pdev_param id, u32 value)
{
	struct wmi_pdev_set_param_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->param_id    = __cpu_to_le32(id);
	cmd->param_value = __cpu_to_le32(value);

	ath10k_dbg(ATH10K_DBG_WMI, "wmi pdev set param %d value %d\n",
		   id, value);
	return wmi_cmd_send(ar, skb, WMI_PDEV_SET_PARAM_CMDID);
}

int wmi_cmd_init(struct ath10k *ar)
{
	struct wmi_init_cmd *cmd;
	struct sk_buff *buf;
	struct wmi_resource_config config = {
		__cpu_to_le32(TARGET_NUM_VDEV),
		/* reserve an additional peer for each VDEV */
		__cpu_to_le32(TARGET_NUM_PEERS + TARGET_NUM_VDEV),
		__cpu_to_le32(TARGET_NUM_OFFLOAD_PEERS),
		__cpu_to_le32(TARGET_NUM_PEER_KEYS),
		__cpu_to_le32(TARGET_NUM_TIDS),
		__cpu_to_le32(TARGET_AST_SKID_LIMIT),
		__cpu_to_le32(TARGET_TX_CHAIN_MASK),
		__cpu_to_le32(TARGET_RX_CHAIN_MASK),
		{
			__cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI),
			__cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI),
			__cpu_to_le32(TARGET_RX_TIMEOUT_LO_PRI),
			__cpu_to_le32(TARGET_RX_TIMEOUT_HI_PRI)
		},
		__cpu_to_le32(TARGET_RX_DECAP_MODE),
		__cpu_to_le32(TARGET_SCAN_MAX_REQS),
		__cpu_to_le32(TARGET_BMISS_OFFLOAD_MAX_VDEV),
		__cpu_to_le32(TARGET_ROAM_OFFLOAD_MAX_VDEV),
		__cpu_to_le32(TARGET_ROAM_OFFLOAD_MAX_PROFILES),
		__cpu_to_le32(TARGET_NUM_MCAST_GROUPS),
		__cpu_to_le32(TARGET_NUM_MCAST_TABLE_ELEMS),
		__cpu_to_le32(TARGET_MCAST2UCAST_MODE),
		__cpu_to_le32(TARGET_TX_DBG_LOG_SIZE),
		__cpu_to_le32(TARGET_WDS_ENTRIES),
		__cpu_to_le32(TARGET_DMA_BURST_SIZE),
		__cpu_to_le32(TARGET_MAC_AGGR_DELIM),
		__cpu_to_le32(TARGET_RX_SKIP_DEFRAG_TIMEOUT_DUP_DETECTION_CHECK),
		__cpu_to_le32(TARGET_VOW_CONFIG),
		__cpu_to_le32(TARGET_GTK_OFFLOAD_MAX_VDEV),
		__cpu_to_le32(TARGET_NUM_MSDU_DESC)
	};

	buf = wmi_alloc_skb(sizeof(*cmd));
	if (!buf)
		return -ENOMEM;

	cmd = (struct wmi_init_cmd *)buf->data;
	cmd->num_host_mem_chunks = 0;
	memcpy(&cmd->resource_config, &config, sizeof(config));

	ath10k_dbg(ATH10K_DBG_WMI, "wmi init\n");
	return wmi_cmd_send(ar, buf, WMI_INIT_CMDID);
}

static int wmi_start_scan_calc_len(const struct wmi_start_scan_arg *arg)
{
	int len;

	len = sizeof(struct wmi_start_scan_cmd);

	if (arg->ie_len) {
		if (!arg->ie)
			return -EINVAL;
		if (arg->ie_len > WLAN_SCAN_PARAMS_MAX_IE_LEN)
			return -EINVAL;

		len += sizeof(struct wmi_ie_data);
		len += roundup(arg->ie_len, 4);
	}

	if (arg->n_channels) {
		if (!arg->channels)
			return -EINVAL;
		if (arg->n_channels > ARRAY_SIZE(arg->channels))
			return -EINVAL;

		len += sizeof(struct wmi_chan_list);
		len += sizeof(__le32) * arg->n_channels;
	}

	if (arg->n_ssids) {
		if (!arg->ssids)
			return -EINVAL;
		if (arg->n_ssids > WLAN_SCAN_PARAMS_MAX_SSID)
			return -EINVAL;

		len += sizeof(struct wmi_ssid_list);
		len += sizeof(struct wmi_ssid) * arg->n_ssids;
	}

	if (arg->n_bssids) {
		if (!arg->bssids)
			return -EINVAL;
		if (arg->n_bssids > WLAN_SCAN_PARAMS_MAX_BSSID)
			return -EINVAL;

		len += sizeof(struct wmi_bssid_list);
		len += sizeof(struct wmi_mac_addr) * arg->n_bssids;
	}

	return len;
}

int wmi_start_scan(struct ath10k *ar, const struct wmi_start_scan_arg *arg)
{
	struct wmi_start_scan_cmd *cmd;
	struct sk_buff *skb;
	struct wmi_ie_data *ie;
	struct wmi_chan_list *channels;
	struct wmi_ssid_list *ssids;
	struct wmi_bssid_list *bssids;
	u32 scan_id;
	u32 scan_req_id;
	int off;
	int len = 0;
	int i;

	len = wmi_start_scan_calc_len(arg);
	if (len < 0)
		return len; /* len contains error code here */

	skb = wmi_alloc_skb(len);
	if (!skb)
		return -ENOMEM;

	scan_id  = WMI_HOST_SCAN_REQ_ID_PREFIX;
	scan_id |= arg->scan_id;

	scan_req_id  = WMI_HOST_SCAN_REQUESTOR_ID_PREFIX;
	scan_req_id |= arg->scan_req_id;

	cmd = (void *)skb->data;
	cmd->scan_id            = __cpu_to_le32(scan_id);
	cmd->scan_req_id        = __cpu_to_le32(scan_req_id);
	cmd->vdev_id            = __cpu_to_le32(arg->vdev_id);
	cmd->scan_priority      = __cpu_to_le32(arg->scan_priority);
	cmd->notify_scan_events = __cpu_to_le32(arg->notify_scan_events);
	cmd->dwell_time_active  = __cpu_to_le32(arg->dwell_time_active);
	cmd->dwell_time_passive = __cpu_to_le32(arg->dwell_time_passive);
	cmd->min_rest_time      = __cpu_to_le32(arg->min_rest_time);
	cmd->max_rest_time      = __cpu_to_le32(arg->max_rest_time);
	cmd->repeat_probe_time  = __cpu_to_le32(arg->repeat_probe_time);
	cmd->probe_spacing_time = __cpu_to_le32(arg->probe_spacing_time);
	cmd->idle_time          = __cpu_to_le32(arg->idle_time);
	cmd->max_scan_time      = __cpu_to_le32(arg->max_scan_time);
	cmd->probe_delay        = __cpu_to_le32(arg->probe_delay);
	cmd->scan_ctrl_flags    = __cpu_to_le32(arg->scan_ctrl_flags);

	/* TLV list starts after fields included in the struct */
	off = sizeof(*cmd);

	if (arg->n_channels) {
		channels = (void *)skb->data + off;
		channels->tag = __cpu_to_le32(WMI_CHAN_LIST_TAG);
		channels->num_chan = __cpu_to_le32(arg->n_channels);

		for (i = 0; i < arg->n_channels; i++)
			channels->channel_list[i] = __cpu_to_le32(arg->channels[i]);

		off += sizeof(*channels);
		off += sizeof(__le32) * arg->n_channels;
	}

	if (arg->n_ssids) {
		ssids = (void *)skb->data + off;
		ssids->tag = __cpu_to_le32(WMI_SSID_LIST_TAG);
		ssids->num_ssids = __cpu_to_le32(arg->n_ssids);

		for (i = 0; i < arg->n_ssids; i++) {
			ssids->ssids[i].ssid_len = __cpu_to_le32(arg->ssids[i].len);
			memcpy(&ssids->ssids[i].ssid, arg->ssids[i].ssid, arg->ssids[i].len);
		}

		off += sizeof(*ssids);
		off += sizeof(struct wmi_ssid) * arg->n_ssids;
	}

	if (arg->n_bssids) {
		bssids = (void *)skb->data + off;
		bssids->tag = __cpu_to_le32(WMI_BSSID_LIST_TAG);
		bssids->num_bssid = __cpu_to_le32(arg->n_bssids);

		for (i = 0; i < arg->n_bssids; i++)
			memcpy(&bssids->bssid_list[i], arg->bssids[i].bssid, ETH_ALEN);

		off += sizeof(*bssids);
		off += sizeof(struct wmi_mac_addr) * arg->n_bssids;
	}

	if (arg->ie_len) {
		ie = (void *)skb->data + off;
		ie->tag = __cpu_to_le32(WMI_IE_TAG);
		ie->ie_len = __cpu_to_le32(arg->ie_len);
		memcpy(ie->ie_data, arg->ie, arg->ie_len);

		off += sizeof(*ie);
		off += roundup(arg->ie_len, 4);
	}

	if (off != skb->len) {
		dev_kfree_skb(skb);
		return -EINVAL;
	}

	ath10k_dbg(ATH10K_DBG_WMI, "wmi start scan\n");
	return wmi_cmd_send(ar, skb, WMI_START_SCAN_CMDID);
}

void wmi_start_scan_init(struct ath10k *ar, struct wmi_start_scan_arg *arg)
{
	/* setup commonly used values */
	arg->scan_req_id = 1;
	arg->scan_priority = WMI_SCAN_PRIORITY_LOW;
	arg->dwell_time_active = 50;
	arg->dwell_time_passive = 150;
	arg->min_rest_time = 50;
	arg->max_rest_time = 500;
	arg->repeat_probe_time = 0;
	arg->probe_spacing_time = 0;
	arg->idle_time = 0;
	arg->max_scan_time = 5000;
	arg->probe_delay = 5;
	arg->notify_scan_events = WMI_SCAN_EVENT_STARTED
		| WMI_SCAN_EVENT_COMPLETED
		| WMI_SCAN_EVENT_BSS_CHANNEL
		| WMI_SCAN_EVENT_FOREIGN_CHANNEL
		| WMI_SCAN_EVENT_DEQUEUED;
	arg->scan_ctrl_flags |= WMI_SCAN_ADD_OFDM_RATES;
	arg->scan_ctrl_flags |= WMI_SCAN_CHAN_STAT_EVENT;
	arg->n_bssids = 1;
	arg->bssids[0].bssid = "\xFF\xFF\xFF\xFF\xFF\xFF";
}

int wmi_stop_scan(struct ath10k *ar, const struct wmi_stop_scan_arg *arg)
{
	struct wmi_stop_scan_cmd *cmd;
	struct sk_buff *skb;
	u32 scan_id;
	u32 req_id;

	if (arg->req_id > 0xFFF)
		return -EINVAL;
	if (arg->req_type == WMI_SCAN_STOP_ONE && arg->u.scan_id > 0xFFF)
		return -EINVAL;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	scan_id = arg->u.scan_id;
	scan_id |= WMI_HOST_SCAN_REQ_ID_PREFIX;

	req_id = arg->req_id;
	req_id |= WMI_HOST_SCAN_REQUESTOR_ID_PREFIX;

	cmd = (struct wmi_stop_scan_cmd *)skb->data;
	cmd->req_type    = __cpu_to_le32(arg->req_type);
	cmd->vdev_id     = __cpu_to_le32(arg->u.vdev_id);
	cmd->scan_id     = __cpu_to_le32(scan_id);
	cmd->scan_req_id = __cpu_to_le32(req_id);

	ath10k_dbg(ATH10K_DBG_WMI, "wmi stop scan reqid %d req_type %d "
		   "vdev/scan_id %d\n",
		   arg->req_id, arg->req_type, arg->u.scan_id);
	return wmi_cmd_send(ar, skb, WMI_STOP_SCAN_CMDID);
}

int wmi_vdev_create(struct ath10k *ar, u32 vdev_id,
		    enum wmi_vdev_type type,
		    enum wmi_vdev_subtype subtype,
		    const u8 macaddr[ETH_ALEN])
{
	struct wmi_vdev_create_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id      = __cpu_to_le32(vdev_id);
	cmd->vdev_type    = __cpu_to_le32(type);
	cmd->vdev_subtype = __cpu_to_le32(subtype);
	memcpy(cmd->vdev_macaddr.addr, macaddr, ETH_ALEN);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "WMI vdev create: id %d type %d subtype %d macaddr %pM\n",
		   vdev_id, type, subtype, macaddr);

	return wmi_cmd_send(ar, skb, WMI_VDEV_CREATE_CMDID);
}

int wmi_vdev_delete(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_delete_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "WMI vdev delete id %d\n", vdev_id);

	return wmi_cmd_send(ar, skb, WMI_VDEV_DELETE_CMDID);
}

static int wmi_vdev_start_restart(struct ath10k *ar,
				  const struct wmi_vdev_start_request_arg *arg,
				  enum wmi_cmd_id cmd_id)
{
	struct wmi_vdev_start_request_cmd *cmd;
	struct sk_buff *skb;
	const char *cmdname;
	u32 flags = 0;

	if (cmd_id != WMI_VDEV_START_REQUEST_CMDID &&
	    cmd_id != WMI_VDEV_RESTART_REQUEST_CMDID)
		return -EINVAL;
	if (WARN_ON(arg->ssid && arg->ssid_len == 0))
		return -EINVAL;
	if (WARN_ON(arg->hidden_ssid && !arg->ssid))
		return -EINVAL;
	if (WARN_ON(arg->ssid_len > sizeof(cmd->ssid.ssid)))
		return -EINVAL;

	if (cmd_id == WMI_VDEV_START_REQUEST_CMDID)
		cmdname = "start";
	else if (cmd_id == WMI_VDEV_RESTART_REQUEST_CMDID)
		cmdname = "restart";
	else
		return -EINVAL; /* should not happen, we already check cmd_id */

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	if (arg->hidden_ssid)
		flags |= WMI_VDEV_START_HIDDEN_SSID;
	if (arg->pmf_enabled)
		flags |= WMI_VDEV_START_PMF_ENABLED;

	cmd = (struct wmi_vdev_start_request_cmd *) skb->data;
	cmd->vdev_id         = __cpu_to_le32(arg->vdev_id);
	cmd->disable_hw_ack  = __cpu_to_le32(arg->disable_hw_ack);
	cmd->beacon_interval = __cpu_to_le32(arg->bcn_intval);
	cmd->dtim_period     = __cpu_to_le32(arg->dtim_period);
	cmd->flags           = __cpu_to_le32(flags);
	cmd->bcn_tx_rate     = __cpu_to_le32(arg->bcn_tx_rate);
	cmd->bcn_tx_power    = __cpu_to_le32(arg->bcn_tx_power);

	if (arg->ssid) {
		cmd->ssid.ssid_len = __cpu_to_le32(arg->ssid_len);
		memcpy(cmd->ssid.ssid, arg->ssid, arg->ssid_len);
	}

	cmd->chan.mhz               = __cpu_to_le32(arg->channel.freq);
	cmd->chan.band_center_freq1 = __cpu_to_le32(arg->channel.band_center_freq1);
	cmd->chan.mode              = arg->channel.mode;
	cmd->chan.min_power         = arg->channel.min_power;
	cmd->chan.max_power         = arg->channel.max_power;
	cmd->chan.reg_power         = arg->channel.max_reg_power;
	cmd->chan.reg_classid       = arg->channel.reg_class_id;
	cmd->chan.antenna_max       = arg->channel.max_antenna_gain;

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi vdev %s id 0x%x freq %d, mode %d, ch_flags: 0x%0X,"
		   "max_power: %d\n", cmdname, arg->vdev_id, arg->channel.freq,
		   arg->channel.mode, flags, arg->channel.max_power);

	return wmi_cmd_send(ar, skb, cmd_id);
}

int wmi_vdev_start(struct ath10k *ar,
		   const struct wmi_vdev_start_request_arg *arg)
{
	return wmi_vdev_start_restart(ar, arg, WMI_VDEV_START_REQUEST_CMDID);
}

int wmi_vdev_restart(struct ath10k *ar,
		     const struct wmi_vdev_start_request_arg *arg)
{
	return wmi_vdev_start_restart(ar, arg, WMI_VDEV_RESTART_REQUEST_CMDID);
}

int wmi_vdev_stop(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_stop_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_vdev_stop_cmd *)skb->data;
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ATH10K_DBG_WMI, "wmi vdev stop id 0x%x\n", vdev_id);

	return wmi_cmd_send(ar, skb, WMI_VDEV_STOP_CMDID);
}

int wmi_vdev_up(struct ath10k *ar, u32 vdev_id, u32 aid, const u8 *bssid)
{
	struct wmi_vdev_up_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_vdev_up_cmd *)skb->data;
	cmd->vdev_id       = __cpu_to_le32(vdev_id);
	cmd->vdev_assoc_id = __cpu_to_le32(aid);
	memcpy(&cmd->vdev_bssid.addr, bssid, 6);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi mgmt vdev up id 0x%x assoc id %d bssid %pM\n",
		   vdev_id, aid, bssid);

	return wmi_cmd_send(ar, skb, WMI_VDEV_UP_CMDID);
}

int wmi_vdev_down(struct ath10k *ar, u32 vdev_id)
{
	struct wmi_vdev_down_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_vdev_down_cmd *)skb->data;
	cmd->vdev_id = __cpu_to_le32(vdev_id);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi mgmt vdev down id 0x%x\n", vdev_id);

	return wmi_cmd_send(ar, skb, WMI_VDEV_DOWN_CMDID);
}

int wmi_vdev_set_param(struct ath10k *ar, u32 vdev_id,
		       enum wmi_vdev_param param_id, u32 param_value)
{
	struct wmi_vdev_set_param_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_vdev_set_param_cmd *)skb->data;
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(param_value);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi vdev id 0x%x set param %d value %d\n",
		   vdev_id, param_id, param_value);

	return wmi_cmd_send(ar, skb, WMI_VDEV_SET_PARAM_CMDID);
}

int wmi_vdev_install_key(struct ath10k *ar,
			 const struct wmi_vdev_install_key_arg *arg)
{
	struct wmi_vdev_install_key_cmd *cmd;
	struct sk_buff *skb;

	if (arg->key_cipher == WMI_CIPHER_NONE && arg->key_data != NULL)
		return -EINVAL;
	if (arg->key_cipher != WMI_CIPHER_NONE && arg->key_data == NULL)
		return -EINVAL;

	skb = wmi_alloc_skb(sizeof(*cmd) + arg->key_len);
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id       = __cpu_to_le32(arg->vdev_id);
	cmd->key_idx       = __cpu_to_le32(arg->key_idx);
	cmd->key_flags     = __cpu_to_le32(arg->key_flags);
	cmd->key_cipher    = __cpu_to_le32(arg->key_cipher);
	cmd->key_len       = __cpu_to_le32(arg->key_len);
	cmd->key_txmic_len = __cpu_to_le32(arg->key_txmic_len);
	cmd->key_rxmic_len = __cpu_to_le32(arg->key_rxmic_len);

	if (arg->macaddr)
		memcpy(cmd->peer_macaddr.addr, arg->macaddr, ETH_ALEN);
	if (arg->key_data)
		memcpy(cmd->key_data, arg->key_data, arg->key_len);

	return wmi_cmd_send(ar, skb, WMI_VDEV_INSTALL_KEY_CMDID);
}

int wmi_peer_create(struct ath10k *ar, u32 vdev_id,
		    const u8 peer_addr[ETH_ALEN])
{
	struct wmi_peer_create_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	memcpy(cmd->peer_macaddr.addr, peer_addr, ETH_ALEN);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi peer create vdev_id %d peer_addr %pM\n",
		   vdev_id, peer_addr);
	return wmi_cmd_send(ar, skb, WMI_PEER_CREATE_CMDID);
}

int wmi_peer_delete(struct ath10k *ar, u32 vdev_id,
		    const u8 peer_addr[ETH_ALEN])
{
	struct wmi_peer_delete_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id = __cpu_to_le32(vdev_id);
	memcpy(cmd->peer_macaddr.addr, peer_addr, ETH_ALEN);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi peer delete vdev_id %d peer_addr %pM\n",
		   vdev_id, peer_addr);
	return wmi_cmd_send(ar, skb, WMI_PEER_DELETE_CMDID);
}

int wmi_peer_flush(struct ath10k *ar, u32 vdev_id,
		   const u8 peer_addr[ETH_ALEN], u32 tid_bitmap)
{
	struct wmi_peer_flush_tids_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id         = __cpu_to_le32(vdev_id);
	cmd->peer_tid_bitmap = __cpu_to_le32(tid_bitmap);
	memcpy(cmd->peer_macaddr.addr, peer_addr, ETH_ALEN);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi peer flush vdev_id %d peer_addr %pM tids %08x\n",
		   vdev_id, peer_addr, tid_bitmap);
	return wmi_cmd_send(ar, skb, WMI_PEER_FLUSH_TIDS_CMDID);
}

int wmi_peer_set_param(struct ath10k *ar, u32 vdev_id, const u8 *peer_addr,
		       enum wmi_peer_param param_id, u32 param_value)
{
	struct wmi_peer_set_param_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_peer_set_param_cmd *) skb->data;
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(param_value);
	memcpy(&cmd->peer_macaddr.addr, peer_addr, 6);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi vdev %d peer 0x%pM set param %d value %d\n",
		   vdev_id, peer_addr, param_id, param_value);

	return wmi_cmd_send(ar, skb, WMI_PEER_SET_PARAM_CMDID);
}

int wmi_set_psmode(struct ath10k *ar, u32 vdev_id, enum wmi_sta_ps_mode psmode)
{
	struct wmi_sta_powersave_mode_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_sta_powersave_mode_cmd *) skb->data;
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->sta_ps_mode = __cpu_to_le32(psmode);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi set powersave id 0x%x mode %d\n",
		   vdev_id, psmode);

	return wmi_cmd_send(ar, skb, WMI_STA_POWERSAVE_MODE_CMDID);
}

int wmi_set_sta_ps_param(struct ath10k *ar, u32 vdev_id,
			 enum wmi_sta_powersave_param param_id, u32 value)
{
	struct wmi_sta_powersave_param_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_sta_powersave_param_cmd *) skb->data;
	cmd->vdev_id     = __cpu_to_le32(vdev_id);
	cmd->param_id    = __cpu_to_le32(param_id);
	cmd->param_value = __cpu_to_le32(value);

	ath10k_dbg(ATH10K_DBG_WMI,
		   "wmi sta ps param vdev_id 0x%x param %d value %d\n",
		   vdev_id, param_id, value);
	return wmi_cmd_send(ar, skb, WMI_STA_POWERSAVE_PARAM_CMDID);
}

int wmi_scan_chan_list(struct ath10k *ar,
		       const struct wmi_scan_chan_list_arg *arg)
{
	struct wmi_scan_chan_list_cmd *cmd;
	struct sk_buff *skb;
	struct wmi_channel_arg *ch;
	struct wmi_channel *ci;
	int len;
	int i;

	len = sizeof(*cmd) + arg->n_channels * sizeof(struct wmi_channel);

	skb = wmi_alloc_skb(len);
	if (!skb)
		return -EINVAL;

	cmd = (void *)skb->data;
	cmd->num_scan_chans = __cpu_to_le32(arg->n_channels);

	for (i = 0; i < arg->n_channels; i++) {
		u32 flags = 0;

		ch = &arg->channels[i];
		ci = &cmd->chan_info[i];

		if (ch->passive)
			flags |= WMI_CHAN_FLAG_PASSIVE;
		if (ch->allow_ibss)
			flags |= WMI_CHAN_FLAG_ADHOC_ALLOWED;
		if (ch->allow_ht)
			flags |= WMI_CHAN_FLAG_ALLOW_HT;
		if (ch->ht40plus)
			flags |= WMI_CHAN_FLAG_HT40_PLUS;

		ci->mhz               = __cpu_to_le32(ch->freq);
		ci->band_center_freq1 = __cpu_to_le32(ch->freq);
		ci->band_center_freq2 = 0;
		ci->min_power         = ch->min_power;
		ci->max_power         = ch->max_power;
		ci->reg_power         = ch->max_reg_power;
		ci->antenna_max       = ch->max_antenna_gain;
		ci->antenna_max       = 0;

		/* mode & flags share storage */
		ci->mode              = ch->mode;
		ci->flags            |= __cpu_to_le32(flags);
	}

	return wmi_cmd_send(ar, skb, WMI_SCAN_CHAN_LIST_CMDID);
}

int wmi_peer_assoc(struct ath10k *ar,
		   const struct wmi_peer_assoc_complete_arg *arg)
{
	struct wmi_peer_assoc_complete_cmd *cmd;
	struct sk_buff *skb;

	if (arg->peer_mpdu_density > 16)
		return -EINVAL;
	if (arg->peer_legacy_rates.num_rates > MAX_SUPPORTED_RATES)
		return -EINVAL;
	if (arg->peer_ht_rates.num_rates > MAX_SUPPORTED_RATES)
		return -EINVAL;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->vdev_id            = __cpu_to_le32(arg->vdev_id);
	cmd->peer_new_assoc     = __cpu_to_le32(arg->peer_reassoc ? 0 : 1);
	cmd->peer_associd       = __cpu_to_le32(arg->peer_aid);
	cmd->peer_flags         = __cpu_to_le32(arg->peer_flags);
	cmd->peer_caps          = __cpu_to_le32(arg->peer_caps);
	cmd->peer_listen_intval = __cpu_to_le32(arg->peer_listen_intval);
	cmd->peer_ht_caps       = __cpu_to_le32(arg->peer_ht_caps);
	cmd->peer_max_mpdu      = __cpu_to_le32(arg->peer_max_mpdu);
	cmd->peer_mpdu_density  = __cpu_to_le32(arg->peer_mpdu_density);
	cmd->peer_rate_caps     = __cpu_to_le32(arg->peer_rate_caps);
	cmd->peer_nss           = __cpu_to_le32(arg->peer_num_spatial_streams);
	cmd->peer_phymode       = __cpu_to_le32(arg->peer_phymode);
	/* FIXME: we dont touch VHT options */

	memcpy(cmd->peer_macaddr.addr, arg->addr, ETH_ALEN);

	cmd->peer_legacy_rates.num_rates =
		__cpu_to_le32(arg->peer_legacy_rates.num_rates);
	memcpy(cmd->peer_legacy_rates.rates, arg->peer_legacy_rates.rates,
	       arg->peer_legacy_rates.num_rates);

	cmd->peer_ht_rates.num_rates =
		__cpu_to_le32(arg->peer_ht_rates.num_rates);
	memcpy(cmd->peer_ht_rates.rates, arg->peer_ht_rates.rates,
	       arg->peer_ht_rates.num_rates);

	return wmi_cmd_send(ar, skb, WMI_PEER_ASSOC_CMDID);
}

int wmi_beacon_send(struct ath10k *ar, const struct wmi_bcn_tx_arg *arg)
{
	struct wmi_bcn_tx_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd) + arg->bcn_len);
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_bcn_tx_cmd *)skb->data;
	cmd->hdr.vdev_id  = __cpu_to_le32(arg->vdev_id);
	cmd->hdr.tx_rate  = __cpu_to_le32(arg->tx_rate);
	cmd->hdr.tx_power = __cpu_to_le32(arg->tx_power);
	cmd->hdr.bcn_len  = __cpu_to_le32(arg->bcn_len);
	memcpy(cmd->bcn, arg->bcn, arg->bcn_len);

	return wmi_cmd_send(ar, skb, WMI_BCN_TX_CMDID);
}

static void wmi_pdev_set_wmm_param(struct wmi_wmm_params *params,
				   const struct wmi_wmm_params_arg *arg)
{
	params->cwmin  = __cpu_to_le32(arg->cwmin);
	params->cwmax  = __cpu_to_le32(arg->cwmax);
	params->aifs   = __cpu_to_le32(arg->aifs);
	params->txop   = __cpu_to_le32(arg->txop);
	params->acm    = __cpu_to_le32(arg->acm);
	params->no_ack = __cpu_to_le32(arg->no_ack);
}

int wmi_pdev_set_wmm_params(struct ath10k *ar,
			    const struct wmi_pdev_set_wmm_params_arg *arg)
{
	struct wmi_pdev_set_wmm_params *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	wmi_pdev_set_wmm_param(&cmd->ac_be, &arg->ac_be);
	wmi_pdev_set_wmm_param(&cmd->ac_bk, &arg->ac_bk);
	wmi_pdev_set_wmm_param(&cmd->ac_vi, &arg->ac_vi);
	wmi_pdev_set_wmm_param(&cmd->ac_vo, &arg->ac_vo);

	ath10k_dbg(ATH10K_DBG_WMI, "wmi pdev set wmm params\n");
	return wmi_cmd_send(ar, skb, WMI_PDEV_SET_WMM_PARAMS_CMDID);
}

int wmi_request_stats(struct ath10k *ar, enum wmi_stats_id stats_id)
{
	struct wmi_request_stats_cmd *cmd;
	struct sk_buff *skb;

	skb = wmi_alloc_skb(sizeof(*cmd));
	if (!skb)
		return -ENOMEM;

	cmd = (void *)skb->data;
	cmd->stats_id = __cpu_to_le32(stats_id);

	ath10k_dbg(ATH10K_DBG_WMI, "wmi request stats %d\n", (int)stats_id);
	return wmi_cmd_send(ar, skb, WMI_REQUEST_STATS_CMDID);
}
