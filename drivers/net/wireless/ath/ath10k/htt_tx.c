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

#include <linux/etherdevice.h>
#include "htt.h"
#include "mac.h"
#include "debug.h"

static void ath10k_htt_tx_info_pool_setup(struct htt_struct *htt)
{
	int i;

	memset(htt->txi_pool, 0, sizeof(htt->txi_pool));
	for (i = 0; i < ARRAY_SIZE(htt->txi_pool); i++) {
		htt->txi_pool[i].msdu_id = i;
		htt->txi_pool[i].htt = htt;
	}
}

struct htt_tx_info *ath10k_htt_tx_info_alloc(struct htt_struct *htt)
{
	struct htt_tx_info *txi = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(htt->txi_pool); i++) {
		if (atomic_xchg(&htt->txi_pool[i].is_used, 1) == 0) {
			txi = &htt->txi_pool[i];
			break;
		}
	}

	if (txi) {
		ath10k_dbg(ATH10K_DBG_HTT, "htt txi alloc idx %d\n",
			   txi->msdu_id);

		txi->htc_tx_completed = false;
		txi->htt_tx_completed = false;

		atomic_inc(&htt->num_used_txi);
	}

	return txi;
}

void ath10k_htt_tx_info_free(struct htt_struct *htt, struct htt_tx_info *txi)
{
	int pending;

	ath10k_dbg(ATH10K_DBG_HTT, "htt txi free idx %d\n",
		   txi->msdu_id);

	WARN_ON(atomic_xchg(&txi->is_used, 0) == 0);

	pending = atomic_sub_return(1, &htt->num_used_txi);
	WARN_ON(pending < 0);
	if (pending == 0)
		wake_up(&htt->empty_tx_wq);
}

void ath10k_htt_tx_info_unref(struct htt_struct *htt, struct htt_tx_info *txi,
			      struct sk_buff *skb)
{
	/* FIXME: we have to carefully synchronize completion of htt
	 *        messages because those come in asynchronously
	 *        and not necessarily in order.
	 *        since htc_packet structure is no more this could perhaps
	 *        be reworked in a more clean manner? */
	if (!txi->htc_tx_completed)
		return;

	if (!txi->htt_tx_completed)
		return;

	dev_kfree_skb_any(skb);
	ath10k_htt_tx_info_free(htt, txi);
}

void ath10k_htt_tx_attach(struct htt_struct *htt)
{
	ath10k_htt_tx_info_pool_setup(htt);
	init_waitqueue_head(&htt->empty_tx_wq);
}

void ath10k_htt_tx_detach(struct htt_struct *htt)
{
	return;
}

struct htt_tx_info *ath10k_htt_tx_info_lookup(struct htt_struct *htt,
					      u16 msdu_id)
{
	if (WARN_ON(msdu_id >= ARRAY_SIZE(htt->txi_pool)))
		return NULL;

	if (WARN_ON(atomic_read(&htt->txi_pool[msdu_id].is_used) == 0))
		return NULL;

	return &htt->txi_pool[msdu_id];
}

void ath10k_htt_htc_tx_complete(void *context, struct sk_buff *skb)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);
	struct htt_struct *htt = (struct htt_struct *)context;
	struct device *dev = htt->ar->dev;
	struct htt_tx_info *txi;
	int ret;

	if (skb_cb->htt.is_conf) {
		dev_kfree_skb_any(skb);
		return;
	}

	txi = ath10k_htt_tx_info_lookup(htt, skb_cb->htt.msdu_id);
	if (!txi) {
		ath10k_warn("tx completion failure, wrong htt msdu_id %d\n",
			    skb_cb->htt.msdu_id);
		return;
	}

	txi->htc_tx_completed = true;

	if (skb_cb->is_aborted) {
		/*
		 * if a packet gets cancelled we need to make sure
		 * to free skbs since htt mgmt tx completion indication
		 * may have not came in yet
		 */
		if (!txi->htt_tx_completed) {
			txi->htt_tx_completed = true;

			if (txi->txfrag) {
				ret = ath10k_skb_unmap(dev, txi->txfrag);
				if (ret)
					ath10k_warn("txfrag unmap failed (%d)\n", ret);

				dev_kfree_skb_any(txi->txfrag);
			}

			ret = ath10k_skb_unmap(dev, txi->msdu);
			if (ret)
				ath10k_warn("data skb unmap failed (%d)\n", ret);

			ieee80211_free_txskb(htt->ar->hw, txi->msdu);
		}
	}

	ath10k_htt_tx_info_unref(htt, txi, skb);
}

int ath10k_htt_h2t_ver_req_msg(struct htt_struct *htt)
{
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	int len = 0;
	int ret;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->ver_req);

	skb = ath10k_htc_alloc_skb(len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);
	cmd = (struct htt_cmd *)skb->data;
	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_VERSION_REQ;

	ATH10K_SKB_CB(skb)->htt.is_conf = true;

	ret = ath10k_htc_send(htt->htc, htt->eid, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_send_rx_ring_cfg_ll(struct htt_struct *htt)
{
	struct sk_buff *skb;
	struct htt_cmd *cmd;
	struct htt_rx_ring_setup_ring *ring;
	const int num_rx_ring = 1;
	u16 flags;
	u32 fw_idx;
	int len;
	int ret;

	/*
	 * the HW expects the buffer to be an integral number of 4-byte
	 * "words"
	 */
	BUILD_BUG_ON((HTT_RX_BUF_SIZE & 0x3) != 0);
	BUILD_BUG_ON((HTT_RX_BUF_SIZE & HTT_MAX_CACHE_LINE_SIZE_MASK) != 0);

	len = sizeof(cmd->hdr) + sizeof(cmd->rx_setup.hdr)
	    + (sizeof(*ring) * num_rx_ring);
	skb = ath10k_htc_alloc_skb(len);
	if (!skb)
		return -ENOMEM;

	skb_put(skb, len);

	cmd = (struct htt_cmd *)skb->data;
	ring = &cmd->rx_setup.rings[0];

	cmd->hdr.msg_type = HTT_H2T_MSG_TYPE_RX_RING_CFG;
	cmd->rx_setup.hdr.num_rings = 1;

	/* FIXME: do we need all of this? */
	flags = 0;
	flags |= HTT_RX_RING_FLAGS_MAC80211_HDR;
	flags |= HTT_RX_RING_FLAGS_MSDU_PAYLOAD;
	flags |= HTT_RX_RING_FLAGS_PPDU_START;
	flags |= HTT_RX_RING_FLAGS_PPDU_END;
	flags |= HTT_RX_RING_FLAGS_MPDU_START;
	flags |= HTT_RX_RING_FLAGS_MPDU_END;
	flags |= HTT_RX_RING_FLAGS_MSDU_START;
	flags |= HTT_RX_RING_FLAGS_MSDU_END;
	flags |= HTT_RX_RING_FLAGS_RX_ATTENTION;
	flags |= HTT_RX_RING_FLAGS_FRAG_INFO;
	flags |= HTT_RX_RING_FLAGS_UNICAST_RX;
	flags |= HTT_RX_RING_FLAGS_MULTICAST_RX;
	flags |= HTT_RX_RING_FLAGS_CTRL_RX;
	flags |= HTT_RX_RING_FLAGS_MGMT_RX;
	flags |= HTT_RX_RING_FLAGS_NULL_RX;
	flags |= HTT_RX_RING_FLAGS_PHY_DATA_RX;

	fw_idx = __le32_to_cpu(*htt->rx_ring.alloc_idx.vaddr);

	ring->fw_idx_shadow_reg_paddr = __cpu_to_le32(htt->rx_ring.alloc_idx.paddr);
	ring->rx_ring_base_paddr      = __cpu_to_le32(htt->rx_ring.base_paddr);
	ring->rx_ring_len             = __cpu_to_le16(htt->rx_ring.size);
	ring->rx_ring_bufsize         = __cpu_to_le16(HTT_RX_BUF_SIZE);
	ring->flags                   = __cpu_to_le16(flags);
	ring->fw_idx_init_val         = __cpu_to_le16(fw_idx);
#define rx_desc_offset(x) (offsetof(struct htt_rx_desc, x) / 4)
	ring->mac80211_hdr_offset     = __cpu_to_le16(rx_desc_offset(rx_hdr_status));
	ring->msdu_payload_offset     = __cpu_to_le16(rx_desc_offset(msdu_payload));
	ring->ppdu_start_offset       = __cpu_to_le16(rx_desc_offset(ppdu_start));
	ring->ppdu_end_offset         = __cpu_to_le16(rx_desc_offset(ppdu_end));
	ring->mpdu_start_offset       = __cpu_to_le16(rx_desc_offset(mpdu_start));
	ring->mpdu_end_offset         = __cpu_to_le16(rx_desc_offset(mpdu_end));
	ring->msdu_start_offset       = __cpu_to_le16(rx_desc_offset(msdu_start));
	ring->msdu_end_offset         = __cpu_to_le16(rx_desc_offset(msdu_end));
	ring->rx_attention_offset     = __cpu_to_le16(rx_desc_offset(attention));
	ring->frag_info_offset        = __cpu_to_le16(rx_desc_offset(frag_info));
#undef rx_desc_offset

	ATH10K_SKB_CB(skb)->htt.is_conf = true;

	ret = ath10k_htc_send(htt->htc, htt->eid, skb);
	if (ret) {
		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
}

int ath10k_htt_mgmt_tx(struct htt_struct *htt, struct sk_buff *msdu)
{
	struct device *dev = htt->ar->dev;
	struct ath10k_skb_cb *skb_cb;
	struct htt_tx_info *txi;
	struct htt_cmd *cmd;
	u8 vdev_id = ATH10K_SKB_CB(msdu)->htt.vdev_id;
	int len = 0;
	int res;

	txi = ath10k_htt_tx_info_alloc(htt);
	if (!txi)
		return -ENOMEM;

	len += sizeof(cmd->hdr);
	len += sizeof(cmd->mgmt_tx);

	txi->txdesc = ath10k_htc_alloc_skb(len);
	txi->msdu = msdu;

	if (!txi->txdesc) {
		res = -ENOMEM;
		goto err;
	}

	res = ath10k_skb_map(dev, msdu);
	if (res)
		goto err;

	skb_put(txi->txdesc, len);
	cmd = (struct htt_cmd *)txi->txdesc->data;
	cmd->hdr.msg_type         = HTT_H2T_MSG_TYPE_MGMT_TX;
	cmd->mgmt_tx.msdu_paddr = __cpu_to_le32(ATH10K_SKB_CB(msdu)->paddr);
	cmd->mgmt_tx.len        = __cpu_to_le32(msdu->len);
	cmd->mgmt_tx.desc_id    = __cpu_to_le32(txi->msdu_id);
	cmd->mgmt_tx.vdev_id    = __cpu_to_le32(vdev_id);
	memcpy(cmd->mgmt_tx.hdr, msdu->data,
	       min((int)msdu->len, HTT_MGMT_FRM_HDR_DOWNLOAD_LEN));

	skb_cb = ATH10K_SKB_CB(txi->txdesc);
	skb_cb->htt.msdu_id = txi->msdu_id;

	res = ath10k_htc_send(htt->htc, htt->eid, txi->txdesc);
	if (res)
		goto err;

	return 0;

err:
	ath10k_skb_unmap(dev, msdu);

	if (txi->txdesc)
		dev_kfree_skb_any(txi->txdesc);

	ath10k_htt_tx_info_free(htt, txi);
	return res;
}

int ath10k_htt_tx(struct htt_struct *htt, struct sk_buff *msdu)
{
	struct device *dev = htt->ar->dev;
	struct htt_cmd *cmd;
	struct htt_data_tx_desc_frag *tx_frags;
	struct htt_tx_info *txi;
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)msdu->data;
	struct ath10k_skb_cb *skb_cb;
	u8 vdev_id = ATH10K_SKB_CB(msdu)->htt.vdev_id;
	u8 tid;
	int prefetch_len, desc_len, frag_len;
	dma_addr_t frags_paddr;
	int res;
	u8 flags0;
	u16 flags1;

	prefetch_len = min(htt->prefetch_len, msdu->len);
	prefetch_len = roundup(prefetch_len, 4);

	txi = ath10k_htt_tx_info_alloc(htt);
	if (!txi)
		return -ENOMEM;

	desc_len = sizeof(cmd->hdr) + sizeof(cmd->data_tx) + prefetch_len;
	frag_len = sizeof(*tx_frags) * 2;

	txi->txdesc = ath10k_htc_alloc_skb(desc_len);
	if (!txi->txdesc) {
		res = -ENOMEM;
		goto err;
	}

	txi->txfrag = dev_alloc_skb(frag_len);
	if (!txi->txfrag) {
		res = -ENOMEM;
		goto err;
	}

	txi->msdu = msdu;

	if ((unsigned long)txi->txdesc->data & 0x3) {
		ath10k_warn("htt alignment check failed. dropping packet.\n");
		res = -EIO;
		goto err;
	}

	res = ath10k_skb_map(dev, msdu);
	if (res)
		goto err;

	/* tx fragment list must be terminated with zero-entry */
	skb_put(txi->txfrag, frag_len);
	tx_frags = (struct htt_data_tx_desc_frag *)txi->txfrag->data;
	tx_frags[0].paddr = __cpu_to_le32(ATH10K_SKB_CB(msdu)->paddr);
	tx_frags[0].len   = __cpu_to_le32(msdu->len);
	tx_frags[1].paddr = __cpu_to_le32(0);
	tx_frags[1].len   = __cpu_to_le32(0);

	res = ath10k_skb_map(dev, txi->txfrag);
	if (res)
		goto err;

	ath10k_dbg(ATH10K_DBG_HTT, "txfrag 0x%llx msdu 0x%llx\n",
		   (unsigned long long) ATH10K_SKB_CB(txi->txfrag)->paddr,
		   (unsigned long long) ATH10K_SKB_CB(txi->msdu)->paddr);
	ath10k_dbg_dump(ATH10K_DBG_HTT, NULL, "txfrag: ",
			txi->txfrag->data,
			frag_len);
	ath10k_dbg_dump(ATH10K_DBG_HTT, NULL, "msdu: ",
			txi->msdu->data,
			txi->msdu->len);

	skb_put(txi->txdesc, desc_len);
	cmd = (struct htt_cmd *)txi->txdesc->data;
	memset(cmd, 0, desc_len);

	tid = ATH10K_SKB_CB(msdu)->htt.tid;

	ath10k_dbg(ATH10K_DBG_HTT, "htt data tx using tid %hhu\n", tid);

	flags0  = 0;
	if (!ieee80211_has_protected(hdr->frame_control))
		flags0 |= HTT_DATA_TX_DESC_FLAGS0_NO_ENCRYPT;
	flags0 |= HTT_DATA_TX_DESC_FLAGS0_MAC_HDR_PRESENT;
	flags0 |= SM(HTT_PKT_TYPE_RAW, HTT_DATA_TX_DESC_FLAGS0_PKT_TYPE);

	flags1  = 0;
	flags1 |= SM((u16)vdev_id, HTT_DATA_TX_DESC_FLAGS1_VDEV_ID);
	flags1 |= SM((u16)tid, HTT_DATA_TX_DESC_FLAGS1_EXT_TID);

	frags_paddr = ATH10K_SKB_CB(txi->txfrag)->paddr;

	cmd->hdr.msg_type        = HTT_H2T_MSG_TYPE_TX_FRM;
	cmd->data_tx.flags0      = flags0;
	cmd->data_tx.flags1      = __cpu_to_le16(flags1);
	cmd->data_tx.len         = __cpu_to_le16(msdu->len);
	cmd->data_tx.id          = __cpu_to_le16(txi->msdu_id);
	cmd->data_tx.frags_paddr = __cpu_to_le32(frags_paddr);
	cmd->data_tx.peerid      = __cpu_to_le32(HTT_INVALID_PEERID);

	memcpy(cmd->data_tx.prefetch, msdu->data, prefetch_len);

	skb_cb = ATH10K_SKB_CB(txi->txdesc);
	skb_cb->htt.msdu_id = txi->msdu_id;

	res = ath10k_htc_send(htt->htc, htt->eid, txi->txdesc);
	if (res)
		goto err;

	return 0;
err:
	if (txi->txfrag)
		ath10k_skb_unmap(dev, txi->txfrag);
	if (txi->txdesc)
		dev_kfree_skb_any(txi->txdesc);
	if (txi->txfrag)
		dev_kfree_skb_any(txi->txfrag);
	ath10k_htt_tx_info_free(htt, txi);
	ath10k_skb_unmap(dev, msdu);
	return res;
}
