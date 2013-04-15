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

#include "htc.h"
#include "htt.h"
#include "txrx.h"
#include "debug.h"

#include <linux/log2.h>

/* slightly larger than one large A-MPDU */
#define HTT_RX_RING_SIZE_MIN 128

/* roughly 20 ms @ 1 Gbps of 1500B MSDUs */
#define HTT_RX_RING_SIZE_MAX 2048

#define HTT_RX_AVG_FRM_BYTES 1000

/* ms, very conservative */
#define HTT_RX_HOST_LATENCY_MAX_MS 20

/* ms, conservative */
#define HTT_RX_HOST_LATENCY_WORST_LIKELY_MS 10

/* when under memory pressure rx ring refill may fail and needs a retry */
#define HTT_RX_RING_REFILL_RETRY_MS 50

static int htt_rx_ring_size(struct htt_struct *htt)
{
	int size;

	/*
	 * It is expected that the host CPU will typically be able to
	 * service the rx indication from one A-MPDU before the rx
	 * indication from the subsequent A-MPDU happens, roughly 1-2 ms
	 * later. However, the rx ring should be sized very conservatively,
	 * to accomodate the worst reasonable delay before the host CPU
	 * services a rx indication interrupt.
	 *
	 * The rx ring need not be kept full of empty buffers. In theory,
	 * the htt host SW can dynamically track the low-water mark in the
	 * rx ring, and dynamically adjust the level to which the rx ring
	 * is filled with empty buffers, to dynamically meet the desired
	 * low-water mark.
	 *
	 * In contrast, it's difficult to resize the rx ring itself, once
	 * it's in use. Thus, the ring itself should be sized very
	 * conservatively, while the degree to which the ring is filled
	 * with empty buffers should be sized moderately conservatively.
	 */

	/* 1e6 bps/mbps / 1e3 ms per sec = 1000 */
	size =
	    htt->cfg.max_throughput_mbps +
	    1000  /
	    (8 * HTT_RX_AVG_FRM_BYTES) * HTT_RX_HOST_LATENCY_MAX_MS;

	if (size < HTT_RX_RING_SIZE_MIN)
		size = HTT_RX_RING_SIZE_MIN;

	if (size > HTT_RX_RING_SIZE_MAX)
		size = HTT_RX_RING_SIZE_MAX;

	size = roundup_pow_of_two(size);

	return size;
}

static int htt_rx_ring_fill_level(struct htt_struct *htt)
{
	int size;

	/* 1e6 bps/mbps / 1e3 ms per sec = 1000 */
	size =
	    htt->cfg.max_throughput_mbps *
	    1000  /
	    (8 * HTT_RX_AVG_FRM_BYTES) * HTT_RX_HOST_LATENCY_WORST_LIKELY_MS;

	/*
	 * Make sure the fill level is at least 1 less than the ring size.
	 * Leaving 1 element empty allows the SW to easily distinguish
	 * between a full ring vs. an empty ring.
	 */
	if (size >= htt->rx_ring.size)
		size = htt->rx_ring.size - 1;

	return size;
}

static void htt_rx_ring_fill_n(struct htt_struct *htt, int num)
{
	struct htt_rx_desc *rx_desc;
	struct sk_buff *skb;
	dma_addr_t paddr;
	int idx;

	lockdep_assert_held(&htt->rx_ring.lock);

	idx = __le32_to_cpu(*(htt->rx_ring.alloc_idx.vaddr));
	while (num > 0) {
		skb = dev_alloc_skb(HTT_RX_BUF_SIZE + HTT_RX_DESC_ALIGN);
		if (!skb) {
			/*
			 * Failed to fill it to the desired level -
			 * we'll start a timer and try again next time.
			 * As long as enough buffers are left in the ring for
			 * another A-MPDU rx, no special recovery is needed.
			 */
			mod_timer(&htt->rx_ring.refill_retry_timer, jiffies +
				  msecs_to_jiffies(HTT_RX_RING_REFILL_RETRY_MS));
			goto fail;
		}

		if (!IS_ALIGNED((unsigned long)skb->data, HTT_RX_DESC_ALIGN))
			skb_pull(skb, PTR_ALIGN(skb->data, HTT_RX_DESC_ALIGN) - skb->data);

		/* Clear rx_desc attention word before posting to Rx ring */
		rx_desc = (struct htt_rx_desc *)skb->data;
		rx_desc->attention.flags = __cpu_to_le32(0);

		paddr = dma_map_single(htt->ar->dev, skb->data,
				       skb->len + skb_tailroom(skb),
				       DMA_FROM_DEVICE);

		if (unlikely(dma_mapping_error(htt->ar->dev, paddr))) {
			dev_kfree_skb_any(skb);
			goto fail;
		}

		ATH10K_SKB_CB(skb)->paddr = paddr;
		htt->rx_ring.buf.netbufs_ring[idx] = skb;
		htt->rx_ring.buf.paddrs_ring[idx] = __cpu_to_le32(paddr);
		htt->rx_ring.fill_cnt++;

		num--;
		idx++;
		idx &= htt->rx_ring.size_mask;
	}

fail:
	*(htt->rx_ring.alloc_idx.vaddr) = __cpu_to_le32(idx);
	return;
}

static void htt_rx_msdu_buff_replenish(struct htt_struct *htt)
{
	int num_to_fill;

	spin_lock_bh(&htt->rx_ring.lock);
	num_to_fill = htt->rx_ring.fill_level - htt->rx_ring.fill_cnt;
	htt_rx_ring_fill_n(htt, num_to_fill);
	spin_unlock_bh(&htt->rx_ring.lock);
}

static void htt_rx_ring_refill_retry(unsigned long arg)
{
	struct htt_struct *htt = (struct htt_struct *)arg;
	htt_rx_msdu_buff_replenish(htt);
}

static unsigned htt_rx_ring_elems(struct htt_struct *htt)
{
	return (__le32_to_cpu(*htt->rx_ring.alloc_idx.vaddr) -
		htt->rx_ring.sw_rd_idx.msdu_payld) & htt->rx_ring.size_mask;
}

void htt_rx_detach(struct htt_struct *htt)
{
	int sw_rd_idx = htt->rx_ring.sw_rd_idx.msdu_payld;

	del_timer_sync(&htt->rx_ring.refill_retry_timer);

	while (sw_rd_idx != __le32_to_cpu(*(htt->rx_ring.alloc_idx.vaddr))) {
		struct sk_buff *skb =
				htt->rx_ring.buf.netbufs_ring[sw_rd_idx];
		struct ath10k_skb_cb *cb = ATH10K_SKB_CB(skb);

		dma_unmap_single(htt->ar->dev, cb->paddr,
				 skb->len + skb_tailroom(skb),
				 DMA_FROM_DEVICE);
		dev_kfree_skb_any(htt->rx_ring.buf.netbufs_ring[sw_rd_idx]);
		sw_rd_idx++;
		sw_rd_idx &= htt->rx_ring.size_mask;
	}

	dma_free_coherent(htt->ar->dev,
			  (htt->rx_ring.size *
			   sizeof(htt->rx_ring.buf.paddrs_ring)),
			  htt->rx_ring.buf.paddrs_ring,
			  htt->rx_ring.base_paddr);

	dma_free_coherent(htt->ar->dev,
			  sizeof(*htt->rx_ring.alloc_idx.vaddr),
			  htt->rx_ring.alloc_idx.vaddr,
			  htt->rx_ring.alloc_idx.paddr);

	kfree(htt->rx_ring.buf.netbufs_ring);
}

static inline struct sk_buff *htt_rx_netbuf_pop(struct htt_struct *htt)
{
	int idx;
	struct sk_buff *msdu;

	spin_lock_bh(&htt->rx_ring.lock);

	if (htt_rx_ring_elems(htt) == 0)
		WARN_ON(1);

	idx = htt->rx_ring.sw_rd_idx.msdu_payld;
	msdu = htt->rx_ring.buf.netbufs_ring[idx];

	idx++;
	idx &= htt->rx_ring.size_mask;
	htt->rx_ring.sw_rd_idx.msdu_payld = idx;
	htt->rx_ring.fill_cnt--;

	spin_unlock_bh(&htt->rx_ring.lock);
	return msdu;
}

static int htt_rx_amsdu_pop(struct htt_struct *htt,
			    u8 **fw_desc, int *fw_desc_len,
			    struct sk_buff **head_msdu,
			    struct sk_buff **tail_msdu)
{
	int msdu_len, msdu_chaining = 0;
	struct sk_buff *msdu;
	struct htt_rx_desc *rx_desc;

	if (htt_rx_ring_elems(htt) == 0)
		WARN_ON(1);

	if (htt->rx_confused) {
		ath10k_warn("%s: htt failure: cannot rx\n", __func__);
		return 0;
	}

	msdu = *head_msdu = htt_rx_netbuf_pop(htt);
	while (msdu) {
		int last_msdu, msdu_len_invalid, msdu_chained;

		dma_unmap_single(htt->ar->dev,
				 ATH10K_SKB_CB(msdu)->paddr,
				 msdu->len + skb_tailroom(msdu),
				 DMA_FROM_DEVICE);

		ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt rx: ",
				msdu->data, msdu->len + skb_tailroom(msdu));

		rx_desc = (struct htt_rx_desc *)msdu->data;

		/* FIXME: we must report msdu payload since this is what caller
		 *        expects now */
		skb_put(msdu, offsetof(struct htt_rx_desc, msdu_payload));
		skb_pull(msdu, offsetof(struct htt_rx_desc, msdu_payload));

		/*
		 * Sanity check - confirm the HW is finished filling in the
		 * rx data.
		 * If the HW and SW are working correctly, then it's guaranteed
		 * that the HW's MAC DMA is done before this point in the SW.
		 * To prevent the case that we handle a stale Rx descriptor,
		 * just assert for now until we have a way to recover.
		 */
		if (WARN_ON(!(__le32_to_cpu(rx_desc->attention.flags)
				& RX_ATTENTION_FLAGS_MSDU_DONE))) {
			if (*head_msdu == msdu)
				*head_msdu = NULL;
			dev_kfree_skb_any(msdu);
			htt->rx_confused = true;
			break;
		}

		/*
		 * Copy the FW rx descriptor for this MSDU from the rx
		 * indication message into the MSDU's netbuf. HL uses the
		 * same rx indication message definition as LL, and simply
		 * appends new info (fields from the HW rx desc, and the
		 * MSDU payload itself). So, the offset into the rx
		 * indication message only has to account for the standard
		 * offset of the per-MSDU FW rx desc info within the
		 * message, and how many bytes of the per-MSDU FW rx desc
		 * info have already been consumed. (And the endianness of
		 * the host, since for a big-endian host, the rx ind
		 * message contents, including the per-MSDU rx desc bytes,
		 * were byteswapped during upload.)
		 */
		if (*fw_desc_len > 0) {
			rx_desc->fw_desc.info0 = **fw_desc;
			/*
			 * The target is expected to only provide the basic
			 * per-MSDU rx descriptors. Just to be sure, verify
			 * that the target has not attached extension data
			 * (e.g. LRO flow ID).
			 */

			/* or more, if there's extension data */
			(*fw_desc)++;
			(*fw_desc_len)--;
		} else {
			/*
			 * When an oversized AMSDU happened, FW will lost
			 * some of MSDU status - in this case, the FW
			 * descriptors provided will be less than the
			 * actual MSDUs inside this MPDU. Mark the FW
			 * descriptors so that it will still deliver to
			 * upper stack, if no CRC error for this MPDU.
			 *
			 * FIX THIS - the FW descriptors are actually for
			 * MSDUs in the end of this A-MSDU instead of the
			 * beginning.
			 */
			rx_desc->fw_desc.info0 = 0;
		}

		msdu_len_invalid = !!(__le32_to_cpu(rx_desc->attention.flags)
					& (RX_ATTENTION_FLAGS_MPDU_LENGTH_ERR |
					   RX_ATTENTION_FLAGS_MSDU_LENGTH_ERR));
		msdu_len = MS(__le32_to_cpu(rx_desc->msdu_start.info0),
			      RX_MSDU_START_INFO0_MSDU_LENGTH);
		msdu_chained = rx_desc->frag_info.ring2_more_count;

		if (msdu_len_invalid)
			msdu_len = 0;

		skb_trim(msdu, 0);
		skb_put(msdu, min(msdu_len, HTT_RX_MSDU_SIZE));
		msdu_len -= msdu->len;

		/* FIXME: Do chained buffers include htt_rx_desc or not? */
		while (msdu_chained--) {
			struct sk_buff *next = htt_rx_netbuf_pop(htt);

			dma_unmap_single(htt->ar->dev,
					 ATH10K_SKB_CB(next)->paddr,
					 next->len + skb_tailroom(next),
					 DMA_FROM_DEVICE);

			ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt rx: ",
					next->data, next->len + skb_tailroom(next));

			skb_trim(next, 0);
			skb_put(next, min(msdu_len, HTT_RX_BUF_SIZE));
			msdu_len -= next->len;

			msdu->next = next;
			msdu = next;
			msdu_chaining = 1;
		}

		if (msdu_len > 0) {
			/* This may suggest FW bug? */
			ath10k_warn("htt rx msdu len not consumed (%d)\n", msdu_len);
		}

		last_msdu = __le32_to_cpu(rx_desc->msdu_end.info0) &
							RX_MSDU_END_INFO0_LAST_MSDU;

		if (last_msdu) {
			msdu->next = NULL;
			break;
		} else {
			struct sk_buff *next = htt_rx_netbuf_pop(htt);
			msdu->next = next;
			msdu = next;
		}
	}
	*tail_msdu = msdu;

	/*
	 * Don't refill the ring yet.
	 *
	 * First, the elements popped here are still in use - it is not
	 * safe to overwrite them until the matching call to
	 * mpdu_desc_list_next. Second, for efficiency it is preferable to
	 * refill the rx ring with 1 PPDU's worth of rx buffers (something
	 * like 32 x 3 buffers), rather than one MPDU's worth of rx buffers
	 * (something like 3 buffers). Consequently, we'll rely on the txrx
	 * SW to tell us when it is done pulling all the PPDU's rx buffers
	 * out of the rx ring, and then refill it just once.
	 */

	return msdu_chaining;
}

int htt_rx_attach(struct htt_struct *htt)
{
	dma_addr_t paddr;
	void *vaddr;
	struct timer_list *timer = &htt->rx_ring.refill_retry_timer;

	htt->rx_ring.size = htt_rx_ring_size(htt);
	WARN_ON(!is_power_of_2(htt->rx_ring.size));
	htt->rx_ring.size_mask = htt->rx_ring.size - 1;

	/*
	 * Set the initial value for the level to which the rx ring
	 * should be filled, based on the max throughput and the
	 * worst likely latency for the host to fill the rx ring
	 * with new buffers. In theory, this fill level can be
	 * dynamically adjusted from the initial value set here, to
	 * reflect the actual host latency rather than a
	 * conservative assumption about the host latency.
	 */
	htt->rx_ring.fill_level = htt_rx_ring_fill_level(htt);

	htt->rx_ring.buf.netbufs_ring =
		kmalloc(htt->rx_ring.size * sizeof(struct sk_buff *),
			GFP_KERNEL);
	if (!htt->rx_ring.buf.netbufs_ring)
		goto fail1;

	vaddr = dma_alloc_coherent(htt->ar->dev,
		   (htt->rx_ring.size * sizeof(htt->rx_ring.buf.paddrs_ring)),
		   &paddr, GFP_DMA);
	if (!vaddr)
		goto fail2;

	htt->rx_ring.buf.paddrs_ring = vaddr;
	htt->rx_ring.base_paddr = paddr;

	vaddr = dma_alloc_coherent(htt->ar->dev,
				   sizeof(*htt->rx_ring.alloc_idx.vaddr),
				   &paddr, GFP_DMA);
	if (!vaddr)
		goto fail3;

	htt->rx_ring.alloc_idx.vaddr = vaddr;
	htt->rx_ring.alloc_idx.paddr = paddr;
	htt->rx_ring.sw_rd_idx.msdu_payld = 0;
	*htt->rx_ring.alloc_idx.vaddr = 0;

	/* Initialize the Rx refill retry timer */
	setup_timer(timer, htt_rx_ring_refill_retry, (unsigned long)htt);

	spin_lock_init(&htt->rx_ring.lock);
	spin_lock_bh(&htt->rx_ring.lock);
	htt->rx_ring.fill_cnt = 0;
	htt_rx_ring_fill_n(htt, htt->rx_ring.fill_level);
	spin_unlock_bh(&htt->rx_ring.lock);

	return 0;

fail3:
	dma_free_coherent(htt->ar->dev,
			  (htt->rx_ring.size *
			   sizeof(htt->rx_ring.buf.paddrs_ring)),
			  htt->rx_ring.buf.paddrs_ring,
			  htt->rx_ring.base_paddr);
fail2:
	kfree(htt->rx_ring.buf.netbufs_ring);
fail1:
	return -ENOMEM;
}

static int htt_rx_crypto_param_len(enum htt_rx_mpdu_encrypt_type type)
{
	switch (type) {
	case HTT_RX_MPDU_ENCRYPT_WEP40:
	case HTT_RX_MPDU_ENCRYPT_WEP104:
		return 4;
	case HTT_RX_MPDU_ENCRYPT_TKIP_WITHOUT_MIC:
	case HTT_RX_MPDU_ENCRYPT_WEP128: /* not tested */
	case HTT_RX_MPDU_ENCRYPT_TKIP_WPA:
	case HTT_RX_MPDU_ENCRYPT_WAPI: /* not tested */
	case HTT_RX_MPDU_ENCRYPT_AES_CCM_WPA2:
		return 8;
	case HTT_RX_MPDU_ENCRYPT_NONE:
		return 0;
	}

	ath10k_warn("unknown encryption type %d\n", type);
	return 0;
}

static int htt_rx_crypto_tail_len(enum htt_rx_mpdu_encrypt_type type)
{
	switch (type) {
	case HTT_RX_MPDU_ENCRYPT_NONE:
	case HTT_RX_MPDU_ENCRYPT_WEP40:
	case HTT_RX_MPDU_ENCRYPT_WEP104:
	case HTT_RX_MPDU_ENCRYPT_WEP128:
	case HTT_RX_MPDU_ENCRYPT_WAPI:
		return 0;
	case HTT_RX_MPDU_ENCRYPT_TKIP_WITHOUT_MIC:
		return 4;
	case HTT_RX_MPDU_ENCRYPT_TKIP_WPA:
		return 4 + 8;
	case HTT_RX_MPDU_ENCRYPT_AES_CCM_WPA2:
		return 8;
	}

	ath10k_warn("unknown encryption type %d\n", type);
	return 0;
}

/* Applies for first msdu in chain, before altering it. */
static struct ieee80211_hdr *htt_rx_skb_get_hdr(struct sk_buff *skb)
{
	struct htt_rx_desc *rxd;
	enum rx_msdu_decap_format fmt;

	rxd = (void *)skb->data - sizeof(*rxd);
	fmt = MS(__le32_to_cpu(rxd->msdu_start.info1),
			RX_MSDU_START_INFO1_DECAP_FORMAT);

	if (fmt == RX_MSDU_DECAP_RAW)
		return (void *)skb->data;
	else
		return (void *)skb->data - RX_HTT_HDR_STATUS_LEN;
}

/* This function only applies for first msdu in an msdu chain */
static bool htt_rx_hdr_is_amsdu(struct ieee80211_hdr *hdr)
{
	if (ieee80211_is_data_qos(hdr->frame_control)) {
		u8 *qc = ieee80211_get_qos_ctl(hdr);
		if (qc[0] & 0x80)
			return true;
	}
	return false;
}

static void htt_rx_free_msdu_chain(struct sk_buff *skb)
{
	struct sk_buff *next;

	while (skb) {
		next = skb->next;
		dev_kfree_skb_any(skb);
		skb = next;
	}
}

static int htt_rx_amsdu(struct htt_struct *htt,
			struct htt_rx_info *info)
{
	struct htt_rx_desc *rxd;
	struct sk_buff *amsdu;
	struct sk_buff *first;
	struct ieee80211_hdr *hdr;
	struct sk_buff *skb = info->skb;
	enum rx_msdu_decap_format fmt;
	enum htt_rx_mpdu_encrypt_type enctype;

	rxd = (void *)skb->data - sizeof(*rxd);
	fmt = MS(__le32_to_cpu(rxd->msdu_start.info1),
			RX_MSDU_START_INFO1_DECAP_FORMAT);
	enctype = MS(__le32_to_cpu(rxd->mpdu_start.info0),
			RX_MPDU_START_INFO0_ENCRYPT_TYPE);

	/* FIXME: No idea what assumptions are safe here. Need logs */
	if (fmt < RX_MSDU_DECAP_ETHERNET2_DIX && skb->next) {
		htt_rx_free_msdu_chain(skb->next);
		skb->next = NULL;
		return -ENOTSUPP;
	}

	/* A-MSDU max is a little less than 8K */
	amsdu = dev_alloc_skb(8*1024);
	if (!amsdu) {
		ath10k_warn("A-MSDU allocation failed\n");
		htt_rx_free_msdu_chain(skb->next);
		skb->next = NULL;
		return -ENOMEM;
	}

	if (fmt >= RX_MSDU_DECAP_NATIVE_WIFI) {
		int hdrlen;

		hdr = (void *)rxd->rx_hdr_status;
		hdrlen = ieee80211_hdrlen(hdr->frame_control);
		memcpy(skb_put(amsdu, hdrlen), hdr, hdrlen);
	}

	first = skb;
	while (skb) {
		int llclen = 0;

		rxd = (void *)skb->data - sizeof(*rxd);
		fmt = MS(__le32_to_cpu(rxd->msdu_start.info1),
				RX_MSDU_START_INFO1_DECAP_FORMAT);
		hdr = (void *)rxd->rx_hdr_status;

		if (fmt == RX_MSDU_DECAP_ETHERNET2_DIX) {
			void *llc = (void *)skb->data - RX_HTT_HDR_STATUS_LEN;

			/* We get rid of the addr[6] + addr[6] + ethertype[2]
			 * as we don't need that at all.
			 * For 8023/llc/snap we keep the original header
			 * (addr[6] + addr[6] + len[2] + llc info) in msdu
			 * since it is integral part of an A-MSDU subframe. */
			skb_pull(skb, 6 + 6 + 2);

			/* Regular LLC/SNAP has 8 bytes.
			 * However when A-MSDU takes place FW decaps complete
			 * LLC headers along with addr[6], addr[6], len[2].
			 * This makes sense only for eth2/dix decap format.
			 * FIXME: if we get different type of LLC this will fail
			 *        as not all LLCs have the 8 byte info */
			llclen += 8;

			/* addr[6] + addr[6] + len[2] */
			llclen += 6 + 6 + 2;

			if (skb == first) {
				struct ieee80211_hdr *hdr = (void *)amsdu->data;
				llc += roundup(ieee80211_hdrlen(hdr->frame_control), 4);
				llc += roundup(htt_rx_crypto_param_len(enctype), 4);
			}

			memcpy(skb_put(amsdu, llclen), llc, llclen);
		}

		if (fmt == RX_MSDU_DECAP_RAW)
			skb_trim(skb, skb->len - 4); /* remove FCS */

		memcpy(skb_put(amsdu, skb->len), skb->data, skb->len);

		/* A-MSDU subframes are padded to 4bytes
		 * but relative to first subframe, not the whole MPDU */
		if (skb->next && ((llclen + skb->len) & 3)) {
			int padlen = 4 - ((llclen + skb->len) & 3);
			memset(skb_put(amsdu, padlen), 0, padlen);
		}

		skb = skb->next;
	}

	info->skb = amsdu;
	info->encrypt_type = enctype;

	htt_rx_free_msdu_chain(first);

	return 0;
}

static int htt_rx_msdu(struct htt_struct *htt,
		       struct htt_rx_info *info)
{
	struct sk_buff *skb = info->skb;
	struct htt_rx_desc *rxd;
	struct ieee80211_hdr *hdr;
	enum rx_msdu_decap_format fmt;
	enum htt_rx_mpdu_encrypt_type enctype;

	rxd = (void *)skb->data - sizeof(*rxd);
	fmt = MS(__le32_to_cpu(rxd->msdu_start.info1),
			RX_MSDU_START_INFO1_DECAP_FORMAT);
	enctype = MS(__le32_to_cpu(rxd->mpdu_start.info0),
			RX_MPDU_START_INFO0_ENCRYPT_TYPE);
	hdr = (void *)skb->data - RX_HTT_HDR_STATUS_LEN;

	switch (fmt) {
	case RX_MSDU_DECAP_RAW:
		/* remove trailing FCS */
		skb_trim(skb, skb->len - 4);
		break;
	case RX_MSDU_DECAP_NATIVE_WIFI:
		/* nothing to do here */
		break;
	case RX_MSDU_DECAP_ETHERNET2_DIX:
		/* macaddr[6] + macaddr[6] + ethertype[2] */
		skb_pull(skb, 6 + 6 + 2);
		break;
	case RX_MSDU_DECAP_8023_SNAP_LLC:
		/* macaddr[6] + macaddr[6] + len[2] */
		/* we don't need this for non-A-MSDU */
		skb_pull(skb, 6 + 6 + 2);
		break;
	}

	if (fmt == RX_MSDU_DECAP_ETHERNET2_DIX) {
		void *llc;
		int llclen;

		llclen = 8;
		llc  = hdr;
		llc += roundup(ieee80211_hdrlen(hdr->frame_control), 4);
		llc += roundup(htt_rx_crypto_param_len(enctype), 4);

		skb_push(skb, llclen);
		memcpy(skb->data, llc, llclen);
	}

	if (fmt >= RX_MSDU_DECAP_ETHERNET2_DIX) {
		int len = ieee80211_hdrlen(hdr->frame_control);
		skb_push(skb, len);
		memcpy(skb->data, hdr, len);
	}

	info->skb = skb;
	info->encrypt_type = enctype;
	return 0;
}

static bool htt_rx_has_decrypt_err(struct sk_buff *skb)
{
	struct htt_rx_desc *rxd;
	u32 flags;

	rxd = (void *)skb->data - sizeof(*rxd);
	flags = __le32_to_cpu(rxd->attention.flags);

	if (flags & RX_ATTENTION_FLAGS_DECRYPT_ERR)
		return true;

	return false;
}

static bool htt_rx_has_fcs_err(struct sk_buff *skb)
{
	struct htt_rx_desc *rxd;
	u32 flags;

	rxd = (void *)skb->data - sizeof(*rxd);
	flags = __le32_to_cpu(rxd->attention.flags);

	if (flags & RX_ATTENTION_FLAGS_FCS_ERR)
		return true;

	return false;
}

static void htt_rx_handler(struct htt_struct *htt, struct htt_rx_indication *rx)
{
	struct htt_rx_info info;
	struct htt_rx_indication_mpdu_range *mpdu_ranges;
	int num_mpdu_ranges;
	int fw_desc_len;
	u8 *fw_desc;
	int i, j;
	int ret;

	memset(&info, 0, sizeof(info));

	fw_desc_len = __le16_to_cpu(rx->prefix.fw_rx_desc_bytes);
	fw_desc = (u8 *)&rx->fw_desc;

	num_mpdu_ranges = MS(__le32_to_cpu(rx->hdr.info1),
			     HTT_RX_INDICATION_INFO1_NUM_MPDU_RANGES);
	mpdu_ranges = htt_rx_ind_get_mpdu_ranges(rx);

	ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt rx ind: ",
			rx, sizeof(*rx) +
			(sizeof(struct htt_rx_indication_mpdu_range) *
				num_mpdu_ranges));

	for (i = 0; i < num_mpdu_ranges; i++) {
		info.status = mpdu_ranges[i].mpdu_range_status;

		for (j = 0; j < mpdu_ranges[i].mpdu_count; j++) {
			struct sk_buff *msdu_head, *msdu_tail;
			int msdu_chaining;

			msdu_head = NULL;
			msdu_tail = NULL;
			msdu_chaining = htt_rx_amsdu_pop(htt,
							 &fw_desc,
							 &fw_desc_len,
							 &msdu_head,
							 &msdu_tail);

			if (!msdu_head) {
				ath10k_warn("htt rx no data!\n");
				continue;
			}

			if (msdu_head->len == 0) {
				ath10k_dbg(ATH10K_DBG_HTT,
					   "htt rx dropping due to zero-len\n");
				htt_rx_free_msdu_chain(msdu_head);
				continue;
			}

			if (htt_rx_has_decrypt_err(msdu_head)) {
				htt_rx_free_msdu_chain(msdu_head);
				continue;
			}

			/* Skip mgmt frames while we handle this in WMI */
			if (info.status == HTT_RX_IND_MPDU_STATUS_MGMT_CTRL) {
				htt_rx_free_msdu_chain(msdu_head);
				continue;
			}

			if (info.status != HTT_RX_IND_MPDU_STATUS_OK &&
			    info.status != HTT_RX_IND_MPDU_STATUS_TKIP_MIC_ERR &&
			    !htt->ar->monitor_enabled) {
				ath10k_dbg(ATH10K_DBG_HTT,
					   "htt rx ignoring frame w/ status %d\n",
					   info.status);
				htt_rx_free_msdu_chain(msdu_head);
				continue;
			}

			/* FIXME: qca_main doesn't support chaining either yet.
			 * this needs investigation */
			if (msdu_chaining) {
				ath10k_warn("msdu_chaining is true\n");
				htt_rx_free_msdu_chain(msdu_head);
				continue;
			}

			info.skb     = msdu_head;
			info.fcs_err = htt_rx_has_fcs_err(msdu_head);
			info.signal  = ATH10K_DEFAULT_NOISE_FLOOR;
			info.signal += rx->ppdu.combined_rssi;

			info.rate.info0 = rx->ppdu.info0;
			info.rate.info1 = __le32_to_cpu(rx->ppdu.info1);
			info.rate.info2 = __le32_to_cpu(rx->ppdu.info2);

			if (htt_rx_hdr_is_amsdu(htt_rx_skb_get_hdr(msdu_head)))
				ret = htt_rx_amsdu(htt, &info);
			else
				ret = htt_rx_msdu(htt, &info);

			if (ret && !info.fcs_err) {
				ath10k_warn("error processing msdus %d\n", ret);
				dev_kfree_skb_any(info.skb);
				continue;
			}

			if (htt_rx_hdr_is_amsdu((void *)info.skb->data))
				ath10k_dbg(ATH10K_DBG_HTT, "htt mpdu is amsdu\n");

			ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt mpdu: ",
					info.skb->data, info.skb->len);
			ath10k_process_rx(htt->ar, &info);
		}
	}

	htt_rx_msdu_buff_replenish(htt);
}

static void htt_rx_frag_handler(struct htt_struct *htt,
				struct htt_rx_fragment_indication *frag)
{
	struct sk_buff *msdu_head, *msdu_tail;
	struct htt_rx_desc *rxd;
	enum rx_msdu_decap_format fmt;
	struct htt_rx_info info;
	int msdu_chaining;
	bool tkip_mic_err;
	bool decrypt_err;
	u8 *fw_desc;
	int fw_desc_len;
	int trim;

	fw_desc_len = __le16_to_cpu(frag->fw_rx_desc_bytes);
	fw_desc = (u8 *)frag->fw_msdu_rx_desc;

more:
	msdu_head = NULL;
	msdu_tail = NULL;
	msdu_chaining = htt_rx_amsdu_pop(htt, &fw_desc, &fw_desc_len,
						&msdu_head, &msdu_tail);

	ath10k_dbg(ATH10K_DBG_HTT_DUMP, "htt rx frag ahead\n");

	if (msdu_chaining || msdu_head != msdu_tail) {
		ath10k_warn("aggregation with fragmentation?!\n");
		htt_rx_free_msdu_chain(msdu_head);
		return;
	}

	/* FIXME: implement signal strength */

	rxd = (void *)msdu_head->data - sizeof(*rxd);
	tkip_mic_err = !!(__le32_to_cpu(rxd->attention.flags) &
				RX_ATTENTION_FLAGS_TKIP_MIC_ERR);
	decrypt_err = !!(__le32_to_cpu(rxd->attention.flags) &
				RX_ATTENTION_FLAGS_DECRYPT_ERR);
	fmt = MS(__le32_to_cpu(rxd->msdu_start.info1),
			RX_MSDU_START_INFO1_DECAP_FORMAT);

	if (fmt != RX_MSDU_DECAP_RAW) {
		ath10k_warn("we dont support non-raw fragmented rx yet\n");
		dev_kfree_skb_any(msdu_head);
		goto end;
	}

	info.skb = msdu_head;
	info.status = HTT_RX_IND_MPDU_STATUS_OK;
	info.encrypt_type = MS(__le32_to_cpu(rxd->mpdu_start.info0),
				RX_MPDU_START_INFO0_ENCRYPT_TYPE);

	if (tkip_mic_err) {
		ath10k_warn("tkip mic error\n");
		info.status = HTT_RX_IND_MPDU_STATUS_TKIP_MIC_ERR;
	}

	if (decrypt_err) {
		ath10k_warn("decryption err in fragmented rx\n");
		dev_kfree_skb_any(info.skb);
		goto end;
	}

	if (info.encrypt_type != HTT_RX_MPDU_ENCRYPT_NONE) {
		struct ieee80211_hdr *hdr = (void *)info.skb->data;
		int hdrlen = ieee80211_hdrlen(hdr->frame_control);
		int paramlen = htt_rx_crypto_param_len(info.encrypt_type);

		/* It is more efficient to move the header than the payload */
		memmove((void *)info.skb->data + paramlen,
			(void *)info.skb->data,
			hdrlen);
		skb_pull(info.skb, paramlen);
	}

	/* remove trailing FCS */
	trim  = 4;
	/* remove crypto trailer; we use rx desc for mic failure */
	trim += htt_rx_crypto_tail_len(info.encrypt_type);

	if (WARN_ON(trim > info.skb->len)) {
		dev_kfree_skb_any(info.skb);
		goto end;
	}

	skb_trim(info.skb, info.skb->len - trim);

	ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt frag mpdu: ",
			info.skb->data, info.skb->len);
	ath10k_process_rx(htt->ar, &info);

end:
	if (fw_desc_len > 0) {
		ath10k_dbg(ATH10K_DBG_HTT,
			   "expecting more fragmented rx in one indication\n");
		goto more;
	}
}

void htt_t2h_msg_handler(void *context, struct sk_buff *skb)
{
	struct htt_struct *htt = (struct htt_struct *)context;
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);
	struct htt_resp *resp = (struct htt_resp *)skb->data;

	/* check for successful message reception */
	if (skb_cb->htc.cancelled) {
		dev_kfree_skb_any(skb);
		return;
	}

	/* confirm alignment */
	WARN_ON_ONCE((((unsigned long)skb->data) & 0x3) != 0);

	ath10k_dbg(ATH10K_DBG_HTT, "HTT RX, msg_type: 0x%0X\n", resp->hdr.msg_type);
	switch (resp->hdr.msg_type) {
	case HTT_T2H_MSG_TYPE_VERSION_CONF: {
		htt->target_version_major = resp->ver_resp.major;
		htt->target_version_minor = resp->ver_resp.minor;
		complete(&htt->target_version_received);
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_IND: {
		htt_rx_handler(htt, &resp->rx_ind);
		break;
	}
	case HTT_T2H_MSG_TYPE_PEER_MAP: {
		struct htt_peer_map_event ev = {
			.vdev_id = resp->peer_map.vdev_id,
			.peer_id = __le16_to_cpu(resp->peer_map.peer_id),
		};
		memcpy(ev.addr, resp->peer_map.addr, sizeof(ev.addr));
		ath10k_peer_map_event(htt, &ev);
		break;
	}
	case HTT_T2H_MSG_TYPE_PEER_UNMAP: {
		struct htt_peer_unmap_event ev = {
			.peer_id = __le16_to_cpu(resp->peer_unmap.peer_id),
		};
		ath10k_peer_unmap_event(htt, &ev);
		break;
	}
	case HTT_T2H_MSG_TYPE_MGMT_TX_COMPLETION: {
		struct htt_mgmt_tx_done arg = {
			.desc_id = __le32_to_cpu(resp->mgmt_tx_completion.desc_id),
			.status  = __le32_to_cpu(resp->mgmt_tx_completion.status),
		};
		ath10k_mgmt_tx_completed(htt, &arg);
		break;
	}
	case HTT_T2H_MSG_TYPE_TX_COMPL_IND: {
		struct htt_data_tx_done ev = {
			.status      = MS(resp->data_tx_completion.flags, HTT_DATA_TX_STATUS),
			.tid         = MS(resp->data_tx_completion.flags, HTT_DATA_TX_TID),
			.tid_invalid = !!(resp->data_tx_completion.flags & HTT_DATA_TX_TID_INVALID),
		};
		int i;

		ath10k_dbg(ATH10K_DBG_HTT, "htt tx completion num_msdus %d\n",
			   resp->data_tx_completion.num_msdus);

		for (i = 0; i < resp->data_tx_completion.num_msdus; i++) {
			ev.msdu_id = __le16_to_cpu(resp->data_tx_completion.msdus[i]);
			ath10k_data_tx_completed(htt, &ev);
		}
		break;
	}
	case HTT_T2H_MSG_TYPE_SEC_IND: {
		struct ath10k *ar = htt->ar;
		struct htt_security_indication *ev = &resp->security_indication;

		ath10k_dbg(ATH10K_DBG_HTT,
			   "sec ind peer_id %d unicast %d type %d\n",
			  __le16_to_cpu(ev->peer_id),
			  !!(ev->flags & HTT_SECURITY_IS_UNICAST),
			  MS(ev->flags, HTT_SECURITY_TYPE));
		complete(&ar->install_key_done);
		break;
	}
	case HTT_T2H_MSG_TYPE_RX_FRAG_IND: {
		ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt event: ",
				skb->data, skb->len);
		htt_rx_frag_handler(htt, &resp->rx_frag_ind);
		break;
	}
	case HTT_T2H_MSG_TYPE_TEST:
		/* FIX THIS */
		break;
	case HTT_T2H_MSG_TYPE_TX_INSPECT_IND:
	case HTT_T2H_MSG_TYPE_STATS_CONF:
	case HTT_T2H_MSG_TYPE_RX_ADDBA:
	case HTT_T2H_MSG_TYPE_RX_DELBA:
	case HTT_T2H_MSG_TYPE_RX_FLUSH:
	default:
		ath10k_dbg(ATH10K_DBG_HTT, "htt event (%d) not handled\n",
			   resp->hdr.msg_type);
		ath10k_dbg_dump(ATH10K_DBG_HTT_DUMP, NULL, "htt event: ",
				skb->data, skb->len);
		break;
	};

	/* Free the indication buffer */
	dev_kfree_skb_any(skb);
}
