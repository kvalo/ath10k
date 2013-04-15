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

#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <linux/types.h>
#include "trace.h"

enum ath10k_debug_mask {
	ATH10K_DBG_PCI		= 0x00000001,
	ATH10K_DBG_BMI		= 0x00000002,
	ATH10K_DBG_WMI		= 0x00000004,
	ATH10K_DBG_HTC		= 0x00000008,
	ATH10K_DBG_HTT		= 0x00000010,
	ATH10K_DBG_MAC		= 0x00000020,
	ATH10K_DBG_CORE		= 0x00000040,
	ATH10K_DBG_BOOT		= 0x00000080,
	ATH10K_DBG_PCI_DUMP	= 0x00000100,
	ATH10K_DBG_HTT_DUMP	= 0x00000200,
	ATH10K_DBG_RX		= 0x00000400,
	ATH10K_DBG_BEACON	= 0x00000800,
	ATH10K_DBG_ANY		= 0xffffffff,
};

extern unsigned int debug_mask;

extern __printf(1, 2) int ath10k_info(const char *fmt, ...);
extern __printf(1, 2) int ath10k_err(const char *fmt, ...);
extern __printf(1, 2) int ath10k_warn(const char *fmt, ...);

#ifdef CONFIG_ATH10K_DEBUGFS
int ath10k_debug_create(struct ath10k *ar);

static inline void ath10k_debug_read_service_map(struct ath10k *ar,
						 void *service_map,
						 size_t map_size)
{
	memcpy(ar->debug.wmi_service_bitmap, service_map, map_size);
}

static inline void ath10k_debug_read_target_stats(struct ath10k *ar,
						  struct wmi_stats_event *ev)
{
	u8 *tmp = ev->data;
	struct ath10k_target_stats *fw_stats;
	int num_pdev_stats, num_vdev_stats, num_peer_stats;
	int i;

	mutex_lock(&ar->debug.debug_mtx);

	fw_stats = &ar->debug.target_stats;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats); /* 0 or 1 */
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats); /* 0 or max vdevs */
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats); /* 0 or max peers */

	if (num_pdev_stats) {
		struct wmi_pdev_stats *pdev_stats = (void *)tmp;

		fw_stats->ch_noise_floor = __le32_to_cpu(pdev_stats->chan_nf);
		fw_stats->tx_frame_count = __le32_to_cpu(pdev_stats->tx_frame_count);
		fw_stats->rx_frame_count = __le32_to_cpu(pdev_stats->rx_frame_count);
		fw_stats->rx_clear_count = __le32_to_cpu(pdev_stats->rx_clear_count);
		fw_stats->cycle_count = __le32_to_cpu(pdev_stats->cycle_count);
		fw_stats->phy_err_count = __le32_to_cpu(pdev_stats->phy_err_count);
		fw_stats->chan_tx_power = __le32_to_cpu(pdev_stats->chan_tx_pwr);

		fw_stats->comp_queued = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.comp_queued);
		fw_stats->comp_delivered = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.comp_delivered);
		fw_stats->msdu_enqued = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.msdu_enqued);
		fw_stats->mpdu_enqued = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.mpdu_enqued);
		fw_stats->wmm_drop = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.wmm_drop);
		fw_stats->local_enqued = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.local_enqued);
		fw_stats->local_freed = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.local_freed);
		fw_stats->hw_queued = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.hw_queued);
		fw_stats->hw_reaped = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.hw_reaped);
		fw_stats->underrun = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.underrun);
		fw_stats->tx_abort = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.tx_abort);
		fw_stats->mpdus_requed = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.mpdus_requed);
		fw_stats->tx_ko = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.tx_ko);
		fw_stats->data_rc = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.data_rc);
		fw_stats->self_triggers = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.self_triggers);
		fw_stats->sw_retry_failure = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.sw_retry_failure);
		fw_stats->illgl_rate_phy_err = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.illgl_rate_phy_err);
		fw_stats->pdev_cont_xretry = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.pdev_cont_xretry);
		fw_stats->pdev_tx_timeout = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.pdev_tx_timeout);
		fw_stats->pdev_resets = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.pdev_resets);
		fw_stats->phy_underrun = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.phy_underrun);
		fw_stats->txop_ovf = __le32_to_cpu(pdev_stats->wal_pdev_stats.tx.txop_ovf);

		fw_stats->mid_ppdu_route_change = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.mid_ppdu_route_change);
		fw_stats->status_rcvd = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.status_rcvd);
		fw_stats->r0_frags = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.r0_frags);
		fw_stats->r1_frags = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.r1_frags);
		fw_stats->r2_frags = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.r2_frags);
		fw_stats->r3_frags = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.r3_frags);
		fw_stats->htt_msdus = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.htt_msdus);
		fw_stats->htt_mpdus = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.htt_mpdus);
		fw_stats->loc_msdus = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.loc_msdus);
		fw_stats->loc_mpdus = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.loc_mpdus);
		fw_stats->oversize_amsdu = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.oversize_amsdu);
		fw_stats->phy_errs = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.phy_errs);
		fw_stats->phy_err_drop = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.phy_err_drop);
		fw_stats->mpdu_errs = __le32_to_cpu(pdev_stats->wal_pdev_stats.rx.mpdu_errs);

		tmp += sizeof(struct wmi_pdev_stats);
	}

	/* 0 or max vdevs */
	/* Currently firmware does not support VDEV stats */
	if (num_vdev_stats) {
		struct wmi_vdev_stats *vdev_stats;

		for (i = 0; i < num_vdev_stats; i++) {
			vdev_stats = (void *)tmp;
			tmp += sizeof(struct wmi_vdev_stats);
		}
	}

	if (num_peer_stats) {
		struct wmi_peer_stats *peer_stats;

		fw_stats->peers = num_peer_stats;

		for (i = 0; i < num_peer_stats; i++) {
			peer_stats = (void *)tmp;

			WMI_MAC_ADDR_TO_CHAR_ARRAY(&peer_stats->peer_macaddr,
						   fw_stats->peer_stat[i].peer_macaddr);
			fw_stats->peer_stat[i].peer_rssi = __le32_to_cpu(peer_stats->peer_rssi);
			fw_stats->peer_stat[i].peer_tx_rate = __le32_to_cpu(peer_stats->peer_tx_rate);

			tmp += sizeof(struct wmi_peer_stats);
		}
	}

	mutex_unlock(&ar->debug.debug_mtx);
	complete(&ar->debug.event_stats_compl);

}

#else
static inline int ath10k_debug_create(struct ath10k *ar)
{
	return 0;
}

static inline void ath10k_debug_read_service_map(struct ath10k *ar,
						 void *service_map,
						 size_t map_size)
{
}

static inline void ath10k_debug_read_target_stats(struct ath10k *ar,
						  struct wmi_stats_event *ev)
{
}
#endif /* CONFIG_ATH10K_DEBUGFS */

#ifdef CONFIG_ATH10K_DEBUG
extern __printf(2, 3) void ath10k_dbg(enum ath10k_debug_mask mask,
				      const char *fmt, ...);
void ath10k_dbg_dump(enum ath10k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len);
#else /* CONFIG_ATH10K_DEBUG */

static inline int ath10k_dbg(enum ath10k_debug_mask dbg_mask,
			     const char *fmt, ...)
{
	return 0;
}

static inline void ath10k_dbg_dump(enum ath10k_debug_mask mask,
				   const char *msg, const char *prefix,
				   const void *buf, size_t len)
{
}
#endif /* CONFIG_ATH10K_DEBUG */
#endif /* _DEBUG_H_ */
