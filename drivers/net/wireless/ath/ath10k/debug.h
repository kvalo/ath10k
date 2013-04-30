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
	ATH10K_DBG_WMI		= 0x00000002,
	ATH10K_DBG_HTC		= 0x00000004,
	ATH10K_DBG_HTT		= 0x00000008,
	ATH10K_DBG_MAC		= 0x00000010,
	ATH10K_DBG_CORE		= 0x00000020,
	ATH10K_DBG_PCI_DUMP	= 0x00000040,
	ATH10K_DBG_HTT_DUMP	= 0x00000080,
	ATH10K_DBG_BEACON	= 0x00000100,
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
	struct ath10k_target_stats *stats;
	int num_pdev_stats, num_vdev_stats, num_peer_stats;
	struct wmi_pdev_stats *ps;
	int i;

	mutex_lock(&ar->conf_mutex);

	stats = &ar->debug.target_stats;

	num_pdev_stats = __le32_to_cpu(ev->num_pdev_stats); /* 0 or 1 */
	num_vdev_stats = __le32_to_cpu(ev->num_vdev_stats); /* 0 or max vdevs */
	num_peer_stats = __le32_to_cpu(ev->num_peer_stats); /* 0 or max peers */

	if (num_pdev_stats) {
		ps = (struct wmi_pdev_stats *)tmp;

		stats->ch_noise_floor = __le32_to_cpu(ps->chan_nf);
		stats->tx_frame_count = __le32_to_cpu(ps->tx_frame_count);
		stats->rx_frame_count = __le32_to_cpu(ps->rx_frame_count);
		stats->rx_clear_count = __le32_to_cpu(ps->rx_clear_count);
		stats->cycle_count = __le32_to_cpu(ps->cycle_count);
		stats->phy_err_count = __le32_to_cpu(ps->phy_err_count);
		stats->chan_tx_power = __le32_to_cpu(ps->chan_tx_pwr);

		stats->comp_queued = __le32_to_cpu(ps->wal.tx.comp_queued);
		stats->comp_delivered =
			__le32_to_cpu(ps->wal.tx.comp_delivered);
		stats->msdu_enqued = __le32_to_cpu(ps->wal.tx.msdu_enqued);
		stats->mpdu_enqued = __le32_to_cpu(ps->wal.tx.mpdu_enqued);
		stats->wmm_drop = __le32_to_cpu(ps->wal.tx.wmm_drop);
		stats->local_enqued = __le32_to_cpu(ps->wal.tx.local_enqued);
		stats->local_freed = __le32_to_cpu(ps->wal.tx.local_freed);
		stats->hw_queued = __le32_to_cpu(ps->wal.tx.hw_queued);
		stats->hw_reaped = __le32_to_cpu(ps->wal.tx.hw_reaped);
		stats->underrun = __le32_to_cpu(ps->wal.tx.underrun);
		stats->tx_abort = __le32_to_cpu(ps->wal.tx.tx_abort);
		stats->mpdus_requed = __le32_to_cpu(ps->wal.tx.mpdus_requed);
		stats->tx_ko = __le32_to_cpu(ps->wal.tx.tx_ko);
		stats->data_rc = __le32_to_cpu(ps->wal.tx.data_rc);
		stats->self_triggers = __le32_to_cpu(ps->wal.tx.self_triggers);
		stats->sw_retry_failure =
			__le32_to_cpu(ps->wal.tx.sw_retry_failure);
		stats->illgl_rate_phy_err =
			__le32_to_cpu(ps->wal.tx.illgl_rate_phy_err);
		stats->pdev_cont_xretry =
			__le32_to_cpu(ps->wal.tx.pdev_cont_xretry);
		stats->pdev_tx_timeout =
			__le32_to_cpu(ps->wal.tx.pdev_tx_timeout);
		stats->pdev_resets = __le32_to_cpu(ps->wal.tx.pdev_resets);
		stats->phy_underrun = __le32_to_cpu(ps->wal.tx.phy_underrun);
		stats->txop_ovf = __le32_to_cpu(ps->wal.tx.txop_ovf);

		stats->mid_ppdu_route_change =
			__le32_to_cpu(ps->wal.rx.mid_ppdu_route_change);
		stats->status_rcvd = __le32_to_cpu(ps->wal.rx.status_rcvd);
		stats->r0_frags = __le32_to_cpu(ps->wal.rx.r0_frags);
		stats->r1_frags = __le32_to_cpu(ps->wal.rx.r1_frags);
		stats->r2_frags = __le32_to_cpu(ps->wal.rx.r2_frags);
		stats->r3_frags = __le32_to_cpu(ps->wal.rx.r3_frags);
		stats->htt_msdus = __le32_to_cpu(ps->wal.rx.htt_msdus);
		stats->htt_mpdus = __le32_to_cpu(ps->wal.rx.htt_mpdus);
		stats->loc_msdus = __le32_to_cpu(ps->wal.rx.loc_msdus);
		stats->loc_mpdus = __le32_to_cpu(ps->wal.rx.loc_mpdus);
		stats->oversize_amsdu =
			__le32_to_cpu(ps->wal.rx.oversize_amsdu);
		stats->phy_errs = __le32_to_cpu(ps->wal.rx.phy_errs);
		stats->phy_err_drop = __le32_to_cpu(ps->wal.rx.phy_err_drop);
		stats->mpdu_errs = __le32_to_cpu(ps->wal.rx.mpdu_errs);

		tmp += sizeof(struct wmi_pdev_stats);
	}

	/* 0 or max vdevs */
	/* Currently firmware does not support VDEV stats */
	if (num_vdev_stats) {
		struct wmi_vdev_stats *vdev_stats;

		for (i = 0; i < num_vdev_stats; i++) {
			vdev_stats = (struct wmi_vdev_stats *)tmp;
			tmp += sizeof(struct wmi_vdev_stats);
		}
	}

	if (num_peer_stats) {
		struct wmi_peer_stats *peer_stats;
		struct ath10k_peer_stat *s;

		stats->peers = num_peer_stats;

		for (i = 0; i < num_peer_stats; i++) {
			peer_stats = (struct wmi_peer_stats *)tmp;
			s = &stats->peer_stat[i];

			WMI_MAC_ADDR_TO_CHAR_ARRAY(&peer_stats->peer_macaddr,
						   s->peer_macaddr);
			s->peer_rssi = __le32_to_cpu(peer_stats->peer_rssi);
			s->peer_tx_rate =
				__le32_to_cpu(peer_stats->peer_tx_rate);

			tmp += sizeof(struct wmi_peer_stats);
		}
	}

	mutex_unlock(&ar->conf_mutex);
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
