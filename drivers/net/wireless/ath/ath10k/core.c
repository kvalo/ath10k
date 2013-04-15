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

#include <linux/module.h>
#include <linux/firmware.h>

#include "core.h"
#include "mac.h"
#include "htc.h"
#include "hif.h"
#include "wmi.h"
#include "bmi.h"
#include "debug.h"
#include "htt.h"

unsigned int debug_mask;
static bool uart_print;
static unsigned int ath10k_p2p;
module_param(debug_mask, uint, 0644);
module_param(uart_print, bool, 0644);
module_param(ath10k_p2p, uint, 0644);
MODULE_PARM_DESC(debug_mask, "Debugging mask");
MODULE_PARM_DESC(uart_print, "Uart target debugging");
MODULE_PARM_DESC(ath10k_p2p, "Enable ath10k P2P support");

enum ath10k_file {
	ATH10K_FILE_OTP,
	ATH10K_FILE_FIRMWARE,
	ATH10K_FILE_BOARD_DATA,
};

static const struct ath10k_hw_params ath10k_hw_params_list[] = {
	{
		.id = AR9888_HW_1_0_VERSION,
		.name = "ar9888 rev1 (build 44)",
		.patch_load_addr = AR9888_HW_1_0_PATCH_LOAD_ADDR,
		.fw = {
			.dir = AR9888_HW_1_0_FW_DIR,
			.fw = AR9888_HW_1_0_FW_FILE,
			.otp = AR9888_HW_1_0_OTP_FILE,
			.board = AR9888_HW_1_0_BOARD_DATA_FILE,
		},
	},
	{
		.id = AR9888_HW_2_0_VERSION,
		.name = "ar9888 rev2 (build 348)",
		.patch_load_addr = AR9888_HW_2_0_PATCH_LOAD_ADDR,
		.fw = {
			.dir = AR9888_HW_2_0_FW_DIR,
			.fw = AR9888_HW_2_0_FW_FILE,
			.otp = AR9888_HW_2_0_OTP_FILE,
			.board = AR9888_HW_2_0_BOARD_DATA_FILE,
		},
	},
};

static void ath10k_target_failure(struct ath10k *ar, int status)
{
	ath10k_dbg(ATH10K_DBG_CORE, "%s\n", __func__);
}

static void ath10k_send_suspend_complete(struct ath10k *ar)
{
	ath10k_dbg(ATH10K_DBG_CORE, "%s\n", __func__);

#if defined(CONFIG_PM_SLEEP)
	ar->is_target_paused = true;
	wake_up(&ar->event_queue);
#endif
}

static int ath10k_check_fw_version(struct ath10k *ar)
{
	char version[32];

	if (ar->fw_version_major >= SUPPORTED_FW_MAJOR &&
	    ar->fw_version_minor >= SUPPORTED_FW_MINOR &&
	    ar->fw_version_release >= SUPPORTED_FW_RELEASE &&
	    ar->fw_version_build >= SUPPORTED_FW_BUILD)
		return 0;

	snprintf(version, sizeof(version), "%u.%u.%u.%u",
		 SUPPORTED_FW_MAJOR, SUPPORTED_FW_MINOR,
		 SUPPORTED_FW_RELEASE, SUPPORTED_FW_BUILD);

	ath10k_err("Firmware %s is not supported. Please use version %s (or newer)\n",
		   ar->hw->wiphy->fw_version, version);

	return -EINVAL;
}

static int ath10k_init_connect_htc(struct ath10k *ar)
{
	int status;
	struct htc_service_connect_req connect;

	memset(&connect, 0, sizeof(connect));

	connect.ep_callbacks.context = ar;
	connect.ep_callbacks.ep_rx_complete = NULL;

	status = wmi_connect_htc_service(ar);
	if (status)
		goto conn_fail;

	/* Start HTC */
	status = ath10k_htc_start(ar->htc_handle);
	if (status)
		goto conn_fail;

	/* Wait for WMI event to be ready */
	status = wmi_wait_for_service_ready(ar);
	if (status <= 0) {
		ath10k_warn("wmi service ready event not received");
		status = -ETIMEDOUT;
		goto timeout;
	}

	ath10k_dbg(ATH10K_DBG_CORE, "core wmi ready\n");
	return 0;

timeout:
	ath10k_htc_stop(ar->htc_handle);
conn_fail:
	return status;
}

static int ath10k_init_configure_target(struct ath10k *ar)
{
	__le32 param_target;
	u32 param_host;
	int ret;
	u32 host_addr;

	/* tell target which HTC version it is used*/
	param_target = __cpu_to_le32(HTC_PROTOCOL_VERSION);
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_app_host_interest));
	ret = ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);
	if (ret) {
		ath10k_err("settings HTC version failed\n");
		return ret;
	}

	/* set the firmware mode to STA/IBSS/AP */
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_option_flag));
	ret = ath10k_bmi_read_memory(ar, host_addr, (u8 *)&param_target, 4);
	param_host = __le32_to_cpu(param_target);
	if (ret) {
		ath10k_err("setting firmware mode (1/2) failed\n");
		return ret;
	}

	/* TODO following parameters need to be re-visited. */
	/* num_device */
	param_host |= (1 << HI_OPTION_NUM_DEV_SHIFT);
	/* Firmware mode */
	/* FIXME: Why FW_MODE_AP ??.*/
	param_host |= (HI_OPTION_FW_MODE_AP << HI_OPTION_FW_MODE_SHIFT);
	/* mac_addr_method */
	param_host |= (1 << HI_OPTION_MAC_ADDR_METHOD_SHIFT);
	/* firmware_bridge */
	param_host |= (0 << HI_OPTION_FW_BRIDGE_SHIFT);
	/* fwsubmode */
	param_host |= (0 << HI_OPTION_FW_SUBMODE_SHIFT);

	param_target = __cpu_to_le32(param_host);
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_option_flag));
	ret = ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);
	if (ret) {
		ath10k_err("setting firmware mode (2/2) failed\n");
		return ret;
	}

	param_target = __cpu_to_le32(0);
	/* We do all byte-swapping on the host */
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_be));
	ret = ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);
	if (ret) {
		ath10k_err("setting host CPU BE mode failed\n");
		return ret;
	}

	/* FW descriptor/Data swap flags */
	param_target = __cpu_to_le32(0);
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_fw_swap));
	ret = ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);

	if (ret) {
		ath10k_err("setting FW data/desc swap flags failed\n");
		return ret;
	}

	return 0;
}

static int ath10k_init_transfer_bin_file(struct ath10k *ar,
					 enum ath10k_file file,
					 u32 address, bool compressed)
{
	int status = 0;
	char filename[100];
	const struct firmware *fw_entry;
	u32 fw_entry_size;
	u8 *temp_eeprom = NULL, *fw_buf = NULL;
	u32 board_data_size;

	switch (file) {
	default:
		ath10k_err("%s: unknown file type\n", __func__);
		return -1;

	case ATH10K_FILE_OTP:
		if (!ar->hw_params.fw.otp) {
			ath10k_err("%s: OTP file not defined\n", __func__);
			return -ENOENT;
		}
		snprintf(filename, sizeof(filename), "%s/%s",
			 ar->hw_params.fw.dir, ar->hw_params.fw.otp);
		break;

	case ATH10K_FILE_FIRMWARE:
		if (!ar->hw_params.fw.fw) {
			ath10k_err("%s: FW file not defined\n", __func__);
			return -ENOENT;
		}
		snprintf(filename, sizeof(filename), "%s/%s",
			 ar->hw_params.fw.dir, ar->hw_params.fw.fw);
		break;

	case ATH10K_FILE_BOARD_DATA:
		if (!ar->hw_params.fw.board) {
			ath10k_err("%s: board file not defined\n", __func__);
			return -ENOENT;
		}
		snprintf(filename, sizeof(filename), "%s/%s",
			 ar->hw_params.fw.dir, ar->hw_params.fw.board);
		break;

	}

	if (request_firmware(&fw_entry, filename, ar->dev) != 0) {
		if (file == ATH10K_FILE_OTP)
			return -ENOENT;

		ath10k_err("%s: failed to get %s\n", __func__, filename);
		return -1;
	}

	fw_entry_size = fw_entry->size;
	fw_buf = (u8 *)fw_entry->data;

	if (file == ATH10K_FILE_BOARD_DATA && fw_entry->data) {
		__le32 param_target;
		u32 board_ext_address;
		int32_t board_ext_data_size;
		u32 host_addr;

		temp_eeprom = kmalloc(fw_entry_size, GFP_ATOMIC);
		if (!temp_eeprom) {
			ath10k_err("%s: memory allocation failed\n", __func__);
			status = -ENOMEM;
			goto exit_fw;
		}

		memcpy(temp_eeprom, fw_buf, fw_entry_size);

		switch (ar->target_type) {
		default:
			board_ext_data_size = 0;
			break;
		case TARGET_TYPE_AR9888:
			board_data_size =  AR9888_BOARD_DATA_SZ;
			board_ext_data_size = AR9888_BOARD_EXT_DATA_SZ;
			break;
		}

		/* Determine where in Target RAM to write Board Data */
		host_addr = host_interest_item_address(ar->target_type,
						       HI_ITEM(hi_board_ext_data));
		ath10k_bmi_read_memory(ar, host_addr, (u8 *)&param_target, 4);
		board_ext_address = __le32_to_cpu(param_target);

		ath10k_dbg(ATH10K_DBG_BOOT,
			   "ath10k: Board extended Data download addr: 0x%x\n",
			   board_ext_address);

		/*
		 * Check whether the target has allocated memory for extended
		 * board data and file contains extended board data
		 */
		if (board_ext_address && (fw_entry_size == (board_data_size +
						board_ext_data_size))) {
			__le32 param_target;

			status = ath10k_bmi_write_memory(ar, board_ext_address,
							 (u8 *)(((unsigned long)temp_eeprom) +
							 board_data_size),
							 board_ext_data_size);

			if (status != 0) {
				ath10k_err("ath10k: BMI operation failed\n");
				goto exit_buf;
			}

			/*
			 * Record the fact that extended board Data IS initialized
			 */
			param_target = __cpu_to_le32((board_ext_data_size << 16) | 1);
			host_addr = host_interest_item_address(ar->target_type,
							       HI_ITEM(hi_board_ext_data_config));
			ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);

			fw_entry_size = board_data_size;
		}
	}

	if (compressed)
		status = ath10k_bmi_fast_download(ar, address,
						  fw_buf, fw_entry_size);
	else {
		if (file == ATH10K_FILE_BOARD_DATA && fw_entry->data)
			status = ath10k_bmi_write_memory(ar, address,
							 temp_eeprom,
							 fw_entry_size);
		else
			status = ath10k_bmi_write_memory(ar, address,
							 fw_buf,
							 fw_entry_size);
	}

exit_buf:
	kfree(temp_eeprom);

	if (status != 0)
		ath10k_err("BMI operation failed: %d\n", __LINE__);
exit_fw:
	release_firmware(fw_entry);
	return status;
}

static int ath10k_init_download_firmware(struct ath10k *ar)
{
	__le32 param_target;
	u32 param_host, address = 0;
	int status;
	u32 host_addr;

	/* Transfer Board Data from Target EEPROM to Target RAM */
	/* Determine where in Target RAM to write Board Data */
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_board_data));
	ath10k_bmi_read_memory(ar, host_addr, (u8 *)&param_target, 4);
	address = __le32_to_cpu(param_target);

	if (!address) {
		ath10k_err("Target address not known!\n");
		return -1;
	}

	/* Write EEPROM data to Target RAM */
	status = ath10k_init_transfer_bin_file(ar, ATH10K_FILE_BOARD_DATA,
				      address, false);
	if (status) {
		ath10k_err("boardData file upload failed!\n");
		return status;
	}

	/* Record the fact that Board Data is initialized */
	param_target = __cpu_to_le32(1);
	host_addr = host_interest_item_address(ar->target_type,
					       HI_ITEM(hi_board_data_initialized));
	ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);

	/* Transfer One Time Programmable data */
	address = ar->hw_params.patch_load_addr;
	ath10k_dbg(ATH10K_DBG_BOOT,
		   "Using 0x%x for the remainder of init\n", address);

	status = ath10k_init_transfer_bin_file(ar, ATH10K_FILE_OTP,
					       address, true);
	if (status == 0) {
		/* Execute the OTP code only if entry found and downloaded */
		param_host = 0;
		ath10k_bmi_execute(ar, address, &param_host);
	} else if (status == -1)
		return status;

	/*
	 * Download Target firmware
	 */
	status = ath10k_init_transfer_bin_file(ar, ATH10K_FILE_FIRMWARE,
					       address, true);
	if (status) {
		ath10k_err("firmware upload failed\n");
		return status;
	}

	if (uart_print) {
		/* Configure GPIO AR9888 UART */
		param_target = __cpu_to_le32(7);
		host_addr = host_interest_item_address(ar->target_type,
						       HI_ITEM(hi_dbg_uart_txpin));
		ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);

		param_target = __cpu_to_le32(1);
		host_addr = host_interest_item_address(ar->target_type,
						       HI_ITEM(hi_serial_enable));
		ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);
	} else {
		/*
		 * Explicitly setting UART prints to zero as target turns it on
		 * based on scratch registers.
		 */
		param_target = __cpu_to_le32(0);
		host_addr = host_interest_item_address(ar->target_type,
						       HI_ITEM(hi_serial_enable));
		ath10k_bmi_write_memory(ar, host_addr, (u8 *)&param_target, 4);
	}

	ath10k_dbg(ATH10K_DBG_CORE, "Firmware downloaded\n");
	return 0;
}

static int ath10k_init_hw_params(struct ath10k *ar)
{
	const struct ath10k_hw_params *uninitialized_var(hw_params);
	int i;

	for (i = 0; i < ARRAY_SIZE(ath10k_hw_params_list); i++) {
		hw_params = &ath10k_hw_params_list[i];

		if (hw_params->id == ar->target_version)
			break;
	}

	if (i == ARRAY_SIZE(ath10k_hw_params_list)) {
		ath10k_err("unsupported hardware version: 0x%x\n",
			   ar->target_version);
		return -EINVAL;
	}

	ar->hw_params = *hw_params;

	ath10k_info("target_ver 0x%x target_type 0x%x name %s\n",
		    ar->target_version, ar->target_type, ar->hw_params.name);

	return 0;
}

struct ath10k *ath10k_core_create(void *hif_priv, struct device *dev,
				  enum ath10k_bus bus, u32 target_type,
				  const struct ath10k_hif_ops *hif_ops)
{
	struct ath10k *ar;
	struct ath_common *common;

	ar = ath10k_mac_create();
	if (!ar)
		return NULL;

	common = ath10k_common(ar);
	common->priv = ar;
	common->hw = ar->hw;

	ar->p2p = !!ath10k_p2p;
	ar->dev = dev;
	ar->target_type = target_type;

	ar->hif.priv = hif_priv;
	ar->hif.ops = hif_ops;
	ar->hif.bus = bus;

	ar->free_vdev_map = 0xFF; /* 8 vdevs */

	init_completion(&ar->scan.started);
	init_completion(&ar->scan.completed);
	spin_lock_init(&ar->scan.lock);

	init_completion(&ar->install_key_done);
	init_completion(&ar->vdev_setup_done);
	mutex_init(&ar->vdev_mtx);

	setup_timer(&ar->scan.timeout, ath10k_reset_scan, (unsigned long)ar);

	ar->workqueue = create_singlethread_workqueue("ath10k_wq");
	if (!ar->workqueue)
		goto err_wq;

	mutex_init(&ar->conf_mutex);
	spin_lock_init(&ar->data_lock);

	INIT_LIST_HEAD(&ar->peers);
	init_waitqueue_head(&ar->peer_mapping_wq);

	init_completion(&ar->offchan_tx_completed);
	INIT_WORK(&ar->offchan_tx_work, ath10k_offchan_tx_work);
	skb_queue_head_init(&ar->offchan_tx_queue);

#if defined(CONFIG_PM_SLEEP)
	init_waitqueue_head(&ar->event_queue);
#endif
	return ar;

err_wq:
	ath10k_mac_destroy(ar);
	return NULL;
}
EXPORT_SYMBOL(ath10k_core_create);

void ath10k_core_destroy(struct ath10k *ar)
{
	flush_workqueue(ar->workqueue);
	destroy_workqueue(ar->workqueue);

	ath10k_mac_destroy(ar);
}
EXPORT_SYMBOL(ath10k_core_destroy);


int ath10k_core_register(struct ath10k *ar)
{
	struct htc_target_cb htc_cb;
	struct bmi_target_info target_info;
	int status;

	memset(&target_info, 0, sizeof(target_info));
	status = ath10k_bmi_get_target_info(ar, &target_info);
	if (status)
		goto err;

	ar->target_type = target_info.type;
	ar->target_version = target_info.version;
	ar->hw->wiphy->hw_version = target_info.version;

	status = ath10k_init_hw_params(ar);
	if (status)
		goto err;

	if (ath10k_init_configure_target(ar)) {
		status = -EINVAL;
		goto err;
	}

	if (ath10k_init_download_firmware(ar)) {
		status = -EIO;
		/* TODO: check if there's really nothing to clean */
		goto err;
	}

	htc_cb.target_failure = ath10k_target_failure;
	htc_cb.target_send_suspend_complete = ath10k_send_suspend_complete;

	ar->htc_handle = ath10k_htc_create(ar, &htc_cb);
	if (ar->htc_handle == NULL) {
		status = -ENOMEM;
		goto err;
	}

	status = ath10k_bmi_done(ar);
	if (status)
		goto err_htc_destroy;

	status = wmi_attach(ar);
	if (status) {
		ath10k_err("WMI attach failed: %d\n", status);
		goto err_htc_destroy;
	}

	status = ath10k_htc_wait_target(ar->htc_handle);
	if (status)
		goto err_wmi_detach;

	ar->htt = ath10k_htt_attach(ar, ar->htc_handle);
	if (!ar->htt) {
		status = -ENOMEM;
		goto err_wmi_detach;
	}

	status = ath10k_init_connect_htc(ar);
	if (status)
		goto err_htt_detach;

	status = ath10k_check_fw_version(ar);
	if (status)
		goto err_disconnect_htc;

	wmi_cmd_init(ar);

	status = wmi_wait_for_unified_ready(ar);
	if (status <= 0) {
		ath10k_warn("wmi unified ready event not received\n");
		status = -ETIMEDOUT;
		goto err_disconnect_htc;
	}

	status = ath10k_htt_attach_target(ar->htt);
	if (status)
		goto err_disconnect_htc;

	status = ath10k_mac_register(ar);
	if (status)
		goto err_disconnect_htc;

	status = ath10k_debug_create(ar);
	if (status) {
		ath10k_warn("unable to initialize debugfs\n");
		goto err_unregister_mac;
	}

	return 0;
/*
 * TODO: Revisit this once more when decided on exact
 * start sequece and callbacks
 */
err_unregister_mac:
	ath10k_mac_unregister(ar);
err_disconnect_htc:
	ath10k_htc_stop(ar->htc_handle);
err_htt_detach:
	ath10k_htt_detach(ar->htt);
err_wmi_detach:
	wmi_detach(ar);
err_htc_destroy:
	ath10k_htc_destroy(ar->htc_handle);
err:
	return status;
}
EXPORT_SYMBOL(ath10k_core_register);

void ath10k_core_unregister(struct ath10k *ar)
{
	/*
	 * FIXME: the ordering here may be broken!
	 *        mac_unregister must be done before htc is stopped,
	 *        since it might want to remove interfaces -> vdev_remove
	 */
	ath10k_mac_unregister(ar);

	if (!WARN_ON(!ar->htc_handle))
		ath10k_htc_stop(ar->htc_handle);

	/* FIXME: we may need to free up htt tx desc here too */
	ath10k_htt_detach(ar->htt);

	wmi_detach(ar);

	ath10k_htc_destroy(ar->htc_handle);
}
EXPORT_SYMBOL(ath10k_core_unregister);

MODULE_AUTHOR("Qualcomm Atheros");
MODULE_DESCRIPTION("Core module for AR9888 PCIe devices.");
MODULE_LICENSE("Dual BSD/GPL");
