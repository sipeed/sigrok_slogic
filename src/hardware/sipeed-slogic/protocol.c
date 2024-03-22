/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2024 taorye <taorye@outlook.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include "protocol.h"

SR_PRIV int sipeed_slogic_acquisition_handler(int fd, int revents,
					      void *cb_data)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct drv_context *drvc;

	(void)fd;
	(void)revents;

	sdi = cb_data;
	devc = sdi->priv;
	drvc = sdi->driver->context;

	if (!devc->running) {
		// release all transfer
		for (GSList *l = devc->transfers_ready; l; l = g_list_next(l)) {
			struct libusb_transfer *transfer = l->data;
			g_free(transfer->buffer);
			libusb_free_transfer(transfer);
		}
		if (devc->transfers_count !=
		    g_list_length(devc->transfers_ready))
			sr_err("Where have we missed these transfers?");
		g_list_free(devc->transfers_submitted);
		g_list_free(devc->transfers_ready);
		devc->transfers_count = 0;

		feed_queue_logic_flush(devc->logic_fq);
		feed_queue_logic_free(devc->logic_fq);

		usb_source_remove(sdi->session, drvc->sr_ctx);
		std_session_send_df_end(sdi);
	} else if (devc->stop_req) {
		devc->stop_req = FALSE;
		devc->running = FALSE;
		uint64_t transfers_submitted_count =
			g_list_length(devc->transfers_submitted);
		// cancel all transfer
		if (transfers_submitted_count) {
			for (GSList *l = devc->transfers_submitted; l;
			     l = g_list_next(l)) {
				struct libusb_transfer *transfer = l->data;
				libusb_cancel_transfer(transfer);
			}
			sr_info("Transfer canceled %u.",
				transfers_submitted_count);
			libusb_handle_events_completed(drvc->sr_ctx->libusb_ctx,
						       NULL);
		}
	} else {
		if (g_list_length(devc->transfers_submitted)) {
			struct timeval tv;
			tv.tv_sec = tv.tv_usec = 0;
			libusb_handle_events_timeout_completed(
				drvc->sr_ctx->libusb_ctx, &tv, NULL);
		}

		sr_spew("Transfer ready/submitted/all=%2u/%2u/%2u.",
			g_list_length(devc->transfers_ready),
			g_list_length(devc->transfers_submitted),
			devc->transfers_count);

		if (sr_sw_limits_check(&devc->sw_limits)) {
			sr_dev_acquisition_stop(sdi);
		} else if (g_list_length(devc->transfers_ready)) {
			//  prepare & submit transfer
			for (GSList *l = devc->transfers_ready,
				    *ll = g_list_next(l);
			     l; l = ll, ll = g_list_next(l)) {
				struct libusb_transfer *transfer = l->data;

				uint64_t transfer_size =
					transfer->length; // 4MB
				uint64_t transfer_timeout =
					1000; // 4M/300Mi=13.981014ms

				transfer->timeout =
					(3 +
					 g_list_length(
						 devc->transfers_submitted)) *
					devc->transfers_base_timeout;

				int ret = libusb_submit_transfer(transfer);
				if (ret) {
					sr_info("Transfer submit failed(%s) will be freed.",
						libusb_error_name(ret));
					g_free(transfer->buffer);
					libusb_free_transfer(transfer);
					devc->transfers_ready =
						g_list_delete_link(
							devc->transfers_ready,
							l);
					devc->transfers_count -= 1;
				} else {
					devc->transfers_ready =
						g_list_remove_link(
							devc->transfers_ready,
							l);
					devc->transfers_submitted = g_list_concat(
						devc->transfers_submitted, l);
				}
			}
		} else if (!g_list_length(devc->transfers_submitted)) {
			sr_warn("Transfer empty!");
			sr_dev_acquisition_stop(sdi);
		}
	}

	return TRUE;
}

SR_PRIV void LIBUSB_CALL
sipeed_slogic_libusb_transfer_cb(struct libusb_transfer *transfer)
{
	const struct sr_dev_inst *sdi;
	struct dev_context *devc;
	struct sr_usb_dev_inst *udi;

	sdi = transfer->user_data;
	devc = sdi->priv;
	udi = sdi->conn;

	if (devc->running) {
		sr_dbg("Transfer CB: status=%d, length=0x%x.", transfer->status,
		       transfer->actual_length);
		switch (transfer->status) {
		case LIBUSB_TRANSFER_COMPLETED: {
			uint64_t remain_samples;
			sr_sw_limits_get_remain(&devc->sw_limits,
						&remain_samples, NULL, NULL,
						NULL);
			uint64_t received_sample_count =
				transfer->actual_length * 8 /
				LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern);
			if (received_sample_count > remain_samples)
				received_sample_count = remain_samples;
			feed_queue_logic_submit_many(devc->logic_fq,
						     transfer->buffer,
						     received_sample_count);
			sr_sw_limits_update_samples_read(&devc->sw_limits,
							 received_sample_count);
		} break;
		default:
			break;
		}
	}

	GList *l = g_list_find(devc->transfers_submitted, transfer);
	if (!l)
		sr_err("Why this transfer[%p] not in submitted?", transfer);
	devc->transfers_submitted =
		g_list_remove_link(devc->transfers_submitted, l);
	devc->transfers_ready = g_list_concat(devc->transfers_ready, l);
}
