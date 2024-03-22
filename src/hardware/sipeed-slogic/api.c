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

static const uint32_t s_scanopts[] = {
	SR_CONF_CONN, // a USB device
};

static const uint32_t s_drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
	// SR_CONF_OSCILLOSCOPE,
};

static const uint32_t s_devopts[] = {
	SR_CONF_CONTINUOUS, SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_LIMIT_MSEC | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_LIMIT_FRAMES | SR_CONF_GET | SR_CONF_SET,
	// SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	// SR_CONF_TRIGGER_MATCH                             | SR_CONF_LIST,
};

static const uint32_t s_devopts_cg_logic[] = {
	SR_CONF_PATTERN_MODE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};

static const char *s_logic_pattern_str[] = {
	[PATTERN_1CH] = "1ch", [PATTERN_2CH] = "2ch",	[PATTERN_4CH] = "4ch",
	[PATTERN_8CH] = "8ch", [PATTERN_16CH] = "16ch",
};

static const uint64_t s_samplerates_supported[] = {
	/* 160M = 2*2*2*2*2*5M */
	/* x 16ch */
	SR_MHZ(1),
	SR_MHZ(2),
	SR_MHZ(5),
	SR_MHZ(10),
	SR_MHZ(20),
	SR_MHZ(50),
	SR_MHZ(100),
	SR_MHZ(120),
	SR_MHZ(150),
	/* x 8ch */
	SR_MHZ(200),
	SR_MHZ(300),
	/* x 4ch */
	SR_MHZ(400),
	SR_MHZ(600),
	/* x 2ch */
	SR_MHZ(1200),
};

static struct sr_dev_driver sipeed_slogic_driver_info;

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	struct drv_context *drvc;
	GSList *devices;
	const char *conn;
	GSList *l;

	(void)options;

	devices = NULL;
	conn = NULL;
	drvc = di->context;

	/* scan for devices, either based on a SR_CONF_CONN option
	 * or on a USB scan. */
	for (l = options; l; l = l->next) {
		struct sr_config *option = l->data;
		switch (option->key) {
		case SR_CONF_CONN:
			conn = g_variant_get_string(option->data, NULL);
			sr_info("use conn=%s.", conn);
			break;
		}
	}

	/* TODO: scan for devices, either based on a SR_CONF_CONN option
	 * or on a USB scan. */
	GSList *udis = sr_usb_find(drvc->sr_ctx->libusb_ctx, "359f.3001");
	for (l = udis; l; l = l->next) {
		struct sr_usb_dev_inst *udi = l->data;
		if (SR_OK != sr_usb_open(drvc->sr_ctx->libusb_ctx, udi))
			continue;
		char *Manufacturer, *Product, *SerialNumber, *Version;
		char cbuf[128];
		struct libusb_device_descriptor des;
		libusb_get_device_descriptor(libusb_get_device(udi->devhdl),
					     &des);

		libusb_get_string_descriptor_ascii(
			udi->devhdl, des.iManufacturer, cbuf, sizeof(cbuf));
		Manufacturer = g_strdup(cbuf);
		libusb_get_string_descriptor_ascii(udi->devhdl, des.iProduct,
						   cbuf, sizeof(cbuf));
		Product = g_strdup(cbuf);
		libusb_get_string_descriptor_ascii(
			udi->devhdl, des.iSerialNumber, cbuf, sizeof(cbuf));
		SerialNumber = g_strdup(cbuf);
		sr_snprintf_ascii(cbuf, sizeof(cbuf), "%x.%x",
				  0xff & (des.bcdDevice >> 8),
				  0xff & (des.bcdDevice >> 0));
		Version = g_strdup(cbuf);
		sr_usb_close(udi);

		struct sr_dev_inst *sdi =
			sr_dev_inst_user_new(Manufacturer, Product, Version);
		sdi->serial_num = SerialNumber;

		struct dev_context *devc =
			g_malloc0(sizeof(struct dev_context));

		{ // init
			devc->logic_pattern_max = PATTERN_16CH;
			devc->logic_channel_start = 0;
			devc->samplerate_max = LOGIC_PATTERN_TO_MAX_SAMPLERATE(
				PATTERN_16CH); // 150MHZ
		}

		devc->samplerate = devc->samplerate_max;

		devc->logic_pattern = devc->logic_pattern_max;
		size_t num_logic_channels =
			LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern);
		if (num_logic_channels > 0) {
			/* Logic channels, all in one channel group. */
			struct sr_channel_group *cg =
				sr_channel_group_new(sdi, "Logic", NULL);
			char channel_name[8];
			for (size_t i = 0; i < num_logic_channels; i++) {
				sr_snprintf_ascii(channel_name,
						  sizeof(channel_name), "D%d",
						  i);
				struct sr_channel *ch =
					sr_channel_new(sdi, i, SR_CHANNEL_LOGIC,
						       TRUE, channel_name);
				cg->channels = g_slist_append(cg->channels, ch);
			}
		}

		sr_sw_limits_init(&devc->sw_limits);

		sdi->status = SR_ST_INACTIVE;
		sdi->conn = udi;
		sdi->inst_type = SR_INST_USB;
		sdi->priv = devc;

		devices = g_slist_append(devices, sdi);
	}

	return std_scan_complete(di, devices);
}

static int dev_open(struct sr_dev_inst *sdi)
{
	int ret;
	struct sr_usb_dev_inst *udi = sdi->conn;
	struct drv_context *drvc = sdi->driver->context;

	ret = SR_OK;
	/* TODO: get handle from sdi->conn and open it. */
	ret = sr_usb_open(drvc->sr_ctx->libusb_ctx, udi);
	if (SR_OK != ret)
		return ret;

	// claim interface 0 (the first) of device (mine had jsut 1)
	ret = libusb_claim_interface(udi->devhdl, 0);
	if (LIBUSB_SUCCESS != ret) {
		sr_err("Interface claim failed(%s)!.", libusb_error_name(ret));
		sr_usb_close(udi);
		ret = SR_ERR_IO;
		return ret;
	}

	return ret;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	int ret;
	struct sr_usb_dev_inst *udi = sdi->conn;

	ret = SR_OK;
	/* TODO: get handle from sdi->conn and close it. */
	/* Handle sdi->priv */
	ret = libusb_release_interface(udi->devhdl, 0);
	if (LIBUSB_SUCCESS != ret) {
		sr_err("Interface declaim failed(%s)!.",
		       libusb_error_name(ret));
		ret = SR_ERR_IO;
	}

	sr_usb_close(udi);
	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
		      const struct sr_dev_inst *sdi,
		      const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;

	if (!sdi)
		return SR_ERR_ARG;

	ret = SR_OK;
	devc = sdi->priv;
	switch (key) {
	/* TODO */
	case SR_CONF_SAMPLERATE:
		if (devc->samplerate > devc->samplerate_max)
			sr_config_set(
				sdi, cg, key,
				g_variant_new_uint64(devc->samplerate_max));
		*data = g_variant_new_uint64(devc->samplerate);
		break;
	case SR_CONF_PATTERN_MODE:
		if (!cg)
			return SR_ERR_CHANNEL_GROUP;
		/* Any channel in the group will do. */
		struct sr_channel *ch = cg->channels->data;
		if (ch->type == SR_CHANNEL_LOGIC)
			*data = g_variant_new_string(
				s_logic_pattern_str[devc->logic_pattern]);
		else
			return SR_ERR_BUG;
		break;
	case SR_CONF_LIMIT_SAMPLES:
	case SR_CONF_LIMIT_MSEC:
	case SR_CONF_LIMIT_FRAMES:
		ret = sr_sw_limits_config_get(&devc->sw_limits, key, data);
		break;
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
		      const struct sr_dev_inst *sdi,
		      const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;

	devc = sdi->priv;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	case SR_CONF_SAMPLERATE:
		devc->samplerate = g_variant_get_uint64(data);
		break;
	case SR_CONF_PATTERN_MODE:
		if (!cg)
			return SR_ERR_CHANNEL_GROUP;
		struct sr_channel *ch;
		ch = cg->channels->data;

		if (ch->type == SR_CHANNEL_LOGIC) {
			int logic_pattern = std_str_idx(
				data, ARRAY_AND_SIZE(s_logic_pattern_str));
			if (logic_pattern < 0)
				return SR_ERR_ARG;
			devc->logic_pattern = logic_pattern;
			devc->samplerate_max = LOGIC_PATTERN_TO_MAX_SAMPLERATE(
				devc->logic_pattern);
			{ // enable channels
				uint64_t logic_channels_start =
					devc->logic_channel_start;
				uint64_t num_logic_channels =
					LOGIC_PATTERN_TO_CHANNELS(
						devc->logic_pattern);

				struct sr_channel *start_channel;
				for (GSList *l = cg->channels; l;
				     l = g_slist_next(l)) {
					ch = l->data;
					ch->enabled = FALSE;
					if (ch->index == logic_channels_start)
						start_channel = ch;
				}
				sr_dev_channel_enable(start_channel, TRUE);
			}
		} else
			return SR_ERR_BUG;
		break;
	case SR_CONF_LIMIT_SAMPLES:
	case SR_CONF_LIMIT_MSEC:
	case SR_CONF_LIMIT_FRAMES:
		ret = sr_sw_limits_config_set(&devc->sw_limits, key, data);
		break;
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_channel_set(const struct sr_dev_inst *sdi,
			      struct sr_channel *ch, unsigned int changes)
{
	struct dev_context *devc;
	devc = sdi->priv;

	if (!(changes & SR_CHANNEL_SET_ENABLED))
		return SR_OK;

	uint64_t logic_channel_start = devc->logic_channel_start;
	uint64_t num_logic_channels =
		LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern);
	uint64_t max_num_logic_channels =
		LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern_max);
	if (logic_channel_start + num_logic_channels > max_num_logic_channels)
		logic_channel_start =
			max_num_logic_channels - num_logic_channels;

	if (ch->enabled) {
		if (ch->index < logic_channel_start)
			logic_channel_start = ch->index;
		else if (ch->index >= logic_channel_start + num_logic_channels)
			logic_channel_start =
				ch->index + 1 - num_logic_channels;
	} else {
		if (ch->index >= logic_channel_start &&
		    ch->index < logic_channel_start + num_logic_channels) {
			gboolean place_left = (ch->index - 0) >=
					      num_logic_channels;
			gboolean place_right =
				(max_num_logic_channels - 1 - ch->index) >=
				num_logic_channels;
			uint64_t remain_left = ch->index - logic_channel_start;
			uint64_t remain_right = logic_channel_start +
						num_logic_channels - 1 -
						ch->index;

			if (place_right &&
			    (!place_left || remain_right > remain_left))
				logic_channel_start = ch->index + 1;
			else if (place_left)
				logic_channel_start =
					ch->index - num_logic_channels;
		}
	}
	sr_dbg("%s %sselected.", ch->name, ch->enabled ? "" : "un");

	devc->logic_channel_start = logic_channel_start;

	struct sr_channel_group *cg = sdi->channel_groups->data;
	if (g_slist_find(cg->channels, ch)) {
		for (GSList *l = cg->channels; l; l = g_slist_next(l)) {
			struct sr_channel *my_ch = l->data;
			my_ch->enabled =
				(my_ch->index >= logic_channel_start &&
				 my_ch->index < logic_channel_start +
							num_logic_channels) ?
					TRUE :
					FALSE;
		}
		sr_info("Channel enabled %uch@%u.", num_logic_channels,
			logic_channel_start);
	}

	return SR_OK;
}

static int config_list(uint32_t key, GVariant **data,
		       const struct sr_dev_inst *sdi,
		       const struct sr_channel_group *cg)
{
	int ret;

	ret = SR_OK;
	/* TODO */
	if (!cg) {
		switch (key) {
		case SR_CONF_SCAN_OPTIONS:
		case SR_CONF_DEVICE_OPTIONS:
			ret = STD_CONFIG_LIST(key, data, sdi, cg, s_scanopts,
					      s_drvopts, s_devopts);
			break;
		case SR_CONF_SAMPLERATE: {
			size_t samplerates_supported_max =
				ARRAY_SIZE(s_samplerates_supported);
			struct dev_context *devc;
			if ((devc = sdi->priv)) {
				GVariant *data = g_variant_new_uint64(
					devc->samplerate_max);
				int idx = std_u64_idx(
					data, ARRAY_AND_SIZE(
						      s_samplerates_supported));
				g_variant_unref(data);
				if (-1 != idx)
					samplerates_supported_max = idx + 1;
			}
			*data = std_gvar_samplerates(s_samplerates_supported,
						     samplerates_supported_max);
		} break;
		case SR_CONF_TRIGGER_MATCH:
			// *data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
			break;
		default:
			return SR_ERR_NA;
		}
	} else { // very driver-specific.
		struct sr_channel *ch = cg->channels->data;
		switch (key) {
		case SR_CONF_DEVICE_OPTIONS:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = std_gvar_array_u32(
					ARRAY_AND_SIZE(s_devopts_cg_logic));
			else
				return SR_ERR_BUG;
			break;
		case SR_CONF_PATTERN_MODE:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = g_variant_new_strv(
					ARRAY_AND_SIZE(s_logic_pattern_str));
			else
				return SR_ERR_BUG;
			break;
		default:
			return SR_ERR_NA;
		}
	}

	return ret;
}

static int dev_acquisition_start(const struct sr_dev_inst *sdi)
{
	uint64_t fps = 30;
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */
	struct dev_context *devc = sdi->priv;
	devc->logic_fq = feed_queue_logic_alloc(
		sdi, devc->samplerate / fps,
		PALIGN_UP(LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern), 8) /
			8);
	if (!devc->logic_fq) {
		sr_err("Logic feed_queue allocate failed.");
		return SR_ERR_MALLOC;
	}
	devc->transfers_submitted = NULL;
	devc->transfers_ready = NULL;
	devc->transfers_count = 64;
	{
#define MAX_TRANSFER_BUFFER_SIZE (1024 * 4 * 1024)
		uint64_t transfer_buffer_size = PALIGN_DOWN(
			devc->samplerate / fps *
				LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern) /
				8,
			4 * 1024);
		if (transfer_buffer_size > MAX_TRANSFER_BUFFER_SIZE)
			transfer_buffer_size = MAX_TRANSFER_BUFFER_SIZE;
		uint64_t transfer_timeout =
			devc->sw_limits.limit_samples * 1000 / devc->samplerate;
		if (!transfer_timeout)
			transfer_timeout = 100;
		uint8_t *transfer_buffer = NULL;
		for (int i = 0; i < devc->transfers_count; i++) {
			if (!transfer_buffer)
				transfer_buffer =
					g_try_malloc(transfer_buffer_size);
			if (!transfer_buffer)
				break;
			struct libusb_transfer *transfer =
				libusb_alloc_transfer(0);
			if (!transfer)
				continue;
			struct sr_usb_dev_inst *udi = sdi->conn;
			libusb_fill_bulk_transfer(
				transfer, udi->devhdl,
				0x02 | LIBUSB_ENDPOINT_IN, transfer_buffer,
				transfer_buffer_size,
				sipeed_slogic_libusb_transfer_cb, sdi,
				transfer_timeout);
			devc->transfers_ready =
				g_list_append(devc->transfers_ready, transfer);
			transfer_buffer = NULL;
		}
		if (transfer_buffer)
			g_free(transfer_buffer);
		uint64_t len = g_list_length(devc->transfers_ready);
		if (!len) {
			sr_err("Transfer allocate failed.");
			return SR_ERR_MALLOC;
		}
		sr_info("Transfer pre allocated %u x 0x%x bytes with %ums timeout.",
			len, transfer_buffer_size, transfer_timeout);
		devc->transfers_count = len;
		devc->transfers_base_timeout = transfer_timeout;
	}
	devc->stop_req = FALSE;
	devc->running = TRUE;
	sr_sw_limits_acquisition_start(&devc->sw_limits);
	struct drv_context *drvc = sdi->driver->context;
	usb_source_add(sdi->session, drvc->sr_ctx, 100,
		       sipeed_slogic_acquisition_handler, sdi);

	std_session_send_df_header(sdi);

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	/* TODO: stop acquisition. */
	struct dev_context *devc = sdi->priv;
	if (devc->running == TRUE) {
		devc->stop_req = TRUE;
	}

	return SR_OK;
}

static struct sr_dev_driver sipeed_slogic_driver_info = {
	.name = "sipeed-slogic",
	.longname = "Sipeed Slogic",
	.api_version = 1,
	.init = std_init,
	.cleanup = std_cleanup,
	.scan = scan,
	.dev_list = std_dev_list,
	.dev_clear = std_dev_clear,
	.config_get = config_get,
	.config_set = config_set,
	.config_channel_set = config_channel_set,
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(sipeed_slogic_driver_info);