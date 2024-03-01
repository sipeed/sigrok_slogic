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
	SR_CONF_CONN,                     // a USB device
};

static const uint32_t s_drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
	// SR_CONF_OSCILLOSCOPE,
};

static const uint32_t s_devopts[] = {
	SR_CONF_CONTINUOUS,
	// SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	// SR_CONF_LIMIT_MSEC    | SR_CONF_GET | SR_CONF_SET,
	// SR_CONF_CAPTURE_RATIO | SR_CONF_GET | SR_CONF_SET,
	// SR_CONF_SAMPLERATE    | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	// SR_CONF_TRIGGER_MATCH                             | SR_CONF_LIST,
};

static const uint32_t s_devopts_cg_logic[] = {
	SR_CONF_PATTERN_MODE | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
};

static const char *s_logic_pattern_str[] = {
	[PATTERN_1CH] = "1ch",
	[PATTERN_2CH] = "2ch",
	[PATTERN_4CH] = "4ch",
	[PATTERN_8CH] = "8ch",
	[PATTERN_16CH] = "16ch",
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
	drvc->instances = NULL;

	/* scan for devices, either based on a SR_CONF_CONN option
	 * or on a USB scan. */
	for (l = options; l; l = l->next) {
		struct sr_config *option = l->data;
		switch (option->key) {
		case SR_CONF_CONN:
			conn = g_variant_get_string(option->data, NULL);
			sr_info("use conn=%s", conn);
			break;
		}
	}

	/* TODO: scan for devices, either based on a SR_CONF_CONN option
	 * or on a USB scan. */
	GSList *udis = sr_usb_find(drvc->sr_ctx->libusb_ctx, "1d50.608c");
	for (l = udis; l; l = l->next) {
		struct sr_usb_dev_inst *udi = l->data;
		if (SR_OK != sr_usb_open(drvc->sr_ctx->libusb_ctx, udi))
			continue;
		char *Manufacturer, *Product, *SerialNumber, *Version;
		char cbuf[128];
		struct libusb_device_descriptor des;
		libusb_get_device_descriptor(libusb_get_device(udi->devhdl), &des);

		libusb_get_string_descriptor_ascii(udi->devhdl,
				des.iManufacturer, cbuf, sizeof(cbuf));
		Manufacturer = g_strdup(cbuf);
		libusb_get_string_descriptor_ascii(udi->devhdl,
				des.iProduct, cbuf, sizeof(cbuf));
		Product = g_strdup(cbuf);
		libusb_get_string_descriptor_ascii(udi->devhdl,
				des.iSerialNumber, cbuf, sizeof(cbuf));
		SerialNumber = g_strdup(cbuf);
		sr_snprintf_ascii(cbuf, sizeof(cbuf), "%x.%x", 0xff&(des.bcdDevice>>8), 0xff&(des.bcdDevice>>0));
		Version = g_strdup(cbuf);
		sr_usb_close(udi);

		struct sr_dev_inst *sdi = sr_dev_inst_user_new(Manufacturer, Product, Version);
		sdi->serial_num = SerialNumber;

		struct dev_context *devc = g_malloc0(sizeof(struct dev_context));

		devc->logic_pattern_max = PATTERN_16CH;

		devc->logic_pattern = devc->logic_pattern_max;
		size_t num_logic_channels = LOGIC_PATTERN_TO_CHANNELS(devc->logic_pattern);
		if (num_logic_channels > 0) {
			/* Logic channels, all in one channel group. */
			struct sr_channel_group *cg = sr_channel_group_new(sdi, "Logic", NULL);
			char channel_name[8];
			for (size_t i = 0; i < num_logic_channels; i++) {
				sr_snprintf_ascii(channel_name, sizeof(channel_name), "D%d", i);
				struct sr_channel *ch = sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, channel_name);
				cg->channels = g_slist_append(cg->channels, ch);
			}
		}
		
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
	(void)sdi;

	/* TODO: get handle from sdi->conn and open it. */

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	(void)sdi;

	/* TODO: get handle from sdi->conn and close it. */

	return SR_OK;
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;

	if (!sdi)
		return SR_ERR_ARG;

	ret = SR_OK;
	devc = sdi->priv;
	switch (key) {
	/* TODO */
	case SR_CONF_PATTERN_MODE:
		if (!cg)
			return SR_ERR_CHANNEL_GROUP;
		/* Any channel in the group will do. */
		struct sr_channel *ch = cg->channels->data;
		if (ch->type == SR_CHANNEL_LOGIC) {
			*data = g_variant_new_string(s_logic_pattern_str[devc->logic_pattern]);
		} else
			return SR_ERR_BUG;
		break;
	default:
		return SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;
	GSList *l;

	devc = sdi->priv;

	ret = SR_OK;
	switch (key) {
	/* TODO */
	case SR_CONF_PATTERN_MODE:
		if (!cg)
			return SR_ERR_CHANNEL_GROUP;
		struct sr_channel *ch;
		ch = cg->channels->data;

		if (ch->type == SR_CHANNEL_LOGIC) {
			int logic_pattern = std_str_idx(data, ARRAY_AND_SIZE(s_logic_pattern_str));
			if (logic_pattern < 0)
				return SR_ERR_ARG;
			devc->logic_pattern = logic_pattern;
		} else
			return SR_ERR_BUG;
		break;
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_list(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;

	ret = SR_OK;
	/* TODO */
	if (!cg) {
		switch (key) {
		case SR_CONF_SCAN_OPTIONS:
		case SR_CONF_DEVICE_OPTIONS:
			return STD_CONFIG_LIST(key, data, sdi, cg, s_scanopts, s_drvopts, s_devopts);
			break;
		case SR_CONF_SAMPLERATE:
			// *data = std_gvar_samplerates_steps(ARRAY_AND_SIZE(samplerates));
			break;
		case SR_CONF_TRIGGER_MATCH:
			// *data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
			break;
		default:
			return SR_ERR_NA;
		}
	} else {                                           // very driver-specific.
		struct sr_channel *ch = cg->channels->data;
		switch (key) {
		case SR_CONF_DEVICE_OPTIONS:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = std_gvar_array_u32(ARRAY_AND_SIZE(s_devopts_cg_logic));
			else
				return SR_ERR_BUG;
			break;
		case SR_CONF_PATTERN_MODE:
			if (ch->type == SR_CHANNEL_LOGIC)
				*data = g_variant_new_strv(ARRAY_AND_SIZE(s_logic_pattern_str));
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
	/* TODO: configure hardware, reset acquisition state, set up
	 * callbacks and send header packet. */

	(void)sdi;

	return SR_OK;
}

static int dev_acquisition_stop(struct sr_dev_inst *sdi)
{
	/* TODO: stop acquisition. */

	(void)sdi;

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
	.config_list = config_list,
	.dev_open = dev_open,
	.dev_close = dev_close,
	.dev_acquisition_start = dev_acquisition_start,
	.dev_acquisition_stop = dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(sipeed_slogic_driver_info);
