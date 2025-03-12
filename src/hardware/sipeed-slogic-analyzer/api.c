/*
 * This file is part of the libsigrok project.
 *
 * Copyright (C) 2023 taorye <taorye@outlook.com>
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
#include "scpi.h"

static const uint32_t scanopts[] = {
	SR_CONF_CONN,
};

static const uint32_t drvopts[] = {
	SR_CONF_LOGIC_ANALYZER,
};

static const uint32_t devopts[] = {
	SR_CONF_CONTINUOUS,
	SR_CONF_LIMIT_SAMPLES | SR_CONF_GET | SR_CONF_SET,
	SR_CONF_SAMPLERATE    | SR_CONF_GET | SR_CONF_SET | SR_CONF_LIST,
	// SR_CONF_TRIGGER_MATCH | SR_CONF_GET | SR_CONF_LIST,
};

static const int32_t trigger_matches[] = {
	SR_TRIGGER_ZERO,
	SR_TRIGGER_ONE,
	SR_TRIGGER_RISING,
	SR_TRIGGER_FALLING,
	SR_TRIGGER_EDGE,
};

static struct sr_dev_driver sipeed_slogic_analyzer_driver_info;

static struct sr_dev_inst *probe_device(struct sr_scpi_dev_inst *scpi)
{
	struct dev_context *devc;
	struct sr_dev_inst *sdi;
	struct sr_scpi_hw_info *hw_info;
	struct sr_channel *ch;
	unsigned int i;
	gchar *channel_name;

	if (sr_scpi_get_hw_id(scpi, &hw_info) != SR_OK) {
		sr_err("Couldn't get IDN response.");
		return NULL;
	}

	// model = NULL;
	// for (i = 0; i < ARRAY_SIZE(supported_models); i++) {
	// 	if (!strcmp(hw_info->model, supported_models[i].name)) {
	// 		model = &supported_models[i];
	// 		break;
	// 	}
	// }

	// if (!model) {
	// 	sr_scpi_hw_info_free(hw_info);
	// 	return NULL;
	// }

	// sr_dbg("Setting Communication Headers to off.");
	// if (sr_scpi_send(scpi, "CHDR OFF") != SR_OK)
	// 	return NULL;

	// sdi = g_malloc0(sizeof(struct sr_dev_inst));
	// sdi->vendor = g_strdup(model->series->vendor->name);
	// sdi->model = g_strdup(model->name);
	// sdi->version = g_strdup(hw_info->firmware_version);
	sdi = sr_dev_inst_user_new(hw_info->manufacturer, hw_info->model, hw_info->firmware_version);
	sdi->serial_num = g_strdup(hw_info->serial_number);
	sdi->inst_type = SR_INST_SCPI;
	sdi->conn = scpi;
	sdi->status = SR_ST_INACTIVE;
	sdi->driver = &sipeed_slogic_analyzer_driver_info;
	devc = g_malloc0(sizeof(struct dev_context));
	// devc->limit_frames = 1;
	// devc->model = model;

	sr_scpi_hw_info_free(hw_info);

	// if (devc->model->has_digital) {
	devc->digital_group = sr_channel_group_new(sdi, "LA", NULL);
	for (i = 0; i < 16; i++) {
		channel_name = g_strdup_printf("D%u", i);
		ch = sr_channel_new(sdi, i, SR_CHANNEL_LOGIC, TRUE, channel_name);
		g_free(channel_name);
		devc->digital_group->channels = g_slist_append(
			devc->digital_group->channels, ch);
	}
	// }

	sdi->priv = devc;

	return sdi;
}

static GSList *scan(struct sr_dev_driver *di, GSList *options)
{
	GSList *l, *devices;
	struct sr_config *option;
	const char *conn;
	static const char *conn_default = "tcp-raw/127.0.0.1/21129";

	conn = NULL;
	for (l = options; l; l = l->next) {
		option = l->data;
		switch (option->key) {
		case SR_CONF_CONN:
			conn = g_variant_get_string(option->data, NULL);
			break;
		default:
			sr_warn("Unhandled option key: %u", option->key);
		}
	}
	if (!conn) {
		conn = conn_default;
		sr_info("Added default conn: %s.", conn);
		option = g_malloc0(sizeof(struct sr_config));
		option->key = SR_CONF_CONN;
		option->data = g_variant_new_take_string(g_strdup(conn)); // need to be freed
		options = g_slist_prepend(options, option);
	}

	devices = sr_scpi_scan(di->context, options, probe_device);

	if (option == options->data) {
		g_variant_unref(option->data); // release GVariant，also free str
		g_free(option);
	}

	return devices;
}

static int dev_open(struct sr_dev_inst *sdi)
{
	int ret;
	struct sr_scpi_dev_inst *scpi = sdi->conn;
	struct dev_context *devc = sdi->priv;

	if ((ret = sr_scpi_open(scpi)) < 0) {
		sr_err("Failed to open SCPI device: %s.", sr_strerror(ret));
		return SR_ERR;
	}

	return SR_OK;
}

static int dev_close(struct sr_dev_inst *sdi)
{
	return sr_scpi_close(sdi->conn);
}

static int config_get(uint32_t key, GVariant **data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;

	(void)cg;

	devc = sdi->priv;

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SAMPLERATE:
		*data = g_variant_new_uint64(devc->cur_samplerate);
		break;
	case SR_CONF_LIMIT_SAMPLES:
		*data = g_variant_new_uint64(devc->limit_samples);
		break;
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static int config_set(uint32_t key, GVariant *data,
	const struct sr_dev_inst *sdi, const struct sr_channel_group *cg)
{
	int ret;
	struct dev_context *devc;

	(void)cg;

	devc = sdi->priv;

	ret = SR_OK;
	switch (key) {
	case SR_CONF_SAMPLERATE:
		if (std_u64_idx(data, ARRAY_AND_SIZE(samplerates)) < 0) {
			ret = SR_ERR_ARG;
		} else {
			devc->cur_samplerate = g_variant_get_uint64(data);
			// {
			// size_t idx = 0;
			// 	for (GSList *l = sdi->channels; l; l = l->next, idx += 1) {
			// 		struct sr_channel *ch = l->data;
			// 		if (ch->type == SR_CHANNEL_LOGIC) { /* Might as well do this now, these are static. */
			// 			sr_dev_channel_enable(ch, (idx >= devc->cur_samplechannel) ? FALSE : TRUE);
			// 		} else {
			// 			return SR_ERR_BUG;
			// 		}
			// 	}
			// }
		}
		break;
	case SR_CONF_LIMIT_SAMPLES:
		devc->limit_samples = g_variant_get_uint64(data);
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
	switch (key) {
	/* TODO */
	case SR_CONF_SCAN_OPTIONS:
	case SR_CONF_DEVICE_OPTIONS:
		ret = STD_CONFIG_LIST(key, data, sdi, cg, scanopts, drvopts, devopts);
		break;
	case SR_CONF_SAMPLERATE:
		*data = std_gvar_samplerates(ARRAY_AND_SIZE(samplerates));
		break;
	case SR_CONF_TRIGGER_MATCH:
		*data = std_gvar_array_i32(ARRAY_AND_SIZE(trigger_matches));
		break;
	default:
		ret = SR_ERR_NA;
	}

	return ret;
}

static struct sr_dev_driver sipeed_slogic_analyzer_driver_info = {
	.name = "sipeed-slogic-analyzer",
	.longname = "Sipeed Slogic Analyzer",
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
	.dev_acquisition_start = std_dummy_dev_acquisition_start,
	.dev_acquisition_stop = std_dummy_dev_acquisition_stop,
	.context = NULL,
};
SR_REGISTER_DEV_DRIVER(sipeed_slogic_analyzer_driver_info);
