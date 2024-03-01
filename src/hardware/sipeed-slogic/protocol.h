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

#ifndef LIBSIGROK_HARDWARE_SIPEED_SLOGIC_PROTOCOL_H
#define LIBSIGROK_HARDWARE_SIPEED_SLOGIC_PROTOCOL_H

#include <stdint.h>
#include <glib.h>
#include <libsigrok/libsigrok.h>
#include "libsigrok-internal.h"

#define LOG_PREFIX "sipeed-slogic"

enum logic_pattern_type {
    PATTERN_1CH,
    PATTERN_2CH,
    PATTERN_4CH,
    PATTERN_8CH,
    PATTERN_16CH,
};

#define LOGIC_PATTERN_TO_CHANNELS(p) (1<<(p))

struct dev_context {
    enum logic_pattern_type logic_pattern;


    enum logic_pattern_type logic_pattern_max;
};

SR_PRIV int sipeed_slogic_receive_data(int fd, int revents, void *cb_data);

#endif
