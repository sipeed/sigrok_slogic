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

#define LOGIC_PATTERN_TO_MAX_SAMPLERATE(P) \
    ({                                 \
        uint64_t __max_sr;               \
        switch (P) {                     \
        case PATTERN_1CH:              \
        case PATTERN_2CH:              \
            __max_sr = SR_MHZ(1200);     \
            break;                       \
        case PATTERN_4CH:              \
            __max_sr = SR_MHZ(600);      \
            break;                       \
        case PATTERN_8CH:              \
            __max_sr = SR_MHZ(300);      \
            break;                       \
        case PATTERN_16CH:             \
        default:                       \
            __max_sr = SR_MHZ(150);      \
            break;                       \
        }                                \
        __max_sr;                        \
    })

struct dev_context {
    /* configure */
    enum logic_pattern_type logic_pattern;
    enum logic_pattern_type logic_pattern_max;

    /* sample */
    uint64_t samplerate;
    uint64_t samplerate_max;
    struct sr_sw_limits sw_limits;


    /* working */
    gboolean running;
    gboolean stop_req;
    struct feed_queue_logic *logic_fq;
    uint64_t transfers_count;
    GSList *transfers_submitted;
    GSList *transfers_ready;
};

SR_PRIV int sipeed_slogic_acquisition_handler(int fd, int revents, void *cb_data);
SR_PRIV void LIBUSB_CALL sipeed_slogic_libusb_transfer_cb(struct libusb_transfer *transfer);

#define PALIGN_DOWN(X, align) ( (X)            & ~((align)-1))
#define PALIGN_UP(X, align)   (((X)+(align)-1) & ~((align)-1))

#endif
