/**
 * Copyright (c) 2021 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PLUM_PROTOCOL_H
#define PLUM_PROTOCOL_H

#include "addr.h"
#include "timestamp.h"

typedef struct {
	addr_record_t gateway;
	void *impl;
} protocol_state_t;

struct client_mapping;

#define PROTOCOL_ERR_SUCCESS 0
#define PROTOCOL_ERR_UNKNOWN -1
#define PROTOCOL_ERR_INTERRUPTED -2
#define PROTOCOL_ERR_TIMEOUT -3
#define PROTOCOL_ERR_RESET -4
#define PROTOCOL_ERR_PROTOCOL_FAILED -5
#define PROTOCOL_ERR_NETWORK_FAILED -6
#define PROTOCOL_ERR_INSUFF_RESOURCES -7
#define PROTOCOL_ERR_UNSUPP_PROTOCOL -8
#define PROTOCOL_ERR_UNSUPP_VERSION -9

typedef struct {
	addr_record_t external_addr;
	timestamp_t refresh_timestamp;
	void *impl_record;
} protocol_map_output_t;

typedef struct {
	int (*init)(protocol_state_t *state);
	int (*cleanup)(protocol_state_t *state);
	int (*discover)(protocol_state_t *state, timediff_t duration);
	int (*map)(protocol_state_t *state, const struct client_mapping *mapping,
	           protocol_map_output_t *output, timediff_t duration);
	int (*unmap)(protocol_state_t *state, const struct client_mapping *mapping, timediff_t duration);
	int (*idle)(protocol_state_t *state, timediff_t duration);
	int (*interrupt)(protocol_state_t *state);
} protocol_t;

#endif
