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

#ifndef PLUM_CLIENT_H
#define PLUM_CLIENT_H

#include "addr.h"
#include "plum.h"
#include "protocol.h"
#include "thread.h"
#include "timestamp.h"

typedef struct client_mapping {
	plum_ip_protocol_t protocol;
	uint16_t internal_port;
	addr_record_t suggested_addr;
	addr_record_t external_addr;
	plum_mapping_callback_t callback;
	plum_state_t state;
	timestamp_t refresh_timestamp;
} client_mapping_t;

typedef struct {
	client_mapping_t *mappings;
	int mappings_size;
	mutex_t mappings_mutex;
	thread_t thread;
	const protocol_t *protocol;
	protocol_state_t protocol_state;
	mutex_t protocol_mutex;
} client_t;

client_t *client_create(void);
void client_destroy(client_t *client);
int client_add_mapping(client_t *client, const plum_mapping_t *mapping, plum_mapping_callback_t callback);
int client_get_mapping(client_t *client, int i, plum_state_t *state, plum_mapping_t *mapping);
int client_remove_mapping(client_t *client, int i);
void client_run(client_t *client);
int client_run_protocol(client_t *client, const protocol_t *protocol, protocol_state_t *protocol_state);
int client_interrupt(client_t *client);

#endif
