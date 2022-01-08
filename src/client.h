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

#define CLIENT_MAX_DISCOVER_TIMEOUT 10000 // msecs
#define CLIENT_MAX_MAPPING_TIMEOUT 10000  // msecs
#define CLIENT_RECHECK_PERIOD 300000      // msecs

typedef struct client_mapping {
	plum_ip_protocol_t protocol;
	uint16_t internal_port;
	addr_record_t suggested_addr;
	addr_record_t external_addr;
	plum_mapping_callback_t callback;
	void *user_ptr;
	plum_state_t state;
	timestamp_t refresh_timestamp;
	void *impl_record;
} client_mapping_t;

typedef struct {
	client_mapping_t *mappings;
	int mappings_size;
	mutex_t mappings_mutex;
	const protocol_t *protocol;
	protocol_state_t protocol_state;
	mutex_t protocol_mutex;
	atomic(bool) is_started;
	atomic(bool) is_stopping;
	thread_t thread;
} client_t;

client_t *client_create(void);
void client_destroy(client_t *client);
int client_start(client_t *client);
int client_add_mapping(client_t *client, const plum_mapping_t *mapping,
                       plum_mapping_callback_t callback);
int client_get_mapping(client_t *client, int i, plum_state_t *state, plum_mapping_t *mapping);
int client_remove_mapping(client_t *client, int i);
void client_run(client_t *client);
int client_run_protocol(client_t *client, const protocol_t *protocol,
                        protocol_state_t *protocol_state, timediff_t duration);
int client_interrupt(client_t *client, bool stop);

#endif
