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

#include "client.h"
#include "addr.h"
#include "log.h"
#include "net.h"
#include "pcp.h"
#include "upnp.h"

#include <string.h>

#define DEFAULT_MAPPINGS_SIZE 16

#define PROTOCOL_PCP 0
#define PROTOCOL_UPNP 1
#define PROTOCOLS_COUNT 2

static const protocol_t protocols[PROTOCOLS_COUNT] = {
    {pcp_init, pcp_cleanup, pcp_discover, pcp_map, pcp_unmap, pcp_idle, pcp_interrupt},
    {upnp_init, upnp_cleanup, upnp_discover, upnp_map, upnp_unmap, upnp_idle, upnp_interrupt}};

static int find_empty_mapping_index(client_t *client) {
	for (int i = 0; i < client->mappings_size; ++i)
		if (client->mappings[i].internal_port == 0)
			return i;

	return -1;
}

static void import_mapping(const plum_mapping_t *mapping, plum_mapping_callback_t callback,
                           client_mapping_t *cm) {
	memset(cm, 0, sizeof(*cm));
	cm->callback = callback;
	cm->protocol = mapping->protocol;
	cm->internal_port = mapping->internal_port;
	cm->state = PLUM_STATE_PENDING;

	if (*mapping->external_host == '\0' ||
	    addr_set(AF_UNSPEC, mapping->external_host, mapping->external_port, &cm->suggested_addr) <
	        0)
		if (mapping->external_port == 0 ||
		    addr_set(AF_INET, "0.0.0.0", mapping->external_port, &cm->suggested_addr) < 0)
			memset(&cm->suggested_addr, 0, sizeof(cm->suggested_addr));
}

static void export_mapping(const client_mapping_t *cm, plum_mapping_t *mapping) {
	memset(mapping, 0, sizeof(*mapping));
	mapping->protocol = cm->protocol;
	mapping->internal_port = cm->internal_port;
	if (cm->external_addr.len > 0) {
		mapping->external_port = addr_get_port((const struct sockaddr *)&cm->external_addr.addr);
		addr_get_host((const struct sockaddr *)&cm->external_addr.addr, mapping->external_host,
		              PLUM_MAX_HOST_LEN);
	}
}

thread_return_t THREAD_CALL client_thread_entry(void *arg) {
	client_run((client_t *)arg);
	return (thread_return_t)0;
}

client_t *client_create(void) {
	client_t *client = malloc(sizeof(client_t));
	if (!client) {
		PLUM_LOG_FATAL("Allocation failed for client");
		return NULL;
	}
	memset(client, 0, sizeof(client_t));

	client->mappings = malloc(DEFAULT_MAPPINGS_SIZE * sizeof(client_mapping_t));
	if (!client->mappings) {
		PLUM_LOG_FATAL("Allocation failed for mappings");
		free(client);
		return NULL;
	}

	memset(client->mappings, 0, DEFAULT_MAPPINGS_SIZE * sizeof(client_mapping_t));
	client->mappings_size = DEFAULT_MAPPINGS_SIZE;

	mutex_init(&client->mappings_mutex, MUTEX_RECURSIVE); // so the user call the API from callbacks
	mutex_init(&client->protocol_mutex, 0);

	int ret = thread_init(&client->thread, client_thread_entry, client);
	if (ret) {
		PLUM_LOG_FATAL("Thread creation failed, error=%d", ret);
		mutex_destroy(&client->mappings_mutex);
		mutex_destroy(&client->protocol_mutex);
		free(client->mappings);
		free(client);
		return NULL;
	}

	return client;
}

void client_destroy(client_t *client) {
	thread_join(client->thread, NULL);
	free(client->mappings);
	free(client);
}

int client_add_mapping(client_t *client, const plum_mapping_t *mapping,
                       plum_mapping_callback_t callback) {
	if (!mapping)
		return -1;

	mutex_lock(&client->mappings_mutex);

	int i = find_empty_mapping_index(client);
	if (i >= 0) {
		client_mapping_t *cm = client->mappings + i;
		import_mapping(mapping, callback, cm);
		mutex_unlock(&client->mappings_mutex);
		return i;
	}

	i = client->mappings_size;

	client_mapping_t *new_mappings =
	    realloc(client->mappings, client->mappings_size * 2 * sizeof(client_mapping_t));
	if (!new_mappings) {
		PLUM_LOG_ERROR("Reallocation failed for mappings");
		mutex_unlock(&client->mappings_mutex);
		return -1;
	}

	client->mappings = new_mappings;
	memset(client->mappings + client->mappings_size, 0,
	       client->mappings_size * sizeof(client_mapping_t));
	client->mappings_size *= 2;

	client_mapping_t *cm = client->mappings + i;
	import_mapping(mapping, callback, cm);

	mutex_unlock(&client->mappings_mutex);

	client_interrupt(client);
	return i;
}

int client_get_mapping(client_t *client, int i, plum_state_t *state, plum_mapping_t *mapping) {
	mutex_lock(&client->mappings_mutex);

	if (i >= client->mappings_size || client->mappings[i].state == PLUM_STATE_DESTROYED) {
		mutex_unlock(&client->mappings_mutex);
		return -1;
	}

	client_mapping_t *cm = client->mappings + i;
	if (mapping)
		export_mapping(cm, mapping);

	if (state)
		*state = cm->state;

	mutex_unlock(&client->mappings_mutex);
	return 0;
}

int client_remove_mapping(client_t *client, int i) {
	mutex_lock(&client->mappings_mutex);

	if (i >= client->mappings_size || client->mappings[i].state == PLUM_STATE_DESTROYED) {
		mutex_unlock(&client->mappings_mutex);
		return -1;
	}

	client_mapping_t *cm = client->mappings + i;
	cm->state = PLUM_STATE_DESTROYING;

	mutex_unlock(&client->mappings_mutex);

	client_interrupt(client);
	return 0;
}

static int trigger_mapping_callback(const client_mapping_t *cm, int i) {
	if (cm->state == PLUM_STATE_DESTROYED)
		return -1;

	plum_mapping_t mapping;
	export_mapping(cm, &mapping);
	if (cm->callback)
		cm->callback(i, cm->state, &mapping);

	return 0;
}

static int change_mapping_state(client_mapping_t *cm, int i, plum_state_t state,
                                bool external_addr_changed) {
	if (state != cm->state || (state == PLUM_STATE_SUCCESS && external_addr_changed)) {
		cm->state = state;
		return trigger_mapping_callback(cm, i);
	}

	return 0;
}

/*
static bool has_private_address() {
	addr_record_t local;
	if (net_get_default_interface(AF_INET, &local) < 0) {
		PLUM_LOG_ERROR("Unable to get default interface address");
		return false;
	}

	return addr_is_private((const struct sockaddr *)&local);
}
*/

void client_run(client_t *client) {
	PLUM_LOG_DEBUG("Starting client thread");

	int protocol_num = PROTOCOL_PCP;
	while (true) {
		mutex_lock(&client->protocol_mutex);
		const protocol_t *protocol = client->protocol = &protocols[protocol_num];
		client->protocol = protocol;
		protocol_state_t *protocol_state = &client->protocol_state;
		mutex_unlock(&client->protocol_mutex);

		int err = client_run_protocol(client, protocol, protocol_state);
		if (err == PROTOCOL_ERR_RESET)
			continue;

		// Try the next protocol
		++protocol_num;

		if (protocol_num == PROTOCOLS_COUNT) {
			protocol_num = 0;

			// Reset all mappings
			mutex_lock(&client->mappings_mutex);
			for (int i = 0; i < client->mappings_size; ++i) {
				client_mapping_t *cm = client->mappings + i;
				if (cm->state != PLUM_STATE_FAILURE) {
					memset(&cm->external_addr, 0, sizeof(cm->external_addr));
					free(cm->impl_record);
					cm->impl_record = NULL;
					change_mapping_state(cm, i, PLUM_STATE_FAILURE, false);
				}
			}
			mutex_unlock(&client->mappings_mutex);
		}
	}

	PLUM_LOG_DEBUG("Exiting client thread");
}

int client_run_protocol(client_t *client, const protocol_t *protocol,
                        protocol_state_t *protocol_state) {
	int err = protocol->init(protocol_state);
	if (err != PROTOCOL_ERR_SUCCESS)
		return err;

	const timediff_t discover_timeout = 10 * 1000;
	err = protocol->discover(protocol_state, discover_timeout);
	if (err != PROTOCOL_ERR_SUCCESS)
		goto error;

	while (true) {
		timestamp_t next_timestamp = 0;
		mutex_lock(&client->mappings_mutex);
		int mappings_size = client->mappings_size;
		mutex_unlock(&client->mappings_mutex);
		for (int i = 0; i < mappings_size; ++i) {
			mutex_lock(&client->mappings_mutex);
			if (client->mappings[i].state == PLUM_STATE_DESTROYED) {
				mutex_unlock(&client->mappings_mutex);
				continue;
			}
			client_mapping_t mapping = client->mappings[i];
			mutex_unlock(&client->mappings_mutex);

			PLUM_LOG_VERBOSE("Mapping %d for internal port %hu is alive", i, mapping.internal_port);

			if (mapping.state == PLUM_STATE_DESTROYING) {
				PLUM_LOG_INFO("Performing unmapping for internal port %hu", mapping.internal_port);

				const timediff_t mapping_timeout = 30 * 1000;
				err = protocol->unmap(protocol_state, &mapping, mapping_timeout);

				// Ignore errors
				if (err == PROTOCOL_ERR_SUCCESS)
					PLUM_LOG_INFO("Unmapped internal port %hu", mapping.internal_port);
				else
					PLUM_LOG_WARN("Failed to unmap internal port %hu", mapping.internal_port);

				mutex_lock(&client->mappings_mutex);
				client_mapping_t *cm = client->mappings + i;
				change_mapping_state(cm, i, PLUM_STATE_DESTROYED, false);
				free(cm->impl_record);
				memset(cm, 0, sizeof(*cm));
				mutex_unlock(&client->mappings_mutex);
				continue;
			}

			if (mapping.refresh_timestamp <= current_timestamp()) {
				PLUM_LOG_INFO("Performing mapping for internal port %hu", mapping.internal_port);

				const timediff_t mapping_timeout = 30 * 1000;
				protocol_map_output_t output;
				memset(&output, 0, sizeof(output));
				err = protocol->map(protocol_state, &mapping, &output, mapping_timeout);
				// TODO: wait on reset
				if (err != PROTOCOL_ERR_SUCCESS)
					goto error;

				if (PLUM_LOG_INFO_ENABLED) {
					char external_str[ADDR_MAX_STRING_LEN];
					addr_record_to_string(&output.external_addr, external_str, ADDR_MAX_STRING_LEN);
					PLUM_LOG_INFO("External address %s mapped to internal port %hu", external_str,
					              mapping.internal_port);
				}

				mutex_lock(&client->mappings_mutex);
				client_mapping_t *cm = client->mappings + i;
				bool changed =
				    !addr_record_is_equal(&cm->external_addr, &output.external_addr, true);
				cm->external_addr = output.external_addr;
				cm->refresh_timestamp = output.refresh_timestamp;
				free(cm->impl_record);
				cm->impl_record = output.impl_record;
				change_mapping_state(cm, i, PLUM_STATE_SUCCESS, changed);
				mutex_unlock(&client->mappings_mutex);
			}

			if (next_timestamp == 0 || next_timestamp > mapping.refresh_timestamp)
				next_timestamp = mapping.refresh_timestamp;
		}

		timestamp_t now = current_timestamp();
		if (now < next_timestamp) {
			timediff_t diff = next_timestamp - now;
			err = protocol->idle(protocol_state, diff);
			if (err != PROTOCOL_ERR_SUCCESS && err != PROTOCOL_ERR_TIMEOUT &&
			    err != PROTOCOL_ERR_INTERRUPTED)
				goto error;
		}
	}

error:
	protocol->cleanup(protocol_state);
	return err;
}

int client_interrupt(client_t *client) {
	int err = PROTOCOL_ERR_SUCCESS;
	mutex_lock(&client->protocol_mutex);
	if (client->protocol)
		err = client->protocol->interrupt(&client->protocol_state);
	mutex_unlock(&client->protocol_mutex);
	return err;
}
