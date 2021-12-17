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

#include "plum.h"
#include "addr.h"
#include "client.h"
#include "log.h"
#include "random.h"

#include <string.h>

client_t *client;

int plum_init() {
	if (client)
		return PLUM_ERR_FAILED;

	plum_log_init();
	plum_random_init();

	client = client_create();
	if (!client)
		return PLUM_ERR_FAILED;

	return PLUM_ERR_SUCCESS;
}

int plum_cleanup() {
	if (!client)
		return PLUM_ERR_FAILED;

	client_destroy(client);
	client = NULL;

	plum_log_cleanup();
	plum_random_cleanup();

	return PLUM_ERR_SUCCESS;
}

int plum_create_mapping(const plum_mapping_t *mapping, plum_mapping_callback_t callback,
                        void *user_ptr) {
	if (!client)
		return PLUM_ERR_FAILED;

	if (!mapping)
		return PLUM_ERR_INVALID;

	int id = client_add_mapping(client, mapping, callback, user_ptr);
	if (id < 0)
		return PLUM_ERR_FAILED;

	return id;
}

int plum_query_mapping(int id, plum_state_t *state, plum_mapping_t *mapping) {
	if (!client)
		return PLUM_ERR_FAILED;

	if (id < 0)
		return PLUM_ERR_INVALID;

	if (client_get_mapping(client, id, state, mapping) < 0)
		return PLUM_ERR_NOT_AVAIL;

	return PLUM_ERR_SUCCESS;
}

int plum_destroy_mapping(int id) {
	if (!client)
		return PLUM_ERR_FAILED;

	if (id < 0)
		return PLUM_ERR_INVALID;

	if (client_remove_mapping(client, id) < 0)
		return PLUM_ERR_NOT_AVAIL;

	return PLUM_ERR_SUCCESS;
}
