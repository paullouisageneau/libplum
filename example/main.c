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

#include "plum/plum.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

static void mapping_callback(int id, plum_state_t state, const plum_mapping_t *mapping) {
	printf("Mapping %d: state=%d\n", id, (int)state);
	switch (state) {
	case PLUM_STATE_SUCCESS:
		printf("Mapping %d: success, internal=%hu, external=%s:%hu\n", id, mapping->internal_port,
		       mapping->external_host, mapping->external_port);
		break;

	case PLUM_STATE_FAILURE:
		printf("Mapping %d: failed", id);
		break;

	default:
		break;
	}
}

int main(int argc, char **argv) {
	plum_set_log_level(PLUM_LOG_LEVEL_VERBOSE);

	plum_init();

	sleep(2);

	plum_mapping_t mapping;
	memset(&mapping, 0, sizeof(mapping));
	mapping.protocol = PLUM_IP_PROTOCOL_TCP;
	mapping.internal_port = 8000;

	int id = plum_create_mapping(&mapping, mapping_callback);

	sleep(2);

	plum_destroy_mapping(id);

	sleep(2);

	plum_cleanup();

	return 0;
}
