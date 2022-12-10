/**
 * Copyright (c) 2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
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
		printf("Mapping %d: failed\n", id);
		break;

	default:
		break;
	}
}

int main(int argc, char **argv) {
	// Initialize
	plum_config_t config;
	memset(&config, 0, sizeof(config));
	config.log_level = PLUM_LOG_LEVEL_DEBUG;
	plum_init(&config);

	// Create a first mapping
	plum_mapping_t mapping1;
	memset(&mapping1, 0, sizeof(mapping1));
	mapping1.protocol = PLUM_IP_PROTOCOL_TCP;
	mapping1.internal_port = 8081;
	int id1 = plum_create_mapping(&mapping1, mapping_callback);

	sleep(1); // simulate doing some stuff

	// Create a second mapping
	plum_mapping_t mapping2;
	memset(&mapping2, 0, sizeof(mapping2));
	mapping2.protocol = PLUM_IP_PROTOCOL_TCP;
	mapping2.internal_port = 8082;
	int id2 = plum_create_mapping(&mapping2, mapping_callback);

	sleep(10); // simulate doing some stuff

	// Destroy the first mapping
	plum_destroy_mapping(id1);

	// Destroy the second mapping
	plum_destroy_mapping(id2);

	// Clean up
	plum_cleanup();
	return 0;
}
