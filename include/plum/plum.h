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

#ifndef PLUM_H
#define PLUM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef PLUM_HAS_EXPORT_HEADER
#include "plum_export.h"
#endif

#ifndef PLUM_EXPORT
#ifdef _WIN32
#define PLUM_EXPORT __declspec(dllexport)
#else
#define PLUM_EXPORT
#endif
#endif

#define PLUM_ERR_SUCCESS 0
#define PLUM_ERR_INVALID -1   // invalid argument
#define PLUM_ERR_FAILED -2    // runtime error
#define PLUM_ERR_NOT_AVAIL -3 // element not available

// Port Mapping

PLUM_EXPORT int plum_init();
PLUM_EXPORT int plum_cleanup();

typedef enum {
	PLUM_IP_PROTOCOL_TCP = 0,
	PLUM_IP_PROTOCOL_UDP = 1
} plum_ip_protocol_t;

typedef enum {
	PLUM_STATE_DESTROYED = 0,
	PLUM_STATE_PENDING = 1,
	PLUM_STATE_SUCCESS = 2,
	PLUM_STATE_FAILURE = 3,
	PLUM_STATE_DESTROYING = 4
} plum_state_t;

#define PLUM_MAX_HOST_LEN 64

typedef struct {
	plum_ip_protocol_t protocol;
	uint16_t internal_port;
	uint16_t external_port;
	char external_host[PLUM_MAX_HOST_LEN];
} plum_mapping_t;

// Callback will be called on SUCCESS, FAILURE, and DESTROYED
typedef void (*plum_mapping_callback_t)(int id, plum_state_t state, const plum_mapping_t *mapping);

PLUM_EXPORT int plum_create_mapping(const plum_mapping_t *mapping, plum_mapping_callback_t callback);
PLUM_EXPORT int plum_query_mapping(int id, plum_state_t *state, plum_mapping_t *mapping);
PLUM_EXPORT int plum_destroy_mapping(int id);

// Logging

typedef enum {
	PLUM_LOG_LEVEL_VERBOSE = 0,
	PLUM_LOG_LEVEL_DEBUG = 1,
	PLUM_LOG_LEVEL_INFO = 2,
	PLUM_LOG_LEVEL_WARN = 3,
	PLUM_LOG_LEVEL_ERROR = 4,
	PLUM_LOG_LEVEL_FATAL = 5,
	PLUM_LOG_LEVEL_NONE = 6
} plum_log_level_t;

typedef void (*plum_log_cb_t)(plum_log_level_t level, const char *message);

PLUM_EXPORT void plum_set_log_level(plum_log_level_t level);
PLUM_EXPORT void plum_set_log_handler(plum_log_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif
