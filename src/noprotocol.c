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

#include "noprotocol.h"
#include "addr.h"
#include "log.h"
#include "net.h"

#include <string.h>

int noprotocol_init(protocol_state_t *state) {
	PLUM_LOG_VERBOSE("Initializing no protocol state");

	memset(state, 0, sizeof(*state));
	state->impl = malloc(sizeof(noprotocol_impl_t));
	if (!state->impl) {
		PLUM_LOG_ERROR("Allocation for no protocol state failed");
		return PROTOCOL_ERR_INSUFF_RESOURCES;
	}

	noprotocol_impl_t *impl = state->impl;
	memset(impl, 0, sizeof(*impl));
	mutex_init(&impl->mutex, 0);
	cond_init(&impl->interrupt_cond);

	return PROTOCOL_ERR_SUCCESS;
}

int noprotocol_cleanup(protocol_state_t *state) {
	PLUM_LOG_VERBOSE("Cleaning up no protocol state");

	noprotocol_impl_t *impl = state->impl;
	mutex_destroy(&impl->mutex);
	cond_destroy(&impl->interrupt_cond);

	free(state->impl);
	return PROTOCOL_ERR_SUCCESS;
}

int noprotocol_discover(protocol_state_t *state, timediff_t duration) {
	// Dummy
	(void)state;
	(void)duration;
	return PROTOCOL_ERR_SUCCESS;
}

int noprotocol_map(protocol_state_t *state, const client_mapping_t *mapping,
                   protocol_map_output_t *output, timediff_t duration) {
	(void)state;
	(void)duration;
	memset(output, 0, sizeof(*output));

	addr_record_t local;
	if (net_get_default_interface(AF_INET, &local) == 0) {
		if (!addr_is_private((const struct sockaddr *)&local)) {
			if (PLUM_LOG_INFO_ENABLED) {
				char local_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&local, local_str, ADDR_MAX_STRING_LEN);
				PLUM_LOG_INFO("Local address is public: %s", local_str);
			}

			output->state = PROTOCOL_MAP_STATE_SUCCESS;
			output->refresh_timestamp = current_timestamp() + CLIENT_RECHECK_PERIOD;
			output->external_addr = local;
			addr_set_port((struct sockaddr *)&output->external_addr, mapping->internal_port);
			return PROTOCOL_ERR_SUCCESS;
		}
	} else {
		PLUM_LOG_WARN("Unable to get default interface address");
	}

	output->state = PROTOCOL_MAP_STATE_FAILURE;
	output->refresh_timestamp = current_timestamp() + CLIENT_RECHECK_PERIOD;
	memset(&output->external_addr, 0, sizeof(output->external_addr));
	return PROTOCOL_ERR_SUCCESS; // report mapping failure but keep running the protocol
}

int noprotocol_unmap(protocol_state_t *state, const client_mapping_t *mapping,
                     timediff_t duration) {
	// Dummy
	(void)state;
	(void)mapping;
	(void)duration;
	return PROTOCOL_ERR_SUCCESS;
}

int noprotocol_idle(protocol_state_t *state, timediff_t duration) {
	noprotocol_impl_t *impl = state->impl;
	mutex_lock(&impl->mutex);
	timestamp_t end_timestamp = current_timestamp() + duration;
	while (!impl->interrupted) {
		timestamp_t now = current_timestamp();
		if (end_timestamp <= now) {
			mutex_unlock(&impl->mutex);
			return PROTOCOL_ERR_SUCCESS;
		}
		timediff_t left = end_timestamp - now;
		cond_timedwait(&impl->interrupt_cond, &impl->mutex, left);
	}
	impl->interrupted = false;
	mutex_unlock(&impl->mutex);
	return PROTOCOL_ERR_INTERRUPTED;
}

int noprotocol_interrupt(protocol_state_t *state, bool hard) {
	(void)hard; // ignored, as discover and map are instantaneous
	noprotocol_impl_t *impl = state->impl;
	mutex_lock(&impl->mutex);
	impl->interrupted = true;
	mutex_unlock(&impl->mutex);
	cond_signal(&impl->interrupt_cond);
	return PROTOCOL_ERR_SUCCESS;
}
