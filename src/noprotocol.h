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

#ifndef PLUM_NOPROTOCOL_H
#define PLUM_NOPROTOCOL_H

#include "client.h"
#include "protocol.h"
#include "timestamp.h"
#include "thread.h"

#include <stdbool.h>

typedef struct {
	mutex_t mutex;
	cond_t interrupt_cond;
	bool interrupted;
} noprotocol_impl_t;

int noprotocol_init(protocol_state_t *state);
int noprotocol_cleanup(protocol_state_t *state);
int noprotocol_discover(protocol_state_t *state, timediff_t duration);
int noprotocol_map(protocol_state_t *state, const client_mapping_t *mapping,
                   protocol_map_output_t *output, timediff_t duration);
int noprotocol_unmap(protocol_state_t *state, const client_mapping_t *mapping, timediff_t duration);
int noprotocol_idle(protocol_state_t *state, timediff_t duration);
int noprotocol_interrupt(protocol_state_t *state, bool hard);

#endif
