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

#ifndef PLUM_UPNP_H
#define PLUM_UPNP_H

#include "addr.h"
#include "client.h"
#include "protocol.h"
#include "socket.h"
#include "timestamp.h"

#define UPNP_SSDP_ADDRESS "239.255.255.250"
#define UPNP_SSDP_PORT 1900

#define UPNP_BUFFER_SIZE 2048
#define UPNP_MAX_URL_LEN 2048
#define UPNP_MAX_HOST_LEN 256

typedef struct {
	socket_t sock;
	char external_addr_str[ADDR_MAX_STRING_LEN];
	char *location_url;
	char *control_url;
	bool interrupted;
} upnp_impl_t;

int upnp_init(protocol_state_t *state);
int upnp_cleanup(protocol_state_t *state);
int upnp_discover(protocol_state_t *state, timediff_t duration);
int upnp_map(protocol_state_t *state, const client_mapping_t *mapping,
             protocol_map_output_t *output, timediff_t duration);
int upnp_idle(protocol_state_t *state, timediff_t duration);
int upnp_interrupt(protocol_state_t *state);

int upnp_impl_probe(upnp_impl_t *impl, addr_record_t *found_gateway, timestamp_t end_timestamp);
int upnp_impl_query_control_url(upnp_impl_t *impl, timestamp_t end_timestamp);
int upnp_impl_query_external_addr(upnp_impl_t *impl, timestamp_t end_timestamp);
int upnp_impl_map(upnp_impl_t *impl, plum_ip_protocol_t protocol, uint16_t external_port,
                  uint16_t internal_port, unsigned int lifetime, timestamp_t end_timestamp);
int upnp_impl_unmap(upnp_impl_t *impl, plum_ip_protocol_t protocol, uint16_t external_port,
                    timestamp_t end_timestamp);

int upnp_impl_wait_response(upnp_impl_t *impl, char *buffer, size_t size, addr_record_t *src,
                            timestamp_t end_timestamp);

#endif
