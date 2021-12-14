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

#include "pcp.h"
#include "client.h"
#include "log.h"
#include "natpmp.h"
#include "net.h"
#include "random.h"
#include "udp.h"

#include <stdlib.h>
#include <string.h>

int pcp_init(protocol_state_t *state) {
	memset(state, 0, sizeof(*state));
	state->impl = malloc(sizeof(pcp_impl_t));
	if (!state->impl) {
		PLUM_LOG_ERROR("Allocation for PCP/NAT-PMP state failed");
		return PROTOCOL_ERR_INSUFF_RESOURCES;
	}

	pcp_impl_t *impl = state->impl;
	memset(impl, 0, sizeof(*impl));
	impl->sock = INVALID_SOCKET;
	impl->mcast_sock = INVALID_SOCKET;
	impl->has_prev_server_time = false;
	impl->use_natpmp = false;
	impl->interrupted = false;

	udp_socket_config_t udp_config;
	memset(&udp_config, 0, sizeof(udp_config));
	udp_config.family = AF_INET;
	udp_config.port = 0;
	impl->sock = udp_create_socket(&udp_config);
	if (impl->sock == INVALID_SOCKET) {
		PLUM_LOG_ERROR("UDP socket creation failed");
		goto error;
	}

	udp_socket_config_t mcast_udp_config;
	memset(&mcast_udp_config, 0, sizeof(mcast_udp_config));
	mcast_udp_config.family = AF_INET;
	mcast_udp_config.port = 5350;
	mcast_udp_config.multicast_group = "224.0.0.1";
	mcast_udp_config.enable_reuseaddr = true;
	impl->mcast_sock = udp_create_socket(&mcast_udp_config);
	if (impl->mcast_sock == INVALID_SOCKET) {
		PLUM_LOG_ERROR("Multicast UDP socket creation on port 5350 failed");
		goto error;
	}

	return PROTOCOL_ERR_SUCCESS;

error:
	if (impl->sock != INVALID_SOCKET)
		closesocket(impl->sock);

	if (impl->mcast_sock != INVALID_SOCKET)
		closesocket(impl->mcast_sock);

	free(state->impl);
	return PROTOCOL_ERR_INSUFF_RESOURCES;
}

int pcp_cleanup(protocol_state_t *state) {
	pcp_impl_t *impl = state->impl;
	closesocket(impl->sock);
	closesocket(impl->mcast_sock);

	free(state->impl);
	return PROTOCOL_ERR_SUCCESS;
}

int pcp_discover(protocol_state_t *state, timediff_t duration) {
	pcp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	int probe_count = 0;
	timediff_t probe_duration = 250;
	do {
		timestamp_t probe_end_timestamp = current_timestamp() + probe_duration;
		if (probe_end_timestamp > end_timestamp)
			probe_end_timestamp = end_timestamp;

		int err;
		if (impl->use_natpmp) {
			PLUM_LOG_DEBUG("Probing NAT-PMP...");
			err = natpmp_impl_probe(impl, &state->gateway, probe_end_timestamp);
		} else {
			PLUM_LOG_DEBUG("Probing PCP...");
			err = pcp_impl_probe(impl, &state->gateway, probe_end_timestamp);
		}
		if (err == PROTOCOL_ERR_SUCCESS) {
			if (PLUM_LOG_INFO_ENABLED) {
				char gateway_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&state->gateway, gateway_str, ADDR_MAX_STRING_LEN);
				if (impl->use_natpmp)
					PLUM_LOG_INFO("Success probing NAT-PMP, gateway address is %s", gateway_str);
				else
					PLUM_LOG_INFO("Success probing PCP, gateway address is %s", gateway_str);
			}
			return PROTOCOL_ERR_SUCCESS;
		}

		if (err != PROTOCOL_ERR_TIMEOUT)
			return err;

		probe_duration *= 2;
	} while (++probe_count < 9 && current_timestamp() < end_timestamp);

	return PROTOCOL_ERR_TIMEOUT;
}

int pcp_map(protocol_state_t *state, const client_mapping_t *mapping, protocol_map_output_t *output,
            timediff_t duration) {
	pcp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	int map_count = 0;
	timediff_t map_duration = 250;
	do {
		timestamp_t map_end_timestamp = current_timestamp() + map_duration;
		if (map_end_timestamp > end_timestamp)
			map_end_timestamp = end_timestamp;

		int err;
		if (impl->use_natpmp) {
			PLUM_LOG_DEBUG("Mapping with NAT-PMP...");
			err = natpmp_impl_map(impl, mapping, output, &state->gateway, map_end_timestamp);
		} else {
			PLUM_LOG_DEBUG("Mapping with PCP...");
			err = pcp_impl_map(impl, mapping, output, &state->gateway, map_end_timestamp);
		}

		if (err == PROTOCOL_ERR_SUCCESS) {
			if (impl->use_natpmp)
				PLUM_LOG_DEBUG("Success mapping with NAT-PMP");
			else
				PLUM_LOG_DEBUG("Success mapping with PCP");

			return PROTOCOL_ERR_SUCCESS;
		}

		if(err == PROTOCOL_ERR_UNSUPP_VERSION && !impl->use_natpmp) {
			impl->use_natpmp = true;
			continue;
		}

		if (err != PROTOCOL_ERR_TIMEOUT)
			return err;

		map_duration *= 2;
	} while (++map_count < 9 && current_timestamp() < end_timestamp);

	return PROTOCOL_ERR_TIMEOUT;
}

int pcp_idle(protocol_state_t *state, timediff_t duration) {
	pcp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	char buffer[PCP_MAX_PAYLOAD_LENGTH];
	addr_record_t src;
	int len;
	while ((len = pcp_natpmp_impl_wait_response(impl, buffer, &src, end_timestamp)) >= 0) {
		PLUM_LOG_DEBUG("Unexpected datagram, ignoring");
	}

	return len; // len < 0
}

int pcp_interrupt(protocol_state_t *state) {
	pcp_impl_t *impl = state->impl;

	impl->interrupted = true;

	PLUM_LOG_VERBOSE("Interrupting PCP/NAT-PMP operation");
	if (udp_sendto_self(impl->sock, NULL, 0) < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK) {
			PLUM_LOG_WARN(
			    "Failed to interrupt PCP/NAT-PMP operation by triggering socket, errno=%d",
			    sockerrno);
			return PROTOCOL_ERR_UNKNOWN;
		}
	}

	return PROTOCOL_ERR_SUCCESS;
}

static int write_pcp_header(struct pcp_request_header *header, uint8_t opcode, uint32_t lifetime) {
	memset(header, 0, sizeof(*header));
	header->version = PCP_VERSION;
	header->opcode = opcode;
	header->lifetime = lifetime;

	addr_record_t local;
	if (net_get_default_interface(AF_INET, &local)) {
		PLUM_LOG_ERROR("Unable to get default interface address");
		return PROTOCOL_ERR_UNKNOWN;
	}

	// RFC 6887: When the address field holds an IPv4 address, an IPv4-mapped IPv6 address
	// [RFC4291] is used.
	addr_map_inet6_v4mapped(&local.addr, &local.len);
	struct sockaddr_in6 *local_sin6 = (struct sockaddr_in6 *)&local.addr;
	memcpy(header->client_address, &local_sin6->sin6_addr, 16);
	return 0;
}

int pcp_impl_probe(pcp_impl_t *impl, addr_record_t *found_gateway, timestamp_t end_timestamp) {
	addr_record_t gateway;
	if (net_get_default_gateway(AF_INET, &gateway)) {
		PLUM_LOG_ERROR("Unable to get the default gateway address");
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	addr_set_port((struct sockaddr *)&gateway.addr, PCP_SERVER_PORT);

	if (found_gateway && found_gateway->len &&
	    !addr_record_is_equal(&gateway, found_gateway, false)) {
		PLUM_LOG_DEBUG("Default gateway changed");
		return PROTOCOL_ERR_RESET;
	}

	if (PLUM_LOG_DEBUG_ENABLED) {
		char gateway_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(&gateway, gateway_str, ADDR_MAX_STRING_LEN);
		PLUM_LOG_DEBUG("Probing gateway at %s", gateway_str);
	}

	char buffer[PCP_MAX_PAYLOAD_LENGTH];
	if (write_pcp_header((struct pcp_request_header *)buffer, PCP_OPCODE_ANNOUNCE, 0)) {
		PLUM_LOG_ERROR("Unable to write PCP header");
		return PROTOCOL_ERR_UNKNOWN;
	}

	PLUM_LOG_DEBUG("Sending PCP announce request");
	if (udp_sendto(impl->sock, buffer, sizeof(struct pcp_request_header), &gateway) < 0) {
		PLUM_LOG_ERROR("UDP send failed, errno=%d", sockerrno);
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	PLUM_LOG_DEBUG("Waiting for PCP announce response...");
	addr_record_t src;
	int len;
	while ((len = pcp_natpmp_impl_wait_response(impl, buffer, &src, end_timestamp)) >= 0) {
		if (len < (int)sizeof(struct pcp_common_header)) {
			PLUM_LOG_WARN("Datagram of length %d is too short, ignoring", len);
			continue;
		}
		const struct pcp_common_header *common_header = (const struct pcp_common_header *)buffer;
		if (common_header->opcode != (PCP_OPCODE_ANNOUNCE | PCP_OPCODE_RESPONSE_BIT)) {
			PLUM_LOG_DEBUG("Unexpected response opcode, ignoring");
			continue;
		}

		uint8_t result = common_header->result;
		if (result != PCP_RESULT_SUCCESS) {
			PLUM_LOG_WARN("Got PCP error response, result=%u", (unsigned int)result);

			if (result == PCP_RESULT_UNSUPP_VERSION)
				return PROTOCOL_ERR_UNSUPP_VERSION;
			else
				return PROTOCOL_ERR_PROTOCOL_FAILED; // TODO
		}

		if (len < (int)sizeof(struct pcp_response_header)) {
			PLUM_LOG_WARN("Announce response of length %d is too short", len);
			continue;
		}
		const struct pcp_response_header *header = (const struct pcp_response_header *)buffer;
		uint32_t epoch_time = ntohl(header->epoch_time);
		int err = pcp_impl_check_epoch_time(impl, epoch_time);
		if (err == PROTOCOL_ERR_RESET)
			return err;

		PLUM_LOG_DEBUG("Success probing PCP compatible gateway");
		if (found_gateway)
			*found_gateway = gateway;

		return PROTOCOL_ERR_SUCCESS;
	}

	return len; // len < 0
}

int pcp_impl_map(pcp_impl_t *impl, const client_mapping_t *mapping, protocol_map_output_t *output,
                 const addr_record_t *gateway, timestamp_t end_timestamp) {
	// RFC 6887: The PCP client requests a certain lifetime, and the PCP server responds with the
	// assigned lifetime. The PCP server MAY grant a lifetime smaller or larger than the requested
	// lifetime. The PCP server SHOULD be configurable for permitted minimum and maximum lifetime,
	// and the minimum value SHOULD be 120 seconds. The maximum value SHOULD be the remaining
	// lifetime of the IP address assigned to the PCP client if that information is available (e.g.,
	// from the DHCP server), or half the lifetime of IP address assignments on that network if the
	// remaining lifetime is not available, or 24 hours.
	uint32_t lifetime = 7200; // seconds

	char buffer[PCP_MAX_PAYLOAD_LENGTH];
	if (write_pcp_header((struct pcp_request_header *)buffer, PCP_OPCODE_MAP, lifetime)) {
		PLUM_LOG_ERROR("Unable to write PCP header");
		return PROTOCOL_ERR_UNKNOWN;
	}

	char nonce[PCP_MAP_NONCE_SIZE];
	plum_random(nonce, PCP_MAP_NONCE_SIZE);

	pcp_protocol_t protocol;
	switch (mapping->protocol) {
	case PLUM_IP_PROTOCOL_TCP:
		protocol = PCP_PROTOCOL_TCP;
		break;
	case PLUM_IP_PROTOCOL_UDP:
		protocol = PCP_PROTOCOL_UDP;
		break;
	default:
		protocol = PCP_PROTOCOL_ALL;
		break;
	}

	struct pcp_map_request *map =
	    (struct pcp_map_request *)(buffer + sizeof(struct pcp_request_header));
	memset(map, 0, sizeof(*map));
	memcpy(map->nonce, nonce, PCP_MAP_NONCE_SIZE);
	map->protocol = protocol;
	map->internal_port = htons(mapping->internal_port);

	addr_record_t suggested = mapping->suggested_addr;

	// RFC 6887: If the PCP client does not know the external address, or does not have a
	// preference, it MUST use the address-family-specific all-zeros address
	if (suggested.len == 0)
		addr_set(AF_INET, "0.0.0.0", 0, &suggested);

	// RFC 6887: When the address field holds an IPv4 address, an IPv4-mapped IPv6 address
	// [RFC4291] is used.
	addr_map_inet6_v4mapped(&suggested.addr, &suggested.len);
	struct sockaddr_in6 *suggested_sin6 = (struct sockaddr_in6 *)&suggested.addr;
	map->suggested_external_port = suggested_sin6->sin6_port; // network byte-order
	memcpy(map->suggested_external_addr, &suggested_sin6->sin6_addr, 16);

	PLUM_LOG_DEBUG("Sending PCP map request");
	if (udp_sendto(impl->sock, buffer,
	               sizeof(struct pcp_request_header) + sizeof(struct pcp_map_request),
	               gateway) < 0) {
		PLUM_LOG_ERROR("UDP send failed, errno=%d", sockerrno);
		return -1;
	}

	PLUM_LOG_DEBUG("Waiting for PCP map response...");
	addr_record_t src;
	int len;
	while ((len = pcp_natpmp_impl_wait_response(impl, buffer, &src, end_timestamp)) >= 0) {
		if (len < (int)sizeof(struct pcp_response_header)) {
			PLUM_LOG_WARN("Mapping response of length %d is too short", len);
			continue;
		}
		const struct pcp_response_header *header = (const struct pcp_response_header *)buffer;
		if (header->opcode != (PCP_OPCODE_MAP | PCP_OPCODE_RESPONSE_BIT)) {
			PLUM_LOG_DEBUG("Unexpected response opcode, ignoring");
			continue;
		}

		uint32_t epoch_time = ntohl(header->epoch_time);
		int err = pcp_impl_check_epoch_time(impl, epoch_time);
		if (err == PROTOCOL_ERR_RESET)
			return err;

		if (header->result != PCP_RESULT_SUCCESS) {
			PLUM_LOG_WARN("Got PCP error response, result=%d", (int)header->result);
			continue;
		}
		if (len < (int)(sizeof(struct pcp_response_header) + sizeof(struct pcp_map_response))) {
			PLUM_LOG_WARN("Mapping success response of length=%d is too short", len);
			continue;
		}

		const struct pcp_map_response *map =
		    (const struct pcp_map_response *)(buffer + sizeof(struct pcp_response_header));
		if (memcmp(map->nonce, nonce, PCP_MAP_NONCE_SIZE) != 0) {
			PLUM_LOG_WARN("Got incorrect nonce in map response");
			return PROTOCOL_ERR_UNKNOWN;
		}

		uint32_t response_lifetime = ntohl(header->lifetime);
		PLUM_LOG_VERBOSE("Server mapping lifetime is %us", (unsigned int)response_lifetime);

		if (lifetime > response_lifetime)
			lifetime = response_lifetime;

		// RFC 6887: The PCP client SHOULD renew the mapping before its expiry time; otherwise, it
		// will be removed by the PCP server. To reduce the risk of inadvertent synchronization of
		// renewal requests, a random jitter component should be included.
		uint32_t r;
		plum_random(&r, sizeof(r));
		timediff_t expiry_delay = (timediff_t)lifetime * 1000;
		timediff_t refresh_delay = expiry_delay / 2 + r % (expiry_delay / 4);
		PLUM_LOG_VERBOSE("Renewing mapping in %us", (unsigned int)(refresh_delay / 1000));
		output->refresh_timestamp = current_timestamp() + refresh_delay;

		struct sockaddr_in6 *external_sin6 = (struct sockaddr_in6 *)&impl->external_addr.addr;
		memset(external_sin6, 0, sizeof(*external_sin6));
		impl->external_addr.len = sizeof(*external_sin6);
		external_sin6->sin6_family = AF_INET6;
		external_sin6->sin6_port = map->external_port; // network byte-order
		memcpy(&external_sin6->sin6_addr, map->external_addr, 16);
		addr_unmap_inet6_v4mapped((struct sockaddr *)&impl->external_addr.addr,
		                          &impl->external_addr.len);
		output->external_addr = impl->external_addr;
		return PROTOCOL_ERR_SUCCESS;
	}

	return len; // len < 0
}

int pcp_impl_process_mcast_response(pcp_impl_t *impl, const char *buffer, int len) {
	if (len < (int)sizeof(struct pcp_response_header)) {
		PLUM_LOG_WARN("Datagram of length %d is too short, ignoring", len);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	const struct pcp_response_header *header = (const struct pcp_response_header *)buffer;
	if (header->opcode != (PCP_OPCODE_ANNOUNCE | PCP_OPCODE_RESPONSE_BIT)) {
		PLUM_LOG_DEBUG("Unexpected opcode received multicast socket, ignoring");
		return PROTOCOL_ERR_SUCCESS;
	}

	uint32_t epoch_time = ntohl(header->epoch_time);
	int err = pcp_impl_check_epoch_time(impl, epoch_time);
	if (err == PROTOCOL_ERR_RESET)
		return err;

	return PROTOCOL_ERR_SUCCESS;
}

int pcp_impl_check_epoch_time(pcp_impl_t *impl, uint32_t curr_server_time) {
	PLUM_LOG_VERBOSE("PCP server epoch time is %u", (unsigned int)curr_server_time);
	uint32_t curr_client_time = (uint32_t)(current_timestamp() / 1000); // seconds

	// RFC 6887: Whenever a client receives a PCP response, the client validates the received Epoch
	// Time value according to the procedure below, using integer arithmetic:
	bool is_valid;

	// ... If this is the first PCP response the client has received from this PCP server, the Epoch
	// Time value is treated as necessarily valid
	if (!impl->has_prev_server_time) {
		is_valid = true;
	}
	// ... If the current PCP server Epoch time (curr_server_time) is less than the previously
	// received PCP server Epoch time (prev_server_time) by more than one second, then the
	// client treats the Epoch time as obviously invalid (time should not go backwards).
	else if (curr_server_time < impl->prev_server_time - 1) {
		is_valid = false;
	}
	// If the server Epoch time passes this check, then further validation checks are performed:
	else {
		// ... The client computes the difference between its current local time (curr_client_time)
		// and the time the previous PCP response was received from this PCP server
		// (prev_client_time)
		uint32_t client_delta = curr_client_time - impl->prev_client_time;

		// ... The client computes the difference between the current PCP server Epoch time
		// (curr_server_time) and the previously received Epoch time (prev_server_time)
		uint32_t server_delta = curr_server_time - impl->prev_server_time;

		// ... If client_delta+2 < server_delta - server_delta/16 or server_delta+2 < client_delta -
		// client_delta/16, then the client treats the Epoch Time value as invalid, else the client
		// treats the Epoch Time value as valid.
		is_valid = !(client_delta + 2 < server_delta - server_delta / 16 ||
		             server_delta + 2 < client_delta - client_delta / 16);
	}

	// ... The client records the current time values for use in its next comparison
	impl->prev_client_time = curr_client_time;
	impl->prev_server_time = curr_server_time;

	if (!is_valid) {
		PLUM_LOG_INFO("PCP reset detected");
		return PROTOCOL_ERR_RESET;
	}

	return PROTOCOL_ERR_SUCCESS;
}

static int process_mcast_response(pcp_impl_t *impl, const char *buffer, int len) {
	if (len < (int)sizeof(struct pcp_common_header)) {
		PLUM_LOG_WARN("Datagram of length %d is too short, ignoring", len);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}
	const struct pcp_common_header *common_header = (const struct pcp_common_header *)buffer;
	uint8_t opcode = common_header->opcode;
	if (opcode != (PCP_OPCODE_ANNOUNCE | PCP_OPCODE_RESPONSE_BIT)) {
		PLUM_LOG_DEBUG("Unexpected response opcode, ignoring");
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	uint8_t version = common_header->version;
	if (!impl->use_natpmp && version == PCP_VERSION)
		return pcp_impl_process_mcast_response(impl, buffer, len);
	if (impl->use_natpmp && version == NATPMP_VERSION)
		return natpmp_impl_process_mcast_response(impl, buffer, len);
	else
		return PROTOCOL_ERR_UNSUPP_VERSION;
}

int pcp_natpmp_impl_wait_response(pcp_impl_t *impl, char *buffer, addr_record_t *src,
                                  timestamp_t end_timestamp) {
	timediff_t timediff;
	while (!impl->interrupted && (timediff = end_timestamp - current_timestamp()) > 0) {
		struct pollfd pfd[2];
		pfd[0].fd = impl->mcast_sock;
		pfd[0].events = POLLIN;
		pfd[1].fd = impl->sock;
		pfd[1].events = POLLIN;

		PLUM_LOG_VERBOSE("Entering poll for %d ms", (int)timediff);
		int ret = poll(pfd, 2, (int)timediff);
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				PLUM_LOG_VERBOSE("poll interrupted");
				continue;
			} else {
				PLUM_LOG_ERROR("poll failed, errno=%d", sockerrno);
				return PROTOCOL_ERR_UNKNOWN;
			}
		}

		if (ret == 0) // timeout
			break;

		for (int i = 0; i < 2; ++i) {
			if (pfd[i].revents & POLLNVAL || pfd[i].revents & POLLERR) {
				PLUM_LOG_ERROR("Error when polling socket");
				return PROTOCOL_ERR_UNKNOWN;
			}

			if (pfd[i].revents & POLLIN) {
				int len = udp_recvfrom(pfd[i].fd, buffer, PCP_MAX_PAYLOAD_LENGTH, src);
				if (len < 0) {
					if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
						continue;

					PLUM_LOG_WARN("UDP recvfrom failed, errno=%d", sockerrno);
					if (sockerrno == SECONNRESET) // ICMP Port Unreachable
						return PROTOCOL_ERR_UNSUPP_PROTOCOL;
					else
						return PROTOCOL_ERR_NETWORK_FAILED;
				}

				if (i == 0) {                                            // mcast_sock
					int err = process_mcast_response(impl, buffer, len); // handles PCP and NAT-PMP
					if (err == PROTOCOL_ERR_RESET)
						return err;
				} else {         // sock
					if (len > 0) // 0-length datagrams are used to interrupt, ignore them
						return len;
				}
			}
		}
	}

	if (impl->interrupted) {
		impl->interrupted = false;
		return PROTOCOL_ERR_INTERRUPTED;
	}

	return PROTOCOL_ERR_TIMEOUT;
}
