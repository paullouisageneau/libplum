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
 */

#include "upnp.h"
#include "http.h"
#include "log.h"
#include "net.h"
#include "random.h"
#include "udp.h"
#include "util.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t random_port() {
	return (uint16_t)(1024 + plum_rand32() % (49151 - 1024)); // TODO
}

int upnp_init(protocol_state_t *state) {
	PLUM_LOG_VERBOSE("Initializing UPnP state");
	memset(state, 0, sizeof(*state));

	state->impl = malloc(sizeof(upnp_impl_t));
	if (!state->impl) {
		PLUM_LOG_ERROR("Allocation for UPnP state failed");
		return PROTOCOL_ERR_INSUFF_RESOURCES;
	}

	upnp_impl_t *impl = state->impl;
	memset(impl, 0, sizeof(*impl));
	impl->sock = INVALID_SOCKET;
	*impl->external_addr_str = '\0';
	impl->location_url = NULL;
	impl->control_url = NULL;
	impl->interrupt = ATOMIC_VAR_INIT(UPNP_INTERRUPT_NONE);

	udp_socket_config_t udp_config;
	memset(&udp_config, 0, sizeof(udp_config));
	udp_config.family = AF_INET;
	udp_config.port = 1900;
	udp_config.enable_broadcast = true;
	udp_config.enable_reuseaddr = true;
	impl->sock = udp_create_socket(&udp_config);
	if (impl->sock == INVALID_SOCKET) {
		PLUM_LOG_ERROR("UDP socket creation on port 1900 failed");
		goto error;
	}

	return PROTOCOL_ERR_SUCCESS;

error:
	if (impl->sock != INVALID_SOCKET)
		closesocket(impl->sock);

	free(state->impl);
	return PROTOCOL_ERR_INSUFF_RESOURCES;
}

int upnp_cleanup(protocol_state_t *state) {
	PLUM_LOG_VERBOSE("Cleaning up UPnP state");

	upnp_impl_t *impl = state->impl;
	closesocket(impl->sock);
	free(impl->location_url);
	free(impl->control_url);

	free(state->impl);
	return PROTOCOL_ERR_SUCCESS;
}

int upnp_discover(protocol_state_t *state, timediff_t duration) {
	upnp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	int probe_count = 0;
	timediff_t probe_duration = 250;
	do {
		timestamp_t probe_end_timestamp = current_timestamp() + probe_duration;
		if (probe_end_timestamp > end_timestamp)
			probe_end_timestamp = end_timestamp;

		timestamp_t query_end_timestamp = current_timestamp() + UPNP_QUERY_TIMEOUT;
		if (query_end_timestamp > end_timestamp)
			query_end_timestamp = end_timestamp;

		PLUM_LOG_DEBUG("Probing UPnP...");
		int err = upnp_impl_probe(impl, &state->gateway, probe_end_timestamp, query_end_timestamp);
		if (err == PROTOCOL_ERR_SUCCESS) {
			if (PLUM_LOG_INFO_ENABLED) {
				char gateway_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&state->gateway, gateway_str, ADDR_MAX_STRING_LEN);
				PLUM_LOG_INFO("Success probing UPnP, external address is %s",
				              impl->external_addr_str);
			}
			return PROTOCOL_ERR_SUCCESS;
		}

		if (err != PROTOCOL_ERR_TIMEOUT)
			return err;

		probe_duration *= 2;
	} while (++probe_count < UPNP_SSDP_MAX_ATTEMPTS && current_timestamp() < end_timestamp);

	return PROTOCOL_ERR_TIMEOUT;
}

int upnp_map(protocol_state_t *state, const client_mapping_t *mapping,
             protocol_map_output_t *output, timediff_t duration) {
	upnp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;
	memset(output, 0, sizeof(*output));

	if (*impl->external_addr_str == '\0') {
		timestamp_t query_end_timestamp = current_timestamp() + UPNP_QUERY_TIMEOUT;
		if (query_end_timestamp > end_timestamp)
			query_end_timestamp = end_timestamp;

		int err = upnp_impl_query_external_addr(impl, query_end_timestamp);
		if (err != PROTOCOL_ERR_SUCCESS)
			return err;
	}

	uint16_t external_port = mapping->external_addr.len > 0
	                             ? addr_get_port((const struct sockaddr *)&mapping->external_addr)
	                             : 0;
	if (external_port == 0) {
		external_port = mapping->suggested_addr.len > 0
		                    ? addr_get_port((const struct sockaddr *)&mapping->suggested_addr)
		                    : 0;
		if (external_port == 0)
			external_port = random_port();
	}

	int lifetime = 7200; // seconds

	int query_count = 0;
	do {
		timestamp_t query_end_timestamp = current_timestamp() + UPNP_QUERY_TIMEOUT;
		if (query_end_timestamp > end_timestamp)
			query_end_timestamp = end_timestamp;

		PLUM_LOG_DEBUG("Mapping with UPnP...");
		int err = upnp_impl_map(impl, mapping->protocol, external_port, mapping->internal_port,
		                        lifetime, query_end_timestamp);
		if (err == PROTOCOL_ERR_SUCCESS) {
			PLUM_LOG_DEBUG("Success mapping with UPnP");
			output->state = PROTOCOL_MAP_STATE_SUCCESS;
			output->refresh_timestamp =
			    current_timestamp() + (lifetime / 2) * 1000; // halfway expiry time
			addr_set(AF_INET, impl->external_addr_str, external_port, &output->external_addr);
			return PROTOCOL_ERR_SUCCESS;

		} else if (err > 0) { // if it's an UPnP error code
			switch (err) {
			case 718: // The port mapping entry specified conflicts with a object assigned
			          // previously to another client
				external_port = random_port();
				break;
			case 725: // The NAT implementation only supports permanent lease times on port mapping
				duration = 0;
				break;
			default:
				return PROTOCOL_ERR_PROTOCOL_FAILED;
				break;
			}

		} else if (err != PROTOCOL_ERR_TIMEOUT)
			return err;

	} while (++query_count < UPNP_MAP_MAX_ATTEMPTS && current_timestamp() < end_timestamp);

	return PROTOCOL_ERR_TIMEOUT;
}

int upnp_unmap(protocol_state_t *state, const client_mapping_t *mapping, timediff_t duration) {
	upnp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	uint16_t external_port = mapping->external_addr.len > 0
	                             ? addr_get_port((const struct sockaddr *)&mapping->external_addr)
	                             : 0;

	if (external_port == 0)
		return PROTOCOL_ERR_SUCCESS; // Nothing to do

	return upnp_impl_unmap(impl, mapping->protocol, external_port, end_timestamp);
}

int upnp_idle(protocol_state_t *state, timediff_t duration) {
	upnp_impl_t *impl = state->impl;
	timestamp_t end_timestamp = current_timestamp() + duration;

	char buffer[UPNP_BUFFER_SIZE];
	addr_record_t src;
	int len;
	while ((len = upnp_impl_wait_response(impl, buffer, UPNP_BUFFER_SIZE - 1, &src, end_timestamp,
	                                      true)) >= 0) {
		PLUM_LOG_DEBUG("Unexpected datagram, ignoring");
	}

	return len; // len < 0
}

int upnp_interrupt(protocol_state_t *state, bool hard) {
	upnp_impl_t *impl = state->impl;

	PLUM_LOG_VERBOSE("Interrupting UPnP operation");
	atomic_store(&impl->interrupt, hard ? UPNP_INTERRUPT_HARD : UPNP_INTERRUPT_SOFT);

	if (udp_sendto_self(impl->sock, NULL, 0) < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK) {
			PLUM_LOG_WARN("Failed to interrupt UPnP operation by triggering socket, errno=%d",
			              sockerrno);
			return PROTOCOL_ERR_UNKNOWN;
		}
	}

	return PROTOCOL_ERR_SUCCESS;
}

int upnp_impl_probe(upnp_impl_t *impl, addr_record_t *found_gateway, timestamp_t end_timestamp,
                    timestamp_t query_end_timestamp) {
	PLUM_LOG_DEBUG("Probing gateway with SSDP");
	addr_record_t broadcast;
	addr_set(AF_INET, UPNP_SSDP_ADDRESS, UPNP_SSDP_PORT, &broadcast);

	char broadcast_str[ADDR_MAX_STRING_LEN];
	addr_record_to_string(&broadcast, broadcast_str, ADDR_MAX_STRING_LEN);

	char buffer[UPNP_BUFFER_SIZE];
	int len = snprintf(buffer, UPNP_BUFFER_SIZE,
	                   "M-SEARCH * HTTP/1.1\r\n"
	                   "HOST: %s\r\n"
	                   "MAN: ssdp:discover\r\n"
	                   "MX: 10\r\n"
	                   "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
	                   broadcast_str);

	if (len <= 0 || len >= UPNP_BUFFER_SIZE) {
		PLUM_LOG_ERROR("Failed to write SSDP message to buffer");
		return PROTOCOL_ERR_UNKNOWN;
	}

	PLUM_LOG_DEBUG("Broadcasting SSDP request");
	if (udp_sendto(impl->sock, buffer, len, &broadcast) < 0) {
		PLUM_LOG_ERROR("UDP broadcast failed, errno=%d", sockerrno);
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	PLUM_LOG_DEBUG("Waiting for SSDP response...");
	addr_record_t src;
	while ((len = upnp_impl_wait_response(impl, buffer, UPNP_BUFFER_SIZE - 1, &src, end_timestamp,
	                                      false)) >= 0) {
		buffer[len] = '\0'; // null-terminate the string

		char tmp[UPNP_BUFFER_SIZE];
		if (header_extract(buffer, "NT", tmp, UPNP_BUFFER_SIZE) <= 0)
			if (header_extract(buffer, "ST", tmp, UPNP_BUFFER_SIZE) <= 0)
				continue;

		if (!strstr(tmp, "device:InternetGatewayDevice"))
			continue;

		if (header_extract(buffer, "SERVER", tmp, UPNP_BUFFER_SIZE) > 0) {
			PLUM_LOG_INFO("Found UPnP-IGD device: %s", tmp);
		}

		char location_url[HTTP_MAX_URL_LEN];
		if (header_extract(buffer, "LOCATION", location_url, HTTP_MAX_URL_LEN) <= 0) {
			PLUM_LOG_WARN("Missing location for UPnP-IGD device");
			continue;
		}

		*found_gateway = src;

		PLUM_LOG_DEBUG("UPnP-IGP location URL: %s", location_url);
		if (impl->location_url) {
			if (strcmp(impl->location_url, location_url) != 0) {
				PLUM_LOG_WARN("UPnP-IGP location URL has changed, resetting");
				return PROTOCOL_ERR_RESET;
			}
			return PROTOCOL_ERR_SUCCESS;
		}

		impl->location_url = malloc(strlen(location_url) + 1);
		strcpy(impl->location_url, location_url);

		int err = upnp_impl_query_control_url(impl, query_end_timestamp);
		if (err != PROTOCOL_ERR_SUCCESS)
			return err;

		return upnp_impl_query_external_addr(impl, query_end_timestamp);
	}

	return len; // len < 0
}

int upnp_impl_query_control_url(upnp_impl_t *impl, timestamp_t end_timestamp) {
	if (!impl->location_url) {
		PLUM_LOG_ERROR("Attempted to query UPnP control URL with unknown location URL");
		return PROTOCOL_ERR_UNKNOWN;
	}

	http_request_t request;
	memset(&request, 0, sizeof(request));
	request.method = HTTP_METHOD_GET;
	request.url = impl->location_url;
	request.headers = "";

	http_response_t response;
	int ret = http_perform(&request, &response, end_timestamp);
	if (ret < 0) {
		PLUM_LOG_WARN("Failed to send HTTP request to UPnP-IGD device");
		return PROTOCOL_ERR_UNKNOWN;
	}

	if (ret != 200) {
		PLUM_LOG_WARN("HTTP request to UPnP-IGD device failed, code=%d", ret);
		http_free(&response);
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	const char *serviceType = "urn:schemas-upnp-org:service:WANIPConnection:1";
	const char *service =
	    xml_find_matching_child(response.body, "service", "serviceType", serviceType);
	if (!service) {
		PLUM_LOG_WARN("WANIPConnection not found in UPnP-IGD services");
		http_free(&response);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	char control_url[HTTP_MAX_URL_LEN];
	if (xml_extract(service, "controlURL", control_url, HTTP_MAX_URL_LEN) <= 0) {
		PLUM_LOG_WARN("Missing control URL for UPnP-IGN service");
		http_free(&response);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	if (control_url[0] == '/') {
		char base_url[HTTP_MAX_URL_LEN];
		assert(strlen(impl->location_url) < HTTP_MAX_URL_LEN);
		strcpy(base_url, impl->location_url);
		char *p = strstr(base_url, "://");
		p = strchr(p ? p + 3 : base_url, '/');
		if (p)
			*p = '\0';

		char tmp[HTTP_MAX_URL_LEN];
		ret = snprintf(tmp, HTTP_MAX_URL_LEN, "%s%s", base_url, control_url);
		if (ret < 0 || ret >= HTTP_MAX_URL_LEN) {
			PLUM_LOG_WARN("WANIPConnection service control URL is too long");
			http_free(&response);
			return PROTOCOL_ERR_PROTOCOL_FAILED;
		}

		strcpy(control_url, tmp);
	}

	PLUM_LOG_DEBUG("UPnP-IGP WANIPConnection control URL: %s", control_url);
	free(impl->control_url);
	impl->control_url = malloc(strlen(control_url) + 1);
	strcpy(impl->control_url, control_url);

	http_free(&response);
	return PROTOCOL_ERR_SUCCESS;
}

int upnp_impl_query_external_addr(upnp_impl_t *impl, timestamp_t end_timestamp) {
	if (!impl->control_url) {
		PLUM_LOG_ERROR("Attempted to query external address with unknown control URL");
		return PROTOCOL_ERR_UNKNOWN;
	}

	http_request_t request;
	memset(&request, 0, sizeof(request));
	request.method = HTTP_METHOD_POST;
	request.url = impl->control_url;
	request.headers =
	    "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\r\n";
	request.body = "<?xml version=\"1.0\"?>\r\n"
	               "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
	               "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	               "<s:Body>"
	               "<m:GetExternalIPAddress "
	               "xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
	               "</m:GetExternalIPAddress>"
	               "</s:Body>"
	               "</s:Envelope>\r\n";
	request.body_size = strlen(request.body);
	request.body_type = "text/xml; charset=\"utf-8\"";

	http_response_t response;
	int ret = http_perform(&request, &response, end_timestamp);
	if (ret < 0) {
		PLUM_LOG_WARN("Failed to send HTTP request to UPnP-IGD device");
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	if (ret != 200) {
		PLUM_LOG_WARN("HTTP request to UPnP-IGD device failed, code=%d", ret);
		http_free(&response);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	if (xml_extract(response.body, "NewExternalIPAddress", impl->external_addr_str,
	                ADDR_MAX_STRING_LEN) <= 0) {
		PLUM_LOG_WARN("Missing external address in response");
		http_free(&response);
		return PROTOCOL_ERR_PROTOCOL_FAILED;
	}

	PLUM_LOG_DEBUG("UPnP-IGP WANIPConnection external address: %s", impl->external_addr_str);

	http_free(&response);
	return PROTOCOL_ERR_SUCCESS;
}

int upnp_impl_map(upnp_impl_t *impl, plum_ip_protocol_t protocol, uint16_t external_port,
                  uint16_t internal_port, unsigned int lifetime, timestamp_t end_timestamp) {
	if (!impl->control_url) {
		PLUM_LOG_ERROR("Attempted to map with UPnP with unknown control URL");
		return PROTOCOL_ERR_UNKNOWN;
	}

	addr_record_t local;
	if (net_get_default_interface(AF_INET, &local)) {
		PLUM_LOG_ERROR("Unable to get default interface address");
		return PROTOCOL_ERR_UNKNOWN;
	}

	char local_str[ADDR_MAX_STRING_LEN];
	addr_record_to_string(&local, local_str, ADDR_MAX_STRING_LEN);

	const char *description = "libplum"; // TODO

	char buffer[UPNP_BUFFER_SIZE];
	int len = snprintf(buffer, UPNP_BUFFER_SIZE,
	                   "<?xml version=\"1.0\"?>\r\n"
	                   "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
	                   "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	                   "<s:Body>"
	                   "<m:AddPortMapping "
	                   "xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
	                   "<NewRemoteHost></NewRemoteHost>"
	                   "<NewExternalPort>%hu</NewExternalPort>"
	                   "<NewProtocol>%s</NewProtocol>"
	                   "<NewInternalPort>%hu</NewInternalPort>"
	                   "<NewInternalClient>%s</NewInternalClient>"
	                   "<NewEnabled>1</NewEnabled>"
	                   "<NewPortMappingDescription>%s</NewPortMappingDescription>"
	                   "<NewLeaseDuration>%u</NewLeaseDuration>"
	                   "</m:AddPortMapping>"
	                   "</s:Body>"
	                   "</s:Envelope>\r\n",
	                   external_port, protocol == PLUM_IP_PROTOCOL_UDP ? "UDP" : "TCP",
	                   internal_port, local_str, description, lifetime);
	if (len <= 0 || len >= UPNP_BUFFER_SIZE) {
		PLUM_LOG_ERROR("Failed to format SOAP request body");
		return PROTOCOL_ERR_UNKNOWN;
	}

	http_request_t request;
	memset(&request, 0, sizeof(request));
	request.method = HTTP_METHOD_POST;
	request.url = impl->control_url;
	request.headers =
	    "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\r\n";
	request.body = buffer;
	request.body_size = strlen(request.body);
	request.body_type = "text/xml; charset=\"utf-8\"";

	http_response_t response;
	int ret = http_perform(&request, &response, end_timestamp);
	if (ret < 0) {
		PLUM_LOG_WARN("Failed to send HTTP request to UPnP-IGD device");
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	if (ret != 200) {
		char error_code_buffer[10];
		int error_code = 0;
		if (xml_extract(response.body, "errorCode", error_code_buffer, 10) <= 0 ||
		    (error_code = atoi(error_code_buffer)) <= 0) {
			PLUM_LOG_WARN("Got unknown UPnP error");
			return PROTOCOL_ERR_PROTOCOL_FAILED;
		}

		PLUM_LOG_WARN("Got UPnP error, code=%d", error_code);
		http_free(&response);
		return error_code;
	}

	http_free(&response);
	return PROTOCOL_ERR_SUCCESS;
}

int upnp_impl_unmap(upnp_impl_t *impl, plum_ip_protocol_t protocol, uint16_t external_port,
                    timestamp_t end_timestamp) {
	if (!impl->control_url) {
		PLUM_LOG_ERROR("Attempted to unmap with UPnP with unknown control URL");
		return PROTOCOL_ERR_UNKNOWN;
	}

	char buffer[UPNP_BUFFER_SIZE];
	int len =
	    snprintf(buffer, UPNP_BUFFER_SIZE,
	             "<?xml version=\"1.0\"?>\r\n"
	             "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
	             "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
	             "<s:Body>"
	             "<m:DeletePortMapping xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
	             "<NewRemoteHost></NewRemoteHost>"
	             "<NewExternalPort>%hu</NewExternalPort>"
	             "<NewProtocol>%s</NewProtocol>"
	             "</m:DeletePortMapping>"
	             "</s:Body>"
	             "</s:Envelope>\r\n",
	             external_port, protocol == PLUM_IP_PROTOCOL_UDP ? "UDP" : "TCP");
	if (len <= 0 || len >= UPNP_BUFFER_SIZE) {
		PLUM_LOG_ERROR("Failed to format SOAP request body");
		return PROTOCOL_ERR_UNKNOWN;
	}

	http_request_t request;
	memset(&request, 0, sizeof(request));
	request.method = HTTP_METHOD_POST;
	request.url = impl->control_url;
	request.headers =
	    "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\r\n";
	request.body = buffer;
	request.body_size = strlen(request.body);
	request.body_type = "text/xml; charset=\"utf-8\"";

	http_response_t response;
	int ret = http_perform(&request, &response, end_timestamp);
	if (ret < 0) {
		PLUM_LOG_WARN("Failed to send HTTP request to UPnP-IGD device");
		return PROTOCOL_ERR_NETWORK_FAILED;
	}

	if (ret != 200) {
		char error_code_buffer[10];
		int error_code = 0;
		if (xml_extract(response.body, "errorCode", error_code_buffer, 10) <= 0 ||
		    (error_code = atoi(error_code_buffer)) <= 0) {
			PLUM_LOG_WARN("Got unknown UPnP error");
			return PROTOCOL_ERR_PROTOCOL_FAILED;
		}

		PLUM_LOG_WARN("Got UPnP error, code=%d", error_code);
		http_free(&response);
		return error_code;
	}

	http_free(&response);
	return PROTOCOL_ERR_SUCCESS;
}

int upnp_impl_wait_response(upnp_impl_t *impl, char *buffer, size_t size, addr_record_t *src,
                            timestamp_t end_timestamp, bool interruptible) {
	timediff_t timediff;
	while ((timediff = end_timestamp - current_timestamp()) > 0) {

		upnp_interrupt_t interrupt = atomic_load(&impl->interrupt);
		if (interrupt == UPNP_INTERRUPT_HARD ||
		    (interrupt == UPNP_INTERRUPT_SOFT && interruptible)) {
			PLUM_LOG_VERBOSE("UPnP interrupted");
			atomic_store(&impl->interrupt, UPNP_INTERRUPT_NONE);
			return PROTOCOL_ERR_INTERRUPTED;
		}

		struct pollfd pfd;
		pfd.fd = impl->sock;
		pfd.events = POLLIN;

		PLUM_LOG_VERBOSE("Entering poll for %d ms", (int)timediff);
		int ret = poll(&pfd, 1, (int)timediff);
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				PLUM_LOG_VERBOSE("poll interrupted");
				continue;
			} else {
				PLUM_LOG_ERROR("poll failed, errno=%d", sockerrno);
				return PROTOCOL_ERR_UNKNOWN;
			}
		}

		PLUM_LOG_VERBOSE("Exiting poll");

		if (ret == 0) // timeout
			break;

		if (pfd.revents & POLLNVAL || pfd.revents & POLLERR) {
			PLUM_LOG_ERROR("Error when polling socket");
			return PROTOCOL_ERR_UNKNOWN;
		}

		if (pfd.revents & POLLIN) {
			int len = udp_recvfrom(pfd.fd, buffer, size, src);
			if (len < 0) {
				if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
					continue;

				PLUM_LOG_WARN("UDP recvfrom failed, errno=%d", sockerrno);
				return PROTOCOL_ERR_NETWORK_FAILED;
			}

			if (len > 0) // 0-length datagrams are used to interrupt, ignore them
				return len;
		}
	}

	return PROTOCOL_ERR_TIMEOUT;
}
