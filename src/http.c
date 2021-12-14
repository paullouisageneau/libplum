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

#include "http.h"
#include "log.h"
#include "tcp.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

#define HTTP_MAX_HOST_LEN 256
#define HTTP_MAX_RECORDS 4

#define DEFAULT_BUFFER_SIZE 2 * 1024
#define MAX_BUFFER_SIZE 2 * 1024 * 1024

int http_perform(const http_request_t *request, http_response_t *response,
                 timestamp_t end_timestamp) {
	const char *scheme = "http://";
	const size_t scheme_len = strlen(scheme);

	const char *url = request->url;
	const size_t url_len = strlen(url);
	if (strncmp(url, scheme, scheme_len) != 0) {
		PLUM_LOG_WARN("HTTP request URL is invalid: %s", request->url);
		return -1;
	}

	const char *path = strchr(url + scheme_len, '/');
	if (!path)
		path = url + url_len;

	char host[HTTP_MAX_HOST_LEN];
	int host_len = (int)(path - (url + scheme_len));
	if (snprintf(host, HTTP_MAX_HOST_LEN, "%.*s", host_len, url + scheme_len) != host_len) {
		PLUM_LOG_WARN("Failed to retrieve HTTP host from URL");
		return -1;
	}

	char *service;
	char *separator = strchr(host, ':');
	if (separator) {
		*separator = '\0';
		service = separator + 1;
	} else {
		service = "80";
	}

	addr_record_t records[HTTP_MAX_RECORDS];
	int n = addr_resolve(host, service, records, HTTP_MAX_RECORDS);
	if (n <= 0) {
		PLUM_LOG_WARN("Failed to resolve HTTP host %s:%s", host, service);
		return -1;
	}
	if (n > HTTP_MAX_RECORDS)
		n = HTTP_MAX_RECORDS;

	socket_t sock = INVALID_SOCKET;
	for (int i = 0; i < n; ++i) {
		addr_record_t *record = records + i;
		sock = tcp_connect_socket(record, end_timestamp);
		if (sock != INVALID_SOCKET)
			break;
	}

	if (sock == INVALID_SOCKET) {
		PLUM_LOG_WARN("Failed to connect to HTTP host %s:%s", host, service);
		return -1;
	}

	size_t size = DEFAULT_BUFFER_SIZE;
	char *buffer = malloc(size);
	if (!buffer) {
		PLUM_LOG_WARN("Failed to allocate HTTP buffer, size=%zu", size);
		goto error;
	}

	const char *method_str = request->method == HTTP_METHOD_POST ? "POST" : "GET";

	int len;
	if (request->body_size > 0)
		len = snprintf(buffer, size,
		               "%s %s HTTP/1.0\r\n"
		               "Host: %s\r\n"
		               "Connection: close\r\n"
		               "Content-Length: %zu\r\n"
		               "Content-Type: %s\r\n"
		               "%s\r\n",
		               method_str, *path != '\0' ? path : "/", host, request->body_size,
		               request->body_type, request->headers ? request->headers : "");
	else
		len = snprintf(buffer, size,
		               "%s %s HTTP/1.0\r\n"
		               "Host: %s\r\n"
		               "Connection: close\r\n"
		               "%s\r\n",
		               method_str, *path != '\0' ? path : "/", host,
		               request->headers ? request->headers : "");

	if (len < 0 || len >= (int)size) {
		PLUM_LOG_WARN("Failed to format HTTP request");
		goto error;
	}

	PLUM_LOG_VERBOSE("Sending HTTP request: %s%s", buffer,
	                 request->body_size > 0 ? request->body : "");

	if (tcp_send(sock, buffer, len, end_timestamp) != len) {
		PLUM_LOG_WARN("Failed to send HTTP request");
		goto error;
	}

	if (request->body_size > 0) {
		if (tcp_send(sock, request->body, request->body_size, end_timestamp) !=
		    (int)request->body_size) {
			PLUM_LOG_WARN("Failed to send HTTP request body");
			goto error;
		}
	}

	size_t total_len = 0;
	while ((len = tcp_recv(sock, buffer + total_len, size - total_len, end_timestamp)) > 0) {
		total_len += len;

		if (total_len == size) {
			if (size == MAX_BUFFER_SIZE) {
				PLUM_LOG_WARN("HTTP response is too big");
				goto error;
			}

			size_t new_size = size * 2;
			if (new_size > MAX_BUFFER_SIZE)
				new_size = MAX_BUFFER_SIZE;

			char *new_buffer = realloc(buffer, new_size);
			if (!new_buffer) {
				PLUM_LOG_WARN("Failed to reallocate HTTP buffer, size=%zu", new_size);
				goto error;
			}

			buffer = new_buffer;
			size = new_size;
		}
	}

	if (len < 0) {
		PLUM_LOG_WARN("Failed to receive HTTP response");
		goto error;
	}

	buffer[total_len] = '\0'; // null-terminate response
	PLUM_LOG_VERBOSE("Received HTTP response: %s", buffer);

	int code = 0;
	if (sscanf(buffer, "HTTP/%*s %d %*s\n%n", &code, &len) != 1 || code <= 0) {
		PLUM_LOG_WARN("Failed to parse HTTP response status");
		goto error;
	}

	PLUM_LOG_DEBUG("Got HTTP response code %d", code);

	const char *headers_begin = buffer + len;
	const char *headers_end = strstr(headers_begin, "\r\n\r\n");
	if (!headers_end) {
		PLUM_LOG_WARN("Failed to parse HTTP response headers");
		goto error;
	}
	headers_end += 2;

	size_t headers_size = headers_end - headers_begin;
	response->headers = malloc(headers_size + 1);
	if (!response->headers) {
		PLUM_LOG_WARN("Failed to allocate memory for HTTP headers, size=%zu", headers_size + 1);
		goto error;
	}
	memcpy(response->headers, headers_begin, headers_size);
	response->headers[headers_size] = '\0';

	const char *body_begin = headers_end + 2;
	size_t body_size = buffer + total_len - body_begin;
	memmove(buffer, body_begin, body_size);
	response->body = buffer;

	closesocket(sock);
	return code;

error:
	free(buffer);
	closesocket(sock);
	return -1;
}

void http_free(http_response_t *response) {
	if (!response)
		return;

	free(response->headers);
	free(response->body);

	response->headers = NULL;
	response->body = NULL;
}
