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

#include "timestamp.h"

#include <stdlib.h>

// Trivial implementation of an HTTP 1.0 client

#define HTTP_MAX_HOST_LEN 256
#define HTTP_MAX_URL_LEN 1024

typedef enum http_method {
	HTTP_METHOD_GET,
	HTTP_METHOD_POST,
} http_method_t;

typedef struct http_request {
	http_method_t method;
	const char *url;
	const char *headers;
	const char *body;
	const char *body_type;
	size_t body_size;
} http_request_t;

typedef struct http_response {
	char *headers;
	char *body;
	size_t body_size;
} http_response_t;

int http_perform(const http_request_t *request, http_response_t *response, timestamp_t end_timestamp);
void http_free(http_response_t *response);

