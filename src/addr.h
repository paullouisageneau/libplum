/**
 * Copyright (c) 2020-2021 Paul-Louis Ageneau
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

#ifndef PLUM_ADDR_H
#define PLUM_ADDR_H

#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

// IPv6 max representation length is 45 plus 4 for potential zone index
#define ADDR_MAX_NUMERICHOST_LEN 56 // 45 + 4 + 1 rounded up
#define ADDR_MAX_NUMERICSERV_LEN 8 // 5 + 1 rounded up
#define ADDR_MAX_STRING_LEN 64

socklen_t addr_get_len(const struct sockaddr *sa);
int addr_get_host(const struct sockaddr *sa, char *buffer, size_t size);
uint16_t addr_get_port(const struct sockaddr *sa);
int addr_set_port(struct sockaddr *sa, uint16_t port);
bool addr_is_any(const struct sockaddr *sa);
bool addr_is_local(const struct sockaddr *sa);
bool addr_is_private(const struct sockaddr *sa);
bool addr_is_public(const struct sockaddr *sa);
bool addr_is_temp_inet6(const struct sockaddr *sa);
bool addr_unmap_inet6_v4mapped(struct sockaddr *sa, socklen_t *len);
bool addr_map_inet6_v4mapped(struct sockaddr_storage *ss, socklen_t *len);
bool addr_is_equal(const struct sockaddr *a, const struct sockaddr *b, bool compare_ports);
int addr_to_string(const struct sockaddr *sa, char *buffer, size_t size);

typedef struct addr_record {
	struct sockaddr_storage addr;
	socklen_t len;
} addr_record_t;

int addr_set(int family, const char *host, uint16_t port, addr_record_t *record);
int addr_set_binary(int family, const void *addr, uint16_t port, addr_record_t *record);
int addr_resolve(const char *hostname, const char *service, addr_record_t *records, size_t count);

bool addr_record_is_equal(const addr_record_t *a, const addr_record_t *b, bool compare_ports);
int addr_record_to_string(const addr_record_t *record, char *buffer, size_t size);

#endif // PLUM_ADDR_H
