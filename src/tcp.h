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

#ifndef PLUM_TCP_H
#define PLUM_TCP_H

#include "addr.h"
#include "socket.h"
#include "timestamp.h"

#include <stdint.h>

socket_t tcp_connect_socket(const addr_record_t *remote_addr, timestamp_t end_timestamp);
int tcp_recv(socket_t sock, char *buffer, size_t size, timestamp_t end_timestamp);
int tcp_send(socket_t sock, const char *data, size_t size, timestamp_t end_timestamp);

#endif // PLUM_UDP_H
