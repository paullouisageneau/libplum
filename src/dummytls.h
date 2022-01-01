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

#ifndef PLUM_DUMMYTLS_H
#define PLUM_DUMMYTLS_H

#include "plum.h"
#include "socket.h"
#include "thread.h"
#include "timestamp.h"

#define DUMMYTLS_MAX_DOMAIN_LEN 256
#define DUMMYTLS_MAX_URL_LEN (DUMMYTLS_MAX_DOMAIN_LEN + 32)

void dummytls_init(void);
void dummytls_cleanup(void);

int dummytls_set_domain(const char *domain);
int dummytls_get_host(const struct sockaddr *sa, char *buffer, size_t size);
int dummytls_get_cert(plum_dummytls_cert_type_t type, char *buffer, size_t size);
int dummytls_renew_certs(void);

#endif
