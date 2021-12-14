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

#include "tcp.h"
#include "log.h"
#include "timestamp.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

socket_t tcp_connect_socket(const addr_record_t *remote_addr, timestamp_t end_timestamp) {
	socket_t sock = INVALID_SOCKET;
	int family = remote_addr->addr.ss_family;

	// Create socket
	sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		PLUM_LOG_ERROR("TCP socket creation failed, errno=%d", sockerrno);
		goto error;
	}

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		PLUM_LOG_ERROR("Setting non-blocking mode on TCP socket failed, errno=%d", sockerrno);
		goto error;
	}

#ifdef __APPLE__
	// MacOS lacks MSG_NOSIGNAL and requires SO_NOSIGPIPE instead
	int opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt))) {
		PLUM_LOG_ERROR("Failed to disable SIGPIPE for socket");
		goto error;
	}
#endif

	// Initiate connection
	int ret =
	    connect(sock, (const struct sockaddr *)&remote_addr->addr, (socklen_t)remote_addr->len);
	if (ret != 0 && sockerrno != SEINPROGRESS && sockerrno != SEWOULDBLOCK) {
		PLUM_LOG_ERROR("TCP connection failed, errno=%d", sockerrno);
		goto error;
	}

	// Wait for connection
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLOUT;

	do {
		timediff_t timediff = end_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		ret = poll(&pfd, 1, (int)timediff);

	} while (ret < 0 && (sockerrno == SEINTR || sockerrno == SEAGAIN));

	if (ret < 0) {
		PLUM_LOG_ERROR("Failed to wait for TCP socket connection");
		goto error;
	}

	if (!(pfd.revents & POLLOUT)) {
		PLUM_LOG_ERROR("TCP connection timed out");
		goto error;
	}

	int err = 0;
	socklen_t errlen = sizeof(err);
	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) != 0) {
		PLUM_LOG_ERROR("Failed to get socket error code");
		goto error;
	}

	if (err != 0) {
		PLUM_LOG_ERROR("TCP connection failed, errno=%d", err);
		goto error;
	}

	PLUM_LOG_DEBUG("TCP connection succeeded");
	return sock;

error:
	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return INVALID_SOCKET;
}

int tcp_recv(socket_t sock, char *buffer, size_t size, timestamp_t end_timestamp) {
	while (true) {
		timediff_t timediff = end_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLIN;

		PLUM_LOG_VERBOSE("Entering poll for %d ms", (int)timediff);
		int ret = poll(&pfd, 1, (int)timediff);
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				PLUM_LOG_VERBOSE("poll interrupted");
				continue;
			} else {
				PLUM_LOG_ERROR("poll failed, errno=%d", sockerrno);
				return -1;
			}
		}

		if (ret == 0) // timeout
			break;

		if (pfd.revents & POLLNVAL || pfd.revents & POLLERR) {
			PLUM_LOG_ERROR("Error when polling socket");
			return -1;
		}

		if (pfd.revents & POLLIN) {
#if defined(__APPLE__) || defined(_WIN32)
			int flags = 0;
#else
			int flags = MSG_NOSIGNAL;
#endif
			int len = recv(pfd.fd, buffer, (int)size, flags);
			if (len < 0) {
				if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
					continue;

				PLUM_LOG_WARN("TCP recv failed, errno=%d", sockerrno);
				return -1;
			}

			return len;
		}
	}

	// Timeout
	PLUM_LOG_WARN("TCP recv timeout");
	return -1;
}

int tcp_send(socket_t sock, const char *data, size_t size, timestamp_t end_timestamp) {
	size_t left = size;
	while (true) {
		timediff_t timediff = end_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLOUT;

		PLUM_LOG_VERBOSE("Entering poll for %d ms", (int)timediff);
		int ret = poll(&pfd, 1, (int)timediff);
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				PLUM_LOG_VERBOSE("poll interrupted");
				continue;
			} else {
				PLUM_LOG_ERROR("poll failed, errno=%d", sockerrno);
				return -1;
			}
		}

		if (ret == 0)
			break;

		if (pfd.revents & POLLNVAL || pfd.revents & POLLERR) {
			PLUM_LOG_ERROR("Error when polling socket");
			return -1;
		}

		if (pfd.revents & POLLOUT) {
#if defined(__APPLE__) || defined(_WIN32)
			int flags = 0;
#else
			int flags = MSG_NOSIGNAL;
#endif
			int len = send(pfd.fd, data, (int)size, flags);
			if (len < 0) {
				if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
					continue;

				PLUM_LOG_WARN("TCP recv failed, errno=%d", sockerrno);
				return -1;
			}

			data += len;
			left -= len;

			if (left == 0)
				return (int)size;
		}
	}

	// Timeout
	PLUM_LOG_WARN("TCP send timeout");
	size_t sent = size - left;
	return sent == 0 ? -1 : (int)sent;
}
