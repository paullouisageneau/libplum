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

#ifndef PLUM_LOG_H
#define PLUM_LOG_H

#include "plum.h"

#include <stdarg.h>

void plum_log_init();
void plum_log_cleanup();

void plum_set_log_level(plum_log_level_t level);
void plum_set_log_handler(plum_log_callback_t callback);

bool plum_log_is_enabled(plum_log_level_t level);
void plum_log_write(plum_log_level_t level, const char *file, int line, const char *fmt, ...);

#define PLUM_LOG_VERBOSE(...) plum_log_write(PLUM_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)
#define PLUM_LOG_DEBUG(...) plum_log_write(PLUM_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define PLUM_LOG_INFO(...) plum_log_write(PLUM_LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define PLUM_LOG_WARN(...) plum_log_write(PLUM_LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define PLUM_LOG_ERROR(...) plum_log_write(PLUM_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define PLUM_LOG_FATAL(...) plum_log_write(PLUM_LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#define PLUM_LOG_VERBOSE_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_VERBOSE)
#define PLUM_LOG_DEBUG_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_DEBUG)
#define PLUM_LOG_INFO_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_INFO)
#define PLUM_LOG_WARN_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_WARN)
#define PLUM_LOG_ERROR_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_ERROR)
#define PLUM_LOG_FATAL_ENABLED plum_log_is_enabled(PLUM_LOG_LEVEL_FATAL)

#endif // PLUM_LOG_H
