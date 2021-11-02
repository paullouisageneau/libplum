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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// String extraction utils
int string_extract(const char *str, const char *before, const char *after, char *buffer, size_t size, bool case_insensitive);
int header_extract(const char *str, const char *name, char *buffer, size_t size);
int xml_extract(const char *str, const char *tag, char *buffer, size_t size);
const char *xml_find_matching_child(const char *str, const char *tag, const char *child_tag, const char *child_value);

