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

#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define PATTERN_BUFFER_SIZE 256

// Case-insensitive equivalent to strstr()
static char *my_stristr(const char *haystack, const char *needle) {
	// pattern to look for
	char *pptr = (char *)needle;
	size_t plen = strlen(needle);

	// string to look into
	char *start = (char *)haystack;
	size_t slen = strlen(haystack);

	// while pattern not longer than string
	while (slen >= plen) {
		// find start of pattern in string
		while (toupper(*start) != toupper(*needle)) {
			start++;
			slen--;
			if (slen < plen) {
				return NULL; // pattern longer than string
			}
		}

		char *sptr = start;
		pptr = (char *)needle;
		while (toupper(*sptr) == toupper(*pptr)) {
			sptr++;
			pptr++;
			if (*pptr == '\0')
				return start; // found whole pattern
		}

		++start;
		--slen;
	}

	return NULL;
}

const char *my_find(const char *str, const char *before, bool case_insensitive) {
	return case_insensitive ? my_stristr(str, before) : strstr(str, before);
}

int string_extract(const char *str, const char *before, const char *after, char *buffer,
                   size_t size, bool case_insensitive) {
	const char *begin = my_find(str, before, case_insensitive);
	if (!begin)
		return -1;

	begin += strlen(before);

	const char *end = my_find(begin, after, case_insensitive);
	if (!end)
		end = begin + strlen(begin);

	while (begin != end && isspace(*begin))
		++begin;

	while (begin != end && isspace(*(end - 1)))
		--end;

	int len = (int)(end - begin);
	return snprintf(buffer, size, "%.*s", len, begin);
}

int header_extract(const char *str, const char *name, char *buffer, size_t size) {
	if (*name == '\0')
		return -1;

	char before[PATTERN_BUFFER_SIZE];
	int ret = snprintf(before, PATTERN_BUFFER_SIZE, "%s:", name);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return -1;

	const char *after = "\r\n";

	return string_extract(str, before, after, buffer, size, true); // case-insensitive
}

int xml_extract(const char *str, const char *tag, char *buffer, size_t size) {
	if (*tag == '\0')
		return -1;

	char before[PATTERN_BUFFER_SIZE];
	int ret = snprintf(before, PATTERN_BUFFER_SIZE, "<%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return -1;

	char after[PATTERN_BUFFER_SIZE];
	ret = snprintf(after, PATTERN_BUFFER_SIZE, "</%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return -1;

	return string_extract(str, before, after, buffer, size, true); // case-insensitive
}

const char *xml_find_matching_child(const char *str, const char *tag, const char *child_tag,
                                    const char *child_value) {
	if (*tag == '\0' || *child_tag == '\0')
		return NULL;

	char before[PATTERN_BUFFER_SIZE];
	int ret = snprintf(before, PATTERN_BUFFER_SIZE, "<%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;

	char after[PATTERN_BUFFER_SIZE];
	ret = snprintf(after, PATTERN_BUFFER_SIZE, "</%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;

	char child_before[PATTERN_BUFFER_SIZE];
	ret = snprintf(child_before, PATTERN_BUFFER_SIZE, "<%s>", child_tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;

	char child_after[PATTERN_BUFFER_SIZE];
	ret = snprintf(child_after, PATTERN_BUFFER_SIZE, "</%s>", child_tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;

	const char *pos = str;
	while ((pos = my_find(pos, before, true))) {
		pos += strlen(before);

		const char *end = my_find(pos, after, true);
		if (!end)
			end = pos + strlen(pos);

		const char *child_pos = pos;
		while ((child_pos = my_find(child_pos, child_before, true)) && child_pos < end) {
			child_pos += strlen(child_before);

			const char *child_end = my_find(child_pos, child_after, true);
			if (!child_end)
				child_end = end;

			if (strncmp(child_value, child_pos, child_end - child_pos) == 0)
				return pos;
		}
	}

	return NULL;
}
