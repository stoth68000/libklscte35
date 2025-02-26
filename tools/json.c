/*
 * Copyright (c) 2025 Kernel Labs Inc. All Rights Reserved
 *
 * Address: Kernel Labs Inc., PO Box 745, St James, NY. 11780
 * Contact: sales@kernellabs.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* Purpose: parse a SCTE35 message, and output the JSON representation */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libklscte35/scte35.h>
#include "scte35_samples.h"

static int parse(const uint8_t *sec, int byteCount)
{
	printf("\nParsing a new SCTE35 section......\n");

	printf("Original section data:\n");
	for (int i = 0; i < byteCount; i++)
		printf("%02x ", sec[i]);
	printf("\n");

	struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(sec, byteCount);
	if (s) {
		/* Dump struct to console */
		scte35_splice_info_section_print(s);

		char *buf;
		uint16_t byteCount;
		int ret = scte35_create_json_message(s, &buf, &byteCount);
		if (ret == 0) {
			printf("JSON formatted message : ");
			printf("%s\n", buf);
			free(buf);
		} else {
			fprintf(stderr, "Unable to convert SCTE35 to JSON, ret = %d\n", ret);
		}

		/* Free the allocated resource */
		scte35_splice_info_section_free(s);
	}

	return 0;
}

int scte35tojson_main(int argc, char *argv[])
{
	int i = 0;
	int ret = 0;
	while (ret == 0) {
		const char *name;
		const uint8_t *buf;
		size_t buf_size;

		ret = get_scte35sample(i, &name, &buf, &buf_size);
		if (ret != 0)
			break;

		printf("Parsing %s\n", name);
		parse(buf, buf_size);
		i++;
	}

	printf("program complete.\n");
	return 0;
}
