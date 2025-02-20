/*
 * Copyright (c) 2016 Kernel Labs Inc. All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libklscte35/scte35.h>
#include "scte35_samples.h"

/* Counters to keep track of test results */
static int success=0;
static int fail=0;

static void hexdump(const uint8_t *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

static int parse(const uint8_t *sec, int byteCount)
{
	struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(sec, byteCount);
	unsigned char buf[1024];
	int ret;

	if (s) {

		/* Dump struct to console */
		scte35_splice_info_section_print(s);

                /* Verify our generator creates the same payload */
		memset(buf, 0, sizeof(buf));
		ret = scte35_splice_info_section_packTo(s, buf, sizeof(buf));
		if (ret < 0) {
			printf("Failed to create section\n");
			fail++;
			return 0;
		}

		if (ret == byteCount && memcmp(sec, buf, byteCount) == 0) {
			printf("Identical!\n");
			success++;
		} else if (ret == byteCount && memcmp(sec+2, buf+2, byteCount-6) == 0) {
			printf("Only difference is Reserved padding at start of segment!\n");
			success++;
		} else {
			struct scte35_splice_info_section_s *generated;
			printf("Different!\n");
			fail++;

			/* Show the differences */
			printf("Orig (len=%d)\n", byteCount);
			hexdump(sec, byteCount, 16);
			printf("New (len=%d)\n", ret);
			if (ret >= 0)
				hexdump(buf, ret, 16);

			generated = scte35_splice_info_section_parse(buf, ret);
			if (generated) {
				scte35_splice_info_section_print(generated);
				scte35_splice_info_section_free(generated);
			}
		}
		/* Free the allocated resource */
		scte35_splice_info_section_free(s);

		printf("\n");
	} else {
		fail++;
	}

	return 0;
}

int parse_main(int argc, char *argv[])
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
	printf("Success=%d Failures=%d\n", success, fail);
	return 0;
}
