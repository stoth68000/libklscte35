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

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

int demo_main(int argc, char *argv[])
{
	/* Generate a OUT_OF_NETWORK IMMEDIATE section */
	printf("Generating out of network table section, event 1000, program 2000\n");
	uint8_t *section = 0;
	uint32_t sectionLengthBytes;
	scte35_generate_out_of_network(0x1000, 0x2000, &section, &sectionLengthBytes, 1, 0, 0);
	hexdump(section, sectionLengthBytes, 32);

	/* Generate a return IN_TO_NETWORK IMMEDIATE section */
	printf("Generating back to network table section, event 1001, program 2000\n");
	scte35_generate_immediate_in_to_network(0x1001, 0x2000, &section, &sectionLengthBytes, 0, 0);
	hexdump(section, sectionLengthBytes, 32);

	printf("program complete.\n");
	return 0;
}
