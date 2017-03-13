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
#include <libklvanc/vanc.h>

#if 1
static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}
#endif


unsigned char __0_vancentry[] = {
	0x00, 0x00, 0x03, 0xff, 0x03, 0xff, 0x02, 0x41, 0x01, 0x07, 0x01, 0x52,
	0x01, 0x08, 0x02, 0xff, 0x02, 0xff, 0x02, 0x00, 0x01, 0x51, 0x02, 0x00,
	0x02, 0x00, 0x01, 0x52, 0x02, 0x00, 0x02, 0x05, 0x02, 0x00, 0x02, 0x00,
	0x02, 0x06, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x01, 0x0e, 0x01, 0x02,
	0x01, 0x40, 0x02, 0x00, 0x02, 0x00, 0x01, 0x52, 0x02, 0x00, 0x01, 0x64,
	0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x90, 0x02, 0x03, 0x01, 0x01,
	0x02, 0x00, 0x01, 0x01, 0x01, 0x04, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00,
	0x02, 0x00, 0x01, 0x01, 0x02, 0x09, 0x02, 0x00, 0x02, 0x03, 0x02, 0x00,
	0x01, 0x01, 0x02, 0x30, 0x01, 0x01, 0x01, 0x0b, 0x02, 0x00, 0x02, 0x12,
	0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
	0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x40, 0x02, 0x00, 0x02, 0x00,
	0x02, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0x02, 0x03,
	0x01, 0x01, 0x01, 0x02, 0x02, 0x00, 0x02, 0x00, 0x01, 0x01, 0x01, 0x08,
	0x02, 0x00, 0x01, 0x08, 0x01, 0x01, 0x01, 0x0b, 0x02, 0x05, 0x01, 0x54,
	0x02, 0x56, 0x02, 0x4e, 0x01, 0x54, 0x02, 0x00, 0x02, 0x06
};

static int cb_SCTE_104(void *callback_context, struct vanc_context_s *ctx, struct packet_scte_104_s *pkt)
{
	struct splice_entries results;
	int ret;

	printf("%s:%s()\n", __FILE__, __func__);

	/* Have the library display some debug */
	printf("Asking libklvanc to dump a struct\n");
	dump_SCTE_104(ctx, pkt);

	/* Let's encode it to SCTE-35 */
	ret = scte35_generate_from_scte104(pkt, &results);
	if (ret != 0) {
		fprintf(stderr, "Generation of SCTE-35 sections failed\n");
	}

	printf("Results: %d SCTE-35 sections\n", results.num_splices);
	for (int i = 0; i < results.num_splices; i++) {
		struct scte35_splice_info_section_s *s;
		printf("SCTE-35 section #%d\n", i);
		hexdump(results.splice_entry[i], results.splice_size[i], 16);
		s = scte35_splice_info_section_parse(results.splice_entry[i],
						     results.splice_size[i]);
		if (s == NULL) {
			fprintf(stderr, "Failed to parse SCTE-35 splice\n");
		} else {
			scte35_splice_info_section_print(s);
			scte35_splice_info_section_free(s);
		}
		free(results.splice_entry[i]);
	}
	return 0;
}

static struct vanc_callbacks_s callbacks = 
{
	.scte_104		= cb_SCTE_104,
};

static int parse(struct vanc_context_s *ctx, uint8_t *sec, int byteCount)
{
	printf("\nParsing a new SCTE104 VANC packet......\n");
	uint16_t *arr = malloc(byteCount / 2 * sizeof(uint16_t));
	if (arr == NULL)
		return -1;

	for (int i = 0; i < (byteCount / 2); i++) {
		arr[i] = sec[i * 2] << 8 | sec[i * 2 + 1];
	}

	int ret = vanc_packet_parse(ctx, 13, arr, byteCount / sizeof(unsigned short));
	free(arr);

	return ret;
}

int scte104to35_main(int argc, char *argv[])
{
	struct vanc_context_s *ctx;

	if (vanc_context_create(&ctx) < 0) {
		fprintf(stderr, "Error initializing library context\n");
		exit(1);
	}
	ctx->verbose = 1;
	ctx->callbacks = &callbacks;

	parse(ctx, &__0_vancentry[0], sizeof(__0_vancentry));

	vanc_context_destroy(ctx);
	printf("program complete.\n");
	return 0;
}
