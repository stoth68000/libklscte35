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

/* Purpose: parse a SCTE35 message, convert to SCTE104 command, convert to VANC. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libklscte35/scte35.h>
#include <libklvanc/vanc.h>
#include "scte35_samples.h"

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

static int cb_SCTE_104(void *callback_context, struct klvanc_context_s *ctx,
		       struct klvanc_packet_scte_104_s *pkt)
{
	printf("%s:%s()\n", __FILE__, __func__);

	/* Have the library display some debug */
	printf("Asking libklvanc to dump a struct\n");
	klvanc_dump_SCTE_104(ctx, pkt);

	return 0;
}

static struct klvanc_callbacks_s callbacks =
{
	.scte_104		= cb_SCTE_104,
};

static int parse(const uint8_t *sec, int byteCount)
{
	printf("\nParsing a new SCTE35 section......\n");

	printf("Original section data:\n");
	for (int i = 0; i < byteCount; i++)
		printf("%02x ", sec[i]);
	printf("\n");

	struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(sec, byteCount);
	if (s) {
		struct klvanc_context_s *ctx;
		if (klvanc_context_create(&ctx) < 0) {
			fprintf(stderr, "Error initializing library context\n");
			exit(1);
		}
		ctx->verbose = 1;
		ctx->callbacks = &callbacks;

		/* Dump struct to console */
		scte35_splice_info_section_print(s);

		/* Optionally, Convert the SCTE35 message into a SCTE104 command */
		uint8_t *buf;
		uint16_t byteCount;
		int ret = scte35_create_scte104_message(s, &buf, &byteCount, 0);
		if (ret == 0) {
			printf("SCTE104 formatted message : ");
			hexdump(buf, byteCount, 32);

			uint8_t *smpte2010_bytes;
			uint16_t smpte2010_len;
			ret = klvanc_convert_SCTE_104_packetbytes_to_SMPTE_2010(ctx,
										buf,
										byteCount,
										&smpte2010_bytes,
										&smpte2010_len);
			if (ret != 0) {
				printf("Error creating SMPTE 2010 VANC payload, ret=%d\n",
				       ret);
				klvanc_context_destroy(ctx);
				return -1;
			}

			/* Convert a SCTE104 message into a standard VANC line. */

			/* Take an array of payload, create a fully formed VANC message,
			 * including parity bits, header signatures, message type,
			 * trailing checksum.
			 * bitDepth of 10 is the only valid input value.
			 * did: 0x41 + sdid: 0x07 = SCTE104
			 */
			uint16_t *vancWords;
			uint16_t vancWordCount;
			ret = klvanc_sdi_create_payload(0x07, 0x41, smpte2010_bytes, smpte2010_len,
							&vancWords, &vancWordCount, 10);
			if (ret == 0) {
				printf("SCTE104 in VANC: ");
				for (int i = 0; i < vancWordCount; i++)
					printf("%03x ", *(vancWords + i));
				printf("\n");

#ifdef DEBUG_RENDER_104
				/* Feed it back into the VANC parser so we can decode it */
				klvanc_packet_parse(ctx, 13, vancWords, vancWordCount);
#endif

				free(vancWords); /* Free the allocated resource */
			} else
				fprintf(stderr, "Error creating VANC message, ret = %d\n", ret);

			free(buf); /* Free the allocated resource */
			free(smpte2010_bytes);
		} else {
			fprintf(stderr, "Unable to convert SCTE35 to SCTE104, ret = %d\n", ret);
		}

		/* Free the allocated resource */
		scte35_splice_info_section_free(s);
		klvanc_context_destroy(ctx);
	}

	return 0;
}

int scte104_main(int argc, char *argv[])
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
