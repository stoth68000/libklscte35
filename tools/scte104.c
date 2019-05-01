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

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

/* Mouse:
   Out of network:
   <SCTE35 command="5" command_str="insert" pts_adjustment="67521" event_id="692" cancel="0"
      out_of_network="1" program_splice="1" splice_time="immediate" unique_program_id="1">
*/
static uint8_t mouse_oon[] = {
	0xfc, 0x30, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x07,
	0xc1, 0x00, 0xff, 0xf0, 0x0a, 0x05, 0x00, 0x00,
	0x02, 0xb4, 0x7f, 0xdf, 0x00, 0x01, 0x01, 0x01,
	0x00, 0x00, 0x7c, 0x18, 0x5d, 0x61
};

/*
   Mouse:
   Back to network:
   <SCTE35 command="5" command_str="insert" pts_adjustment="67521" event_id="693" cancel="0"
      out_of_network="0" program_splice="1" splice_time="2241430756" unique_program_id="1">
*/
static uint8_t mouse_btn[] = {
	0xfc, 0x30, 0x20, 0x00, 0x00, 0x00, 0x01, 0x07,
	0xc1, 0x00, 0xff, 0xf0, 0x0f, 0x05, 0x00, 0x00,
	0x02, 0xb5, 0x7f, 0x4f, 0xfe, 0x85, 0x99, 0x84,
	0xe4, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x3e,
	0x17, 0xd8, 0x2e 
};

static uint8_t comcast_gots_test1 [] = {
	0xfc, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0xff, 0xff, 0xf0, 0x05, 0x06, 0xfe, 0x86,
	0xdf, 0x75, 0x50, 0x00, 0x11, 0x02, 0x0f, 0x43,
	0x55, 0x45, 0x49, 0x41, 0x42, 0x43, 0x44, 0x7f,
	0x8f, 0x00, 0x00, 0x10, 0x01, 0x01, 0xce, 0x6d,
	0x6a, 0x49,
};

static uint8_t multi_descriptor_test1[] = {
	0xfc, 0x30, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0xf0, 0x0f, 0x05, 0x40, 0x00,
	0x00, 0x52, 0x7f, 0xff, 0x7e, 0x00, 0x36, 0xee,
	0x80, 0x00, 0x64, 0x03, 0x01, 0x00, 0x1a, 0x01,
	0x07, 0x43, 0x55, 0x45, 0x49, 0x00, 0x3f, 0x30,
	0x02, 0x0f, 0x43, 0x55, 0x45, 0x49, 0x00, 0x00,
	0x00, 0x00, 0x7f, 0xbf, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x5f, 0x33, 0xe8, 0xf6,
};

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

static int parse(uint8_t *sec, int byteCount)
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
	parse(&mouse_oon[0], sizeof(mouse_oon));
	parse(&mouse_btn[0], sizeof(mouse_btn));
	parse(&comcast_gots_test1[0], sizeof(comcast_gots_test1));
	parse(&multi_descriptor_test1[0], sizeof(multi_descriptor_test1));

	printf("program complete.\n");
	return 0;
}
