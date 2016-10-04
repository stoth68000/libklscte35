/* Copyright Kernel Labs Inc 2016. All Rights Reserved. */

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

static int parse(struct scte35_context_s *scte35, uint8_t *sec, int byteCount)
{
	printf("\nParsing a new SCTE35 section......\n");
	struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(sec, byteCount);
	if (s) {

		/* Dump struct to console */
		scet35_splice_info_section_print(s);

		/* Optionally, Convert the SCTE35 message into a SCTE104 command */
		uint8_t *buf;
		uint16_t byteCount;
		int ret = scte35_create_scte104_message(scte35, s, &buf, &byteCount);
		if (ret == 0) {
			printf("SCTE104 formatted message : ");
			hexdump(buf, byteCount, 32);

			/* Convert a SCTE104 message into a standard VANC line. */

			/* Take an array of payload, create a fully formed VANC message,
			 * including parity bits, header signatures, message type,
			 * trailing checksum.
			 * bitDepth of 10 is the only valid input value.
			 * did: 0x41 + sdid: 0x07 = SCTE104
			 */
			uint16_t *vancWords;
			uint16_t vancWordCount;
			ret = vanc_sdi_create_payload(0x07, 0x41, buf, byteCount, &vancWords, &vancWordCount, 10);
			if (ret == 0) {
				printf("SCTE104 in VANC: ");
				for (int i = 0; i < vancWordCount; i++)
					printf("%03x ", *(vancWords + i));
				printf("\n");

				free(vancWords); /* Free the allocated resource */
			} else
				fprintf(stderr, "Error creating VANC message, ret = %d\n", ret);

			free(buf); /* Free the allocated resource */
		} else {
			fprintf(stderr, "Unable to convert SCTE35 to SCTE104, ret = %d\n", ret);
		}

		/* Free the allocated resource */
		scte35_splice_info_section_free(s);
	}

	return 0;
}

int scte104_main(int argc, char *argv[])
{
	struct scte35_context_s s35, *scte35;
	scte35 = &s35;
        scte35_initialize(scte35, 0x0123);

	parse(scte35, &mouse_oon[0], sizeof(mouse_oon));
	parse(scte35, &mouse_btn[0], sizeof(mouse_btn));

	printf("program complete.\n");
	return 0;
}
