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

/* Mouse:
   Out of network:
   <SCTE35 command="5" command_str="insert" pts_adjustment="67521" event_id="692" cancel="0"
      out_of_network="1" program_splice="1" splice_time="immediate" unique_program_id="1">
*/
uint8_t mouse_oon[] = {
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
uint8_t mouse_btn[] = {
	0xfc, 0x30, 0x20, 0x00, 0x00, 0x00, 0x01, 0x07,
	0xc1, 0x00, 0xff, 0xf0, 0x0f, 0x05, 0x00, 0x00,
	0x02, 0xb5, 0x7f, 0x4f, 0xfe, 0x85, 0x99, 0x84,
	0xe4, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x3e,
	0x17, 0xd8, 0x2e 
};

static int parse(uint8_t *sec, int byteCount)
{
	printf("\nParsing a new section......\n");
	struct scte35_splice_info_section_s *s = scte35_splice_info_section_parse(sec, byteCount);
	if (s) {
		scet35_splice_info_section_print(s);
		scte35_splice_info_section_free(s);
	}

	return 0;
}

int parse_main(int argc, char *argv[])
{
	parse(&mouse_oon[0], sizeof(mouse_oon));
	parse(&mouse_btn[0], sizeof(mouse_btn));

	printf("program complete.\n");
	return 0;
}
