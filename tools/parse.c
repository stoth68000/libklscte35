#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libklscte35/scte35.h>

// push this into the klscte35
#include <bitstream/scte/35.h>

static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

/* Mouse:
   Out of network:
<SCTE35 command="5" command_str="insert" pts_adjustment="67521" event_id="692" cancel="0" out_of_network="1" program_splice="1" splice_time="immediate" unique_program_id="1">
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
   fc 30 20 00 00 00 01 07 c1 00 ff f0 0f 05 00 00 02 b5 7f 4f fe 85 99 84 e4 00 01 01 01 00 00 3e 17 d8 2e 
<SCTE35 command="5" command_str="insert" pts_adjustment="67521" event_id="693" cancel="0" out_of_network="0" program_splice="1" splice_time="2241430756" unique_program_id="1">
*/


static int test01(uint8_t *sec, int byteCount)
{
	uint8_t cmdtype = scte35_get_command_type(sec);
	printf("cmttype = %02x\n", cmdtype);

	uint8_t protocol = scte35_get_protocol(sec);
	printf("protocol = %02x\n", protocol);

	return 0;
}

int parse_main(int argc, char *argv[])
{
	test01(&mouse_oon[0], sizeof(mouse_oon));

	printf("program complete.\n");
	return 0;
}
