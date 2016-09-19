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
	struct scte35_context_s s35, *scte35;
	scte35 = &s35;

	scte35_initialize(scte35, 0x0123);

	/* Generate a OUT_OF_NETWORK IMMEDIATE section */
	printf("Generating out of network table section\n");
	scte35_set_next_event_id(scte35, 1);
	scte35_generate_immediate_out_of_network(scte35, 0x1000);
	hexdump(scte35->section, scte35->section_length, 32);

	/* Generate a return IN_TO_NETWORK IMMEDIATE section */
	printf("Generating back to network table section\n");
	scte35_set_next_event_id(scte35, 1);
	scte35_generate_immediate_in_to_network(scte35, 0x1000);
	hexdump(scte35->section, scte35->section_length, 32);

	printf("program complete.\n");
	return 0;
}
