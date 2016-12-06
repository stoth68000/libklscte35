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

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

#include <bitstream/mpeg/ts.h>
#include <bitstream/mpeg/psi.h>
#include <bitstream/dvb/si.h>
#include <bitstream/dvb/si_print.h>
#include <bitstream/scte/35.h>
#include <bitstream/scte/35_print.h>

#include <libklscte35/scte35.h>
#include <libiso13818/iso13818.h>
#include "klbitstream_readwriter.h"

#define dprintf(level, fmt, arg...) \
do {\
  if (ctx->verbose >= level) printf(fmt, ## arg); \
} while(0);
 
static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}

static void print_wrapper(void *_unused, const char *fmt, ...)
{
	char v[strlen(fmt) + 2];
	va_list args;
	va_start(args, fmt);
	strcpy(v, fmt);
	strcat(v, "\n");
	vprintf(v, args);
	va_end(args);
}

/* Return the number of TS packets we've generated */
static int output_psi_section(struct scte35_context_s *ctx, uint8_t *section, uint16_t pid, uint8_t *cc)
{
	uint16_t section_length = psi_get_length(section) + PSI_HEADER_SIZE;
	uint16_t section_offset = 0;
	int count = 0;

	memcpy(&ctx->section[0], section, section_length);
	ctx->section_length = section_length;

	do {
		uint8_t ts_offset = 0;
		memset(ctx->pkt, 0xff, TS_SIZE);

		psi_split_section(ctx->pkt, &ts_offset, section, &section_offset);

		ts_set_pid(ctx->pkt, pid);
		ts_set_cc(ctx->pkt, *cc);
		(*cc)++;
		*cc &= 0xf;

		if (section_offset == section_length)
			psi_split_end(ctx->pkt, &ts_offset);

		count++;
		if (ctx->verbose >= 2) {
			hexdump(ctx->pkt, TS_SIZE, 16);
			scte35_print(section, print_wrapper, NULL, PRINT_XML);
 		}

	} while (section_offset < section_length);
	return count;
}

int scte35_generate_heartbeat(struct scte35_context_s *ctx)
{
	uint8_t *scte35 = psi_allocate();

/*
47 41 23 10 00
fc          table id
30 11       SSI / Sec Length
00          protocol version
00          encrypted packet / enc algo / pts 32:32
00 00 00 00 pts 31:0
00          cw_index
ff f        tier
 0 00       splice command length
00          splice command type (0 = NULL)
00 00       descriptor look length
7a 4f bf ff crc32
ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff 
*/
	/* Generate empty section */
	scte35_init(scte35);
	psi_set_length(scte35, PSI_MAX_SIZE);
	scte35_set_pts_adjustment(scte35, 0);
	scte35_null_init(scte35);
	scte35_set_desclength(scte35, 0);
	psi_set_length(scte35, scte35_get_descl(scte35) + PSI_CRC_SIZE - scte35 - PSI_HEADER_SIZE);
	psi_set_crc(scte35);
	int count = output_psi_section(ctx, scte35, ctx->outputPid, &ctx->cc);

	free(scte35);
	return count;
}

#if 0
static void scte35_generate_pointinout(struct scte35_context_s *ctx, int out_of_network_indicator)
{
	uint8_t *scte35 = psi_allocate();

/*
47 41 23 11 00
fc          table id
30 25       SSI / Section length
00          protocol version
00          encrypted packet / enc algo / pts 32:32
00 00 00 00 pts 31:0
00          cw_index
ff f        tier
 0 14       splice command length
05          splice command type (5 = splice insert)
            00 00 10 92   event id
            7f            splice event cancel indicator
            ef            out of network indicator / program splice / duration flag
            fe
10 17 df 80 fe
            01 9b fc c0
            09 78
            00            aval_num
            00            avails_expected
00 00       descriptor loop length
e9 7f f3 c0 crc32
ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff 
*/

	/* Generate insert section */
	scte35_init(scte35);
	psi_set_length(scte35, PSI_MAX_SIZE);
	scte35_set_pts_adjustment(scte35, 0);
	scte35_insert_init(scte35,
			   SCTE35_INSERT_HEADER2_SIZE +
			   SCTE35_SPLICE_TIME_HEADER_SIZE +
			   SCTE35_SPLICE_TIME_TIME_SIZE +
			   SCTE35_BREAK_DURATION_HEADER_SIZE +
			   SCTE35_INSERT_FOOTER_SIZE);
	scte35_insert_set_cancel(scte35, false);
	scte35_insert_set_event_id(scte35, 4242);
	scte35_insert_set_out_of_network(scte35, true);
	scte35_insert_set_program_splice(scte35, true);
	scte35_insert_set_duration(scte35, true);
	scte35_insert_set_splice_immediate(scte35, false);

	uint8_t *splice_time = scte35_insert_get_splice_time(scte35);
	scte35_splice_time_init(splice_time);
	scte35_splice_time_set_time_specified(splice_time, true);
	scte35_splice_time_set_pts_time(splice_time, 270000000);

	uint8_t *duration = scte35_insert_get_break_duration(scte35);
	scte35_break_duration_init(duration);
	scte35_break_duration_set_auto_return(duration, true);
	scte35_break_duration_set_duration(duration, 27000000);

	scte35_insert_set_unique_program_id(scte35, 2424);
	scte35_insert_set_avail_num(scte35, 0);
	scte35_insert_set_avails_expected(scte35, 0);
	scte35_set_desclength(scte35, 0);
	psi_set_length(scte35, scte35_get_descl(scte35) + PSI_CRC_SIZE - scte35 - PSI_HEADER_SIZE);
	psi_set_crc(scte35);
	output_psi_section(scte35, ctx->outputPid, &ctx->cc);

	free(scte35);
}
#else
static int scte35_generate_pointinout(struct scte35_context_s *ctx, int out_of_network_indicator)
{
	uint8_t *scte35 = psi_allocate();

/*
47 41 23 10 00   out of network
fc
30 25
00            protocol version
00 00 00 00 00
00            cw_index
ff f          tier
 0 14         slice command length
05            slice command type 5 (insert)
00 00 00 01   eventid
7f            cancel prior = false
df            out of network | program splice | splice_immediate
00 01         uniq program id 
00            avail_num
00            avails_expected
00 00         desc loop length
00
00 00 00 00 00 00 00 00 00
6b 97 98 28   crc32
ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff 

47 41 23 11 00   back into network
fc
30 25
00
00 00 00 00
00 00       cw_index
ff f
 0 14
05
00 00 00 02 event id
7f          cancel prior = false
5f 00 01 00 00 00 00 00
00 00 00 00 00 00 00 00 00 b7 68 65 22 ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff 
*/

/*
47 41 23 11 00
fc          table id
30 25       SSI / Section length
00          protocol version
00          encrypted packet / enc algo / pts 32:32
00 00 00 00 pts 31:0
00          cw_index
ff f        tier
 0 14       splice command length
05          splice command type (5 = splice insert)
            00 00 10 92   event id
            7f            splice event cancel indicator
            ef            out of network indicator / program splice / duration flag
            fe
10 17 df 80 fe
            01 9b fc c0
            09 78
            00            aval_num
            00            avails_expected
00 00       descriptor loop length
e9 7f f3 c0 crc32
ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff 
*/

	/* Generate insert section */
	scte35_init(scte35);
	psi_set_length(scte35, PSI_MAX_SIZE);
	scte35_set_pts_adjustment(scte35, 0);
	scte35_insert_init(scte35, SCTE35_INSERT_HEADER2_SIZE + SCTE35_INSERT_FOOTER_SIZE);
	scte35_insert_set_cancel(scte35, false);
	scte35_insert_set_event_id(scte35, ctx->eventId++);
	scte35_insert_set_out_of_network(scte35, out_of_network_indicator);

	/* Slice the entire program, audio, video, everything */
	scte35_insert_set_program_splice(scte35, true);
	scte35_insert_set_duration(scte35, false);
	scte35_insert_set_splice_immediate(scte35, true);

	/* See SCTE 118-2 - for Unique Program Number */
	scte35_insert_set_unique_program_id(scte35, ctx->uniqueProgramId);
	scte35_insert_set_avail_num(scte35, 0);
	scte35_insert_set_avails_expected(scte35, 0);
	scte35_set_desclength(scte35, 0);
	psi_set_length(scte35, scte35_get_descl(scte35) + PSI_CRC_SIZE - scte35 - PSI_HEADER_SIZE);
	psi_set_crc(scte35);
	int count = output_psi_section(ctx, scte35, ctx->outputPid, &ctx->cc);

	free(scte35);
	return count;
}
#endif

void scte35_initialize(struct scte35_context_s *ctx, uint16_t outputPid)
{
	dprintf(1, "%s()\n", __func__);
/* TODO: What is this and why do we need it? */
static int count = 0;
	if (count++ > 0)
		return;

	memset(ctx, 0, sizeof(*ctx));
	ctx->verbose = 2;
	ctx->outputPid = outputPid;
	ctx->eventId = 1;
	ctx->uniqueProgramId = 1;
}

	/* Go into Ad, switch away from the network */
int scte35_generate_immediate_out_of_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId)
{
	dprintf(1, "%s()\n", __func__);
	ctx->uniqueProgramId = uniqueProgramId;
	return scte35_generate_pointinout(ctx, 1);
}

int scte35_generate_immediate_in_to_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId)
{
	dprintf(1, "%s()\n", __func__);
	/* Go to network, switch away from the ad slicer */
	ctx->uniqueProgramId = uniqueProgramId;
	return scte35_generate_pointinout(ctx, 0);
}

int scte35_set_next_event_id(struct scte35_context_s *ctx, uint32_t eventId)
{
	dprintf(1, "%s(%d)\n", __func__, eventId);
	ctx->eventId = eventId;
	return 0;
}

static uint8_t *parse_time(struct scte35_splice_time_s *st, uint8_t *p)
{
	st->time_specified_flag = *(p + 0) & 0x80 ? 1 : 0;
	if (st->time_specified_flag == 1) {
		st->pts_time = ((uint64_t)*(p + 0) << 32 |
			(uint64_t)*(p + 1) << 24 |
			(uint64_t)*(p + 2) << 16 |
			(uint64_t)*(p + 3) << 8 |
			(uint64_t)*(p + 4)) & 0x1ffffffffL;
		return p + 5;
	} else
		return p + 1;
}

static uint8_t *parse_component(struct scte35_splice_insert_s *si, struct scte35_splice_component_s *c, uint8_t *p)
{
	c->component_tag = *p; p++;
	if (si->splice_immediate_flag == 0)
		p = parse_time(&c->splice_time, p);

	return p;
}

#define SHOW_LINE_U32(indent, field) printf("%s%s = 0x%x (%d)\n", indent, #field, field, field);
#define SHOW_LINE_U64(indent, field) printf("%s%s = %" PRIu64 "\n", indent, #field, field);
void scet35_splice_info_section_print(struct scte35_splice_info_section_s *s)
{
	SHOW_LINE_U32("", s->table_id);
	SHOW_LINE_U32("", s->section_syntax_indicator);
	SHOW_LINE_U32("", s->private_indicator);
	SHOW_LINE_U32("", s->section_length);
	SHOW_LINE_U32("", s->protocol_version);
	SHOW_LINE_U32("", s->encrypted_packet);
	SHOW_LINE_U32("", s->encryption_algorithm);
	SHOW_LINE_U64("", s->pts_adjustment);
	SHOW_LINE_U32("", s->cw_index);
	SHOW_LINE_U32("", s->tier);
	SHOW_LINE_U32("", s->splice_command_length);
	SHOW_LINE_U32("", s->splice_command_type);

	if (s->splice_command_type == 0x05 /* Insert */) {
		SHOW_LINE_U32("\t", s->splice_insert.splice_event_id);
		SHOW_LINE_U32("\t", s->splice_insert.splice_event_cancel_indicator);
		SHOW_LINE_U32("\t", s->splice_insert.out_of_network_indicator);
		SHOW_LINE_U32("\t", s->splice_insert.program_splice_flag);
		SHOW_LINE_U32("\t", s->splice_insert.duration_flag);
		SHOW_LINE_U32("\t", s->splice_insert.splice_immediate_flag);
		SHOW_LINE_U32("\t", s->splice_insert.splice_time.time_specified_flag);
		SHOW_LINE_U64("\t", s->splice_insert.splice_time.pts_time);
		SHOW_LINE_U32("\t", s->splice_insert.component_count);

		if (s->splice_insert.duration_flag) {
			SHOW_LINE_U32("\t\t", s->splice_insert.duration.auto_return);
			SHOW_LINE_U64("\t\t", s->splice_insert.duration.duration);
		}

		SHOW_LINE_U32("\t", s->splice_insert.unique_program_id);
		SHOW_LINE_U32("\t", s->splice_insert.avail_num);
		SHOW_LINE_U32("\t", s->splice_insert.avails_expected);

	}

        /* We don't support descriptor parsing. */
	SHOW_LINE_U32("", s->descriptor_loop_length);

	SHOW_LINE_U32("", s->e_crc_32);
	SHOW_LINE_U32("", s->crc_32);
}

struct scte35_splice_info_section_s *scte35_splice_info_section_parse(uint8_t *section, unsigned int byteCount)
{
	if (*(section + 0) != SCTE35_TABLE_ID)
		return 0;

	struct scte35_splice_info_section_s *s = calloc(1, sizeof(*s));

	uint8_t *p = section;
	s->table_id = *(section + 0);
	s->section_syntax_indicator = *(section + 1) & 0x80 ? 1 : 0;
	s->private_indicator = *(section + 1) & 0x40 ? 1 : 0;
        s->section_length = (*(section + 1) << 8 | *(section + 2)) & 0xfff;
	s->protocol_version = scte35_get_protocol(section);
	s->encrypted_packet = scte35_is_encrypted(section);
	s->encryption_algorithm = (*(section + 4) >> 1) & 0x3f;
	s->pts_adjustment = scte35_get_pts_adjustment(section);
	s->cw_index = *(section + 8);
        s->tier = (*(section + 9) << 8 | *(section + 10)) & 0xfff;
	s->splice_command_length = scte35_get_command_length(section);
	s->splice_command_type = scte35_get_command_type(section);

	if (s->splice_command_type == 0x00 /* null processing */) {
	} else
	if (s->splice_command_type == 0x05 /* insert processing */) {
		struct scte35_splice_insert_s *si = &s->splice_insert;
		si->splice_event_id = *(section + 14) << 24 | *(section + 15) << 16 | *(section + 16) << 8 | *(section + 17);
		si->splice_event_cancel_indicator = *(section + 18) & 0x80 ? 1 : 0;
		if (si->splice_event_cancel_indicator == 0) {
			si->out_of_network_indicator = *(section + 19) & 0x80 ? 1 : 0;
			si->program_splice_flag = *(section + 19) & 0x40 ? 1 : 0;
			si->duration_flag = *(section + 19) & 0x20 ? 1 : 0;
			si->splice_immediate_flag = *(section + 19) & 0x10 ? 1 : 0;

			p = section + 20;
			if ((si->program_splice_flag == 1) && (si->splice_immediate_flag == 0)) {
				struct scte35_splice_time_s *st = &si->splice_time;
				p = parse_time(st, p);
			}

			if (si->program_splice_flag == 0) {
				/* We don't support Component counts */
				si->component_count = *p;
				p++;
				for (int i = 0; i < si->component_count; i++)
					p = parse_component(si, &si->components[i], p);
				
			}

			if (si->duration_flag == 1) {
				struct scte35_break_duration_s *d = &si->duration;
				d->auto_return = *(p + 0) & 0x80 ? 1 : 0;
				d->duration = ((uint64_t)*(p + 0) << 32 |
					(uint64_t)*(p + 1) << 24 |
					(uint64_t)*(p + 2) << 16 |
					(uint64_t)*(p + 3) << 8 |
					(uint64_t)*(p + 4)) & 0x1ffffffffL;

				p += 5;
			}

			si->unique_program_id = *(p + 0) << 8 | *(p + 1); p+= 2;
			si->avail_num = *p; p++;
			si->avails_expected = *p; p++;
			
		} /* si->splice_event_cancel_indicator == 0 */

	} /* s->splice_command_type == 0x05 */
	else {
		/* No support for schedule, time_signal or bandwidth reservervation, or
		 * private commands.
		 */
		scte35_splice_info_section_free(s);
		return 0;
	}

	s->descriptor_loop_length = *(p + 0) << 8 | *(p + 1); p+= 2;

	/* TODO: We don't support descriptor parsing, yet. */
	for (int i = 0; i < s->descriptor_loop_length; i++) {
		uint8_t tag = *p; p++;
		uint8_t len = *p; p++;
		p += len;
	}

	/* TODO: Alignment stuff, we've never seen a frame with alignment stuffing */

	if (s->encrypted_packet) {
		s->e_crc_32 = 0;
	}

	s->crc_32 = 0;

	return s;
}

void scte35_splice_info_section_free(struct scte35_splice_info_section_s *s)
{
	free(s);
}

static int scte104_generate_immediate_out_of_network(const struct scte35_splice_insert_s *si,
	uint8_t **buf, uint16_t *byteCount)
{
	uint8_t *b = calloc(1, 32);
	uint8_t *p = b;

	/* single_message_operation() */
	*(p++) = 0x08;			/* Version */

	*(p++) = 0x00;			/* opID - init_request_data() */
	*(p++) = 0x01;			/* ... */

	*(p++) = 0x00;			/* messageSize (entire size excluding Version) */
	*(p++) = 0x1b;			/* ... */

	*(p++) = 0xff;			/* result */
	*(p++) = 0xff;			/* ... */

	*(p++) = 0xff;			/* result_expansion */
	*(p++) = 0xff;			/* ... */

	*(p++) = 0x00;			/* protocol_version */
	*(p++) = 0x00;			/* AS_index */
	*(p++) = 0x00;			/* message_number */

	*(p++) = 0x00;			/* DPI_PID_index */
	*(p++) = 0x00;			/* ... */

	/* splice_request_data() */
	*(p++) = 0x02;			/* spliceStart_immediate */

	/* splice_event_index */
	*(p++) = si->splice_event_id >> 24;
	*(p++) = si->splice_event_id >> 16;
	*(p++) = si->splice_event_id >>  4;
	*(p++) = si->splice_event_id;

	/* unique_program_id */
	*(p++) = si->unique_program_id >> 8;
	*(p++) = si->unique_program_id;

	*(p++) = 0x00;			/* pre_roll_time */
	*(p++) = 0x00;			/* ... */

	*(p++) = 0x01;			/* break_duration in 1/10 secs (30) */
	*(p++) = 0x2c;			/* ... */

	*(p++) = si->avail_num;		/* avail_num */
	*(p++) = si->avails_expected;	/* avails_expected */
	*(p++) = 0x01;			/* auto_return_flag */

	*buf = b;
	*byteCount = (p - b);
	return 0;
}

static int scte104_generate_immediate_in_to_network(const struct scte35_splice_insert_s *si,
	uint8_t **buf, uint16_t *byteCount)
{
	uint8_t *b = calloc(1, 32);
	uint8_t *p = b;

	/* single_message_operation() */
	*(p++) = 0x08;			/* Version */

	*(p++) = 0x00;			/* opID - init_request_data() */
	*(p++) = 0x01;			/* ... */

	*(p++) = 0x00;			/* messageSize (entire size excluding Version) */
	*(p++) = 0x1b;			/* ... */

	*(p++) = 0xff;			/* result */
	*(p++) = 0xff;			/* ... */

	*(p++) = 0xff;			/* result_expansion */
	*(p++) = 0xff;			/* ... */

	*(p++) = 0x00;			/* protocol_version */
	*(p++) = 0x00;			/* AS_index */
	*(p++) = 0x00;			/* message_number */

	*(p++) = 0x00;			/* DPI_PID_index */
	*(p++) = 0x00;			/* ... */

	/* splice_request_data() */
	*(p++) = 0x04;			/* spliceEnd_immediate */

	/* splice_event_index */
	*(p++) = si->splice_event_id >> 24;
	*(p++) = si->splice_event_id >> 16;
	*(p++) = si->splice_event_id >>  4;
	*(p++) = si->splice_event_id;

	/* unique_program_id */
	*(p++) = si->unique_program_id >> 8;
	*(p++) = si->unique_program_id;

	*(p++) = 0x00;			/* pre_roll_time */
	*(p++) = 0x00;			/* ... */

	*(p++) = 0x00;			/* break_duration in 1/10 secs (30) */
	*(p++) = 0x00;			/* ... */

	*(p++) = si->avail_num;		/* avail_num */
	*(p++) = si->avails_expected;	/* avails_expected */
	*(p++) = 0x01;			/* auto_return_flag */

	*buf = b;
	*byteCount = (p - b);
	return 0;
}

int scte35_create_scte104_message(struct scte35_context_s *ctx,
	struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount)
{
	int ret = -1;

	/* We support some very specific SCTE104 message types. Immediate INTO/OUT-OF messages.
	 * Only 'insert' messages, no other message support. Return an error if we're not sure
	 * what kind of message is being requested.
	 */
	if (s->splice_command_type != 0x05 /* Insert */)
		return -1;

	struct scte35_splice_insert_s *si = &s->splice_insert;

	if (si->splice_event_cancel_indicator) {
		/* TODO: Create a SCTE104 cancel event */
		return -1;
	}

	if (si->splice_event_cancel_indicator == 0) {
		if (si->splice_immediate_flag == 0) {
			fprintf(stderr, "%s() we won't support events that are not immediate\n", __func__);
			return -1;
		}
		if (si->out_of_network_indicator == 1)
			ret = scte104_generate_immediate_out_of_network(si, buf, byteCount);
		else
			ret = scte104_generate_immediate_in_to_network(si, buf, byteCount);
	}

	return ret;
}

struct scte35_splice_info_section_s *scte35_splice_info_section_alloc(uint8_t command_type)
{
	switch (command_type) {
	case SCTE35_COMMAND_TYPE__SPLICE_NULL:
	case SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE:
	case SCTE35_COMMAND_TYPE__SPLICE_INSERT:
	case SCTE35_COMMAND_TYPE__TIME_SIGNAL:
	case SCTE35_COMMAND_TYPE__BW_RESERVATION:
	case SCTE35_COMMAND_TYPE__PRIVATE:
		break;
	default:
		return 0;
	}

	struct scte35_splice_info_section_s *si = calloc(1, sizeof(*si));
	if (!si)
		return 0;

	si->table_id = 0xFC;
	si->splice_command_type = command_type;

	return si;
}

int scte35_splice_info_section_packTo(struct scte35_context_s *ctx,
	struct scte35_splice_info_section_s *si, uint8_t *buffer, uint32_t buffer_length_bytes)
{
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buffer, buffer_length_bytes);

	klbs_write_bits(bs, si->table_id, 8);
	klbs_write_bits(bs, si->section_syntax_indicator, 1);
	klbs_write_bits(bs, si->private_indicator, 1);
	klbs_write_bits(bs, 0xff, 2); /* Reserved */
	klbs_write_bits(bs, 0, 12); /* Section length, to be filled later */

	klbs_write_bits(bs, si->protocol_version, 8);
	klbs_write_bits(bs, si->encrypted_packet, 1);
	klbs_write_bits(bs, si->encryption_algorithm, 6);
	klbs_write_bits(bs, si->pts_adjustment, 33);
	klbs_write_bits(bs, si->cw_index, 8);
	klbs_write_bits(bs, si->tier, 12);

	klbs_write_bits(bs, si->splice_command_length, 12); /* to be filled later */
	klbs_write_bits(bs, si->splice_command_type, 8);

	int posa = klbs_get_byte_count(bs);
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_NULL) {
		/* Nothing to do */
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE) {
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__TIME_SIGNAL) {
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__BW_RESERVATION) {
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__PRIVATE) {
	}
	int posb = klbs_get_byte_count(bs);
	si->splice_command_length = posb - posa;

	/* Patch in the command length */
	bs->buf[11] |= ((si->splice_command_length >> 8) & 0x0f);
	bs->buf[12]  =  (si->splice_command_length       & 0xff);

	/* Checksum */
	unsigned int crc32 = 0;
	iso13818_getCRC32(klbs_get_buffer(bs), klbs_get_byte_count(bs), &crc32);
	klbs_write_bits(bs, crc32, 32);
	klbs_write_buffer_complete(bs);

	int count = klbs_get_byte_count(bs);
	klbs_free(bs);
	return count;
}
