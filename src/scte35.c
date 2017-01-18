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

#include <libklscte35/scte35.h>
#include "klbitstream_readwriter.h"
#include "crc32.h"

#define dprintf(level, fmt, arg...) \
do {\
  if (ctx->verbose >= level) printf(fmt, ## arg); \
} while(0);

#if 0 
static void hexdump(unsigned char *buf, unsigned int len, int bytesPerRow /* Typically 16 */)
{
	for (unsigned int i = 0; i < len; i++)
		printf("%02x%s", buf[i], ((i + 1) % bytesPerRow) ? " " : "\n");
	printf("\n");
}
#endif

const char *scte35_description_command_type(uint32_t command_type)
{
	switch(command_type) {
	case SCTE35_COMMAND_TYPE__SPLICE_NULL: return "SPLICE_NULL";
	case SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE: return "SPLICE_SCHEDULE"; 
	case SCTE35_COMMAND_TYPE__SPLICE_INSERT: return "SPLICE_INSERT"; 
	case SCTE35_COMMAND_TYPE__TIME_SIGNAL: return "TIME_SIGNAL"; 
	case SCTE35_COMMAND_TYPE__BW_RESERVATION: return "BW_RESERVATION"; 
	case SCTE35_COMMAND_TYPE__PRIVATE: return "PRIVATE_COMMAND"; 
	default: return "Reserved";
	}
}

int scte35_generate_immediate_out_of_network_duration(uint16_t uniqueProgramId, uint32_t eventId, uint32_t duration, int autoReturn,
	uint8_t **dst, uint32_t *dstLengthBytes)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 1;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 1;
	si->splice_insert.duration.auto_return = autoReturn;
	si->splice_insert.duration.duration = duration;
	si->splice_insert.splice_immediate_flag = 1;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = 0; /* Not supported */
	si->splice_insert.avails_expected = 0; /* Not supported */

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf)
		return -1;

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -1;
	}

	*dst = buf;
	*dstLengthBytes = packedLength;
	scte35_splice_info_section_free(si);

	return 0;
}

/* Go into Ad, switch away from the network */
int scte35_generate_immediate_out_of_network(uint16_t uniqueProgramId, uint32_t eventId,
	uint8_t **dst, uint32_t *dstLengthBytes)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 1;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 0;
	si->splice_insert.splice_immediate_flag = 1;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = 0; /* Not supported */
	si->splice_insert.avails_expected = 0; /* Not supported */

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf)
		return -1;

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -1;
	}

	*dst = buf;
	*dstLengthBytes = packedLength;
	scte35_splice_info_section_free(si);

	return 0;
}

int scte35_generate_immediate_in_to_network(uint16_t uniqueProgramId, uint32_t eventId,
	uint8_t **dst, uint32_t *dstLengthBytes)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 0;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 0;
	si->splice_insert.splice_immediate_flag = 1;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = 0; /* Not supported */
	si->splice_insert.avails_expected = 0; /* Not supported */

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf)
		return -1;

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -1;
	}

	*dst = buf;
	*dstLengthBytes = packedLength;
	scte35_splice_info_section_free(si);

	return 0;
}

#define SHOW_LINE_U32(indent, field) printf("%s%s = 0x%x (%d)\n", indent, #field, field, field);
#define SHOW_LINE_U32_SUFFIX(indent, field, suffix) printf("%s%s = 0x%x (%d) [%s]\n", indent, #field, field, field, suffix);
#define SHOW_LINE_U64(indent, field) printf("%s%s = %" PRIu64 "\n", indent, #field, field);
void scte35_splice_info_section_print(struct scte35_splice_info_section_s *s)
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
	SHOW_LINE_U32_SUFFIX("", s->splice_command_type, scte35_description_command_type(s->splice_command_type));

	if (s->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {
		SHOW_LINE_U32("\t", s->splice_insert.splice_event_id);
		SHOW_LINE_U32("\t", s->splice_insert.splice_event_cancel_indicator);
		if (s->splice_insert.splice_event_cancel_indicator == 0) {
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

	} else
	if (s->splice_command_type == SCTE35_COMMAND_TYPE__TIME_SIGNAL) {
		SHOW_LINE_U32("", s->time_signal.time_specified_flag);
		if (s->time_signal.time_specified_flag == 1)
			SHOW_LINE_U64("", s->time_signal.pts_time);
	} else {
		fprintf(stderr, "No dump support for command type 0x%02x, asserting\n", s->splice_command_type);
		assert(0);
	}

        /* We don't support descriptor parsing. */
	SHOW_LINE_U32("", s->descriptor_loop_length);

	SHOW_LINE_U32("", s->e_crc_32);
	SHOW_LINE_U32("", s->crc_32);
	SHOW_LINE_U32("", s->crc_32_is_valid);
}

ssize_t scte35_splice_info_section_unpackFrom(struct scte35_splice_info_section_s *si, uint8_t *src, uint32_t srcLengthBytes)
{
	if ((!si) || (!src) || (srcLengthBytes == 0))
		return -1;

	struct klbs_context_s *bs = klbs_alloc();
	klbs_read_set_buffer(bs, src, srcLengthBytes);

	si->table_id = klbs_read_bits(bs, 8);
	assert(si->table_id == SCTE35_TABLE_ID);

	si->section_syntax_indicator = klbs_read_bits(bs, 1);
	assert(si->section_syntax_indicator == 0);

	si->private_indicator = klbs_read_bits(bs, 1);
	assert(si->private_indicator == 0);

	uint32_t v = klbs_read_bits(bs, 2); /* Reserved */
	assert(v == 0x03);

	//
	si->section_length = klbs_read_bits(bs, 12);

	si->protocol_version = klbs_read_bits(bs, 8);
	si->encrypted_packet = klbs_read_bits(bs, 1);
	si->encryption_algorithm = klbs_read_bits(bs, 6);
	si->pts_adjustment = klbs_read_bits(bs, 33);

	si->cw_index = klbs_read_bits(bs, 8);
	si->tier = klbs_read_bits(bs, 12);

	si->splice_command_length = klbs_read_bits(bs, 12);
	si->splice_command_type = klbs_read_bits(bs, 8);

	int posa = klbs_get_byte_count(bs);
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_NULL) {
		/* Nothing to do */
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE) {
		assert(0);
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {

		struct scte35_splice_insert_s *i = &si->splice_insert;

		i->splice_event_id = klbs_read_bits(bs, 32);
		i->splice_event_cancel_indicator = klbs_read_bits(bs, 1);
		klbs_read_bits(bs, 7); /* Reserved */

		if (i->splice_event_cancel_indicator == 0) {

			i->out_of_network_indicator = klbs_read_bits(bs, 1);
			i->program_splice_flag = klbs_read_bits(bs, 1);
			i->duration_flag = klbs_read_bits(bs, 1);
			i->splice_immediate_flag = klbs_read_bits(bs, 1);
			klbs_read_bits(bs, 4); /* Reserved */

			if ((i->program_splice_flag == 1) && (i->splice_immediate_flag == 0)) {
				i->splice_time.time_specified_flag = klbs_read_bits(bs, 1);
				if (i->splice_time.time_specified_flag == 1) {
					klbs_read_bits(bs, 6); /* Reserved */
					i->splice_time.pts_time = klbs_read_bits(bs, 33);
				} else
					klbs_read_bits(bs, 7); /* Reserved */
			}
			if (i->program_splice_flag == 0) {
				/* TODO: We don't support component counts, write fixed values */
				klbs_read_bits(bs, 8);
			}
			if (i->duration_flag == 1) {
				i->duration.auto_return = klbs_read_bits(bs, 1);
				klbs_read_bits(bs, 6); /* Reserved */
				i->duration.duration = klbs_read_bits(bs, 33);
			}

			i->unique_program_id = klbs_read_bits(bs, 16);
			i->avail_num = klbs_read_bits(bs, 8);
			i->avails_expected = klbs_read_bits(bs, 8);
		}

	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__TIME_SIGNAL) {
		si->time_signal.time_specified_flag = klbs_read_bits(bs, 1);
		if (si->time_signal.time_specified_flag == 1) {
			v = klbs_read_bits(bs, 6); /* Reserved */
			assert(v == 0x3f);
			si->time_signal.pts_time = klbs_read_bits(bs, 33);
		} else {
			v = klbs_read_bits(bs, 7); /* Reserved */
			assert(v == 0x7f);
		}
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__BW_RESERVATION) {
		/* TODO: Not supported */
		assert(0);
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__PRIVATE) {
		/* TODO: Not supported */
		assert(0);
	}
	int posb = klbs_get_byte_count(bs);
	si->splice_command_length = posb - posa;

	si->descriptor_loop_length = klbs_read_bits(bs, 16);
	if (si->descriptor_loop_length) {
		si->splice_descriptor = malloc(si->descriptor_loop_length);
		if (!si->splice_descriptor)
			return -1;
		for (int i = 0; i < si->descriptor_loop_length; i++) {
			si->splice_descriptor[i] = klbs_read_bits(bs, 8);
		}
	}

	/* We don't support encryption so we dont need alignment stuffing */
	/* We don't support encrypted_packets so we dont need e_crc_32 */
	si->e_crc_32 = 0;

	/* Checksum */
	si->crc_32 = klbs_read_bits(bs, 32);
	if (iso13818_checkCRC32(klbs_get_buffer(bs), klbs_get_byte_count(bs)) == 0) {
		/* CRC OK */
		si->crc_32_is_valid = 1;
	} else
		si->crc_32_is_valid = 0;

	klbs_free(bs);
	return klbs_get_byte_count(bs);
}

struct scte35_splice_info_section_s *scte35_splice_info_section_parse(uint8_t *section, unsigned int byteCount)
{
	if (*(section + 0) != SCTE35_TABLE_ID)
		return 0;

	struct scte35_splice_info_section_s *s = calloc(1, sizeof(*s));
	if (scte35_splice_info_section_unpackFrom(s, section, byteCount) < 0) {
		free(s);
		return NULL;
	}

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

int scte35_create_scte104_message(struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount)
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
	si->tier = 0xFFF; /* We don't support tiers. So the spec says value 0xFFF will be passed down stream and
			   * ignored by any equipment. So, lets pass a value to be ignored.
			   */

	return si;
}

int scte35_splice_info_section_packTo(struct scte35_splice_info_section_s *si, uint8_t *buffer, uint32_t buffer_length_bytes)
{
	if ((!si) || (!buffer) || (buffer_length_bytes < 128))
		return -1;

	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buffer, buffer_length_bytes);

	klbs_write_bits(bs, si->table_id, 8);
	klbs_write_bits(bs, si->section_syntax_indicator, 1);
	assert(si->section_syntax_indicator == 0);

	klbs_write_bits(bs, si->private_indicator, 1);
	assert(si->private_indicator == 0);

	klbs_write_bits(bs, 0xff, 2); /* Reserved */
	klbs_write_bits(bs, 0, 12); /* Section length, to be filled later */

	klbs_write_bits(bs, si->protocol_version, 8);
	assert(si->protocol_version == 0);

	klbs_write_bits(bs, si->encrypted_packet, 1);
	assert(si->encrypted_packet == 0);

	klbs_write_bits(bs, si->encryption_algorithm, 6);
	assert(si->encryption_algorithm == 0);

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
		/* TODO: Not supported */
		assert(0);
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {

		struct scte35_splice_insert_s *i = &si->splice_insert;

		klbs_write_bits(bs, i->splice_event_id, 32);
		klbs_write_bits(bs, i->splice_event_cancel_indicator, 1);
		klbs_write_bits(bs, 0xff, 7); /* Reserved */
		if (i->splice_event_cancel_indicator == 0) {

			klbs_write_bits(bs, i->out_of_network_indicator, 1);
			klbs_write_bits(bs, i->program_splice_flag, 1);
			klbs_write_bits(bs, i->duration_flag, 1);
			klbs_write_bits(bs, i->splice_immediate_flag, 1);
			klbs_write_bits(bs, 0xff, 4); /* Reserved */
			if ((i->program_splice_flag == 1) && (i->splice_immediate_flag == 0)) {
				klbs_write_bits(bs, i->splice_time.time_specified_flag, 1);
				if (i->splice_time.time_specified_flag == 1) {
					klbs_write_bits(bs, 0xff, 6); /* Reserved */
					klbs_write_bits(bs, i->splice_time.pts_time, 33);
				} else
					klbs_write_bits(bs, 0xff, 7); /* Reserved */
			}
			if (i->program_splice_flag == 0) {
				/* TODO: We don't support component counts, write fixed values */
				klbs_write_bits(bs, 0, 8);
			}
			if (i->duration_flag == 1) {
				klbs_write_bits(bs, i->duration.auto_return, 1);
				klbs_write_bits(bs, 0xff, 6); /* Reserved */
				klbs_write_bits(bs, i->duration.duration, 33);
			}

			klbs_write_bits(bs, i->unique_program_id, 16);
			klbs_write_bits(bs, i->avail_num, 8);
			klbs_write_bits(bs, i->avails_expected, 8);
		}

	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__TIME_SIGNAL) {
		klbs_write_bits(bs, si->time_signal.time_specified_flag, 1);
		if (si->time_signal.time_specified_flag == 1) {
			klbs_write_bits(bs, 0xff, 6); /* Reserved */
			klbs_write_bits(bs, si->time_signal.pts_time, 33);
		} else
			klbs_write_bits(bs, 0xff, 7); /* Reserved */
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__BW_RESERVATION) {
		/* TODO: Not supported */
		assert(0);
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__PRIVATE) {
		/* TODO: Not supported */
		assert(0);
	}
	int posb = klbs_get_byte_count(bs);
	si->splice_command_length = posb - posa;

	/* Patch in the command length */
	bs->buf[11] |= ((si->splice_command_length >> 8) & 0x0f);
	bs->buf[12]  =  (si->splice_command_length       & 0xff);

	klbs_write_bits(bs, si->descriptor_loop_length, 16);
	for (int i = 0; i < si->descriptor_loop_length; i++) {
		klbs_write_bits(bs, si->splice_descriptor[i], 8);
	}

	/* We don't support encryption so we dont need alignment stuffing */
	/* We don't support encrypted_packets so we dont need e_crc_32 */
	si->e_crc_32 = 0;

	si->section_length = klbs_get_byte_count(bs)
		+ 4 /* CRC */
		- 3 /* Header */
		;
	bs->buf[1] |= ((si->section_length >> 8) & 0x0f);
	bs->buf[2]  =  (si->section_length       & 0xff);

	/* Checksum */
	si->crc_32 = 0;
	iso13818_getCRC32(klbs_get_buffer(bs), klbs_get_byte_count(bs), &si->crc_32);
	klbs_write_bits(bs, si->crc_32, 32);
	klbs_write_buffer_complete(bs);

	int count = klbs_get_byte_count(bs);
	klbs_free(bs);
	return count;
}
