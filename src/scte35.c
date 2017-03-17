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

#if 1
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


int scte35_generate_out_of_network_duration(uint16_t uniqueProgramId, uint32_t eventId, uint32_t duration, int autoReturn,
					    uint8_t **dst, uint32_t *dstLengthBytes, uint32_t immediate, uint16_t availNum,
					    uint16_t availsExpected)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	if (si == NULL)
		return -1;
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 1;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 1;
	si->splice_insert.duration.auto_return = autoReturn;
	si->splice_insert.duration.duration = duration * 9000;
	si->splice_insert.splice_immediate_flag = immediate ? 1 : 0;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = availNum;
	si->splice_insert.avails_expected = availsExpected;

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf) {
		scte35_splice_info_section_free(si);
		return -1;
	}

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
int scte35_generate_out_of_network(uint16_t uniqueProgramId, uint32_t eventId,
				   uint8_t **dst, uint32_t *dstLengthBytes, uint32_t immediate,
				   uint16_t availNum, uint16_t availsExpected)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	if (si == NULL)
		return -1;
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 1;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 0;
	si->splice_insert.splice_immediate_flag = immediate ? 1 : 0;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = availNum;
	si->splice_insert.avails_expected = availsExpected;

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf) {
		scte35_splice_info_section_free(si);
		return -1;
	}

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
					    uint8_t **dst, uint32_t *dstLengthBytes, uint16_t availNum,
					    uint16_t availsExpected)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	if (si == NULL)
		return -1;
	si->splice_insert.splice_event_id = eventId;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 0;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 0;
	si->splice_insert.splice_immediate_flag = 1;
	si->splice_insert.unique_program_id = uniqueProgramId;
	si->splice_insert.avail_num = availNum;
	si->splice_insert.avails_expected = availsExpected;

	int l = 4096;
	uint8_t *buf = calloc(1, l);
	if (!buf) {
		scte35_splice_info_section_free(si);
		return -1;
	}

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
	if (s->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_NULL) {
		/* Nothing to do */
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
	hexdump(s->splice_descriptor, s->descriptor_loop_length, 16);

	SHOW_LINE_U32("", s->e_crc_32);
	SHOW_LINE_U32("", s->crc_32);
	SHOW_LINE_U32("", s->crc_32_is_valid);
}

ssize_t scte35_splice_info_section_unpackFrom(struct scte35_splice_info_section_s *si, uint8_t *src, uint32_t srcLengthBytes)
{
	uint32_t v;

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

#ifdef ABORT_ON_RESERVED_BITS_NOT_SET
	v = klbs_read_bits(bs, 2); /* Reserved */
	assert(v == 0x3);
#else
	klbs_read_bits(bs, 2); /* Reserved */
#endif

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
		if (si->splice_descriptor == NULL) {
			klbs_free(bs);
			return -1;
		}
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

	/* Grab the byte count to avoid use-after-free condition */
	int byteCount = klbs_get_byte_count(bs);
	klbs_free(bs);

	return byteCount;
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
	if (s->splice_descriptor)
		free(s->splice_descriptor);
	free(s);
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

	si->table_id = SCTE35_TABLE_ID;
	si->splice_command_type = command_type;
	si->tier = 0xFFF; /* We don't support tiers. So the spec says value 0xFFF will be passed down stream and
			   * ignored by any equipment. So, lets pass a value to be ignored.
			   */

	return si;
}

int scte35_append_dtmf(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, 0x01, 8);
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, desc->identifier, 32);
	klbs_write_bits(bs, desc->dtmf_data.preroll, 8);
	klbs_write_bits(bs, desc->dtmf_data.dtmf_count, 3);
	klbs_write_bits(bs, 0x1f, 5); /* Reserved */
	for (int i = 0; i < desc->dtmf_data.dtmf_count; i++) {
		klbs_write_bits(bs, desc->dtmf_data.dtmf_char[i], 8);
	}
	buffer[1] = klbs_get_byte_count(bs) - 2;

	/* Append to splice_descriptor (creating if not already allocated) */
	si->splice_descriptor = realloc(si->splice_descriptor,
					klbs_get_byte_count(bs) + si->descriptor_loop_length);
	memcpy(si->splice_descriptor + si->descriptor_loop_length, buffer, klbs_get_byte_count(bs));
	si->descriptor_loop_length += klbs_get_byte_count(bs);

	klbs_write_buffer_complete(bs);
	klbs_free(bs);

	return 0;
}

int scte35_splice_info_section_packTo(struct scte35_splice_info_section_s *si, uint8_t *buffer, uint32_t buffer_length_bytes)
{
	int ret;

	if ((!si) || (!buffer) || (buffer_length_bytes < 128))
		return -1;

	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buffer, buffer_length_bytes);

	klbs_write_bits(bs, si->table_id, 8);
	assert(si->table_id == SCTE35_TABLE_ID);
	klbs_write_bits(bs, si->section_syntax_indicator, 1);
	assert(si->section_syntax_indicator == 0);

	klbs_write_bits(bs, si->private_indicator, 1);
	assert(si->private_indicator == 0);

	klbs_write_bits(bs, 0xff, 2); /* Reserved */
	klbs_write_bits(bs, 0, 12); /* Section length, to be filled later */

	/* Technically SCTE104 can pass us an arbitrary protocol version and the SCTE104 Figure 8-1
	 * mapping table says field SCTE35_protocol_version should be mapped into the SCTE35
	 * reconstructed table. I'm NOT going to do that, because the SCTE35 spec says the only valid
	 * value is zero. So, I'm going to ensure that any SCTE35 message we generate contains
	 * protocol_zero, regardless.
	 */
	klbs_write_bits(bs, si->protocol_version, 8);
	assert(si->protocol_version == 0);

	klbs_write_bits(bs, si->encrypted_packet, 1);
	assert(si->encrypted_packet == 0); /* No support */

	klbs_write_bits(bs, si->encryption_algorithm, 6);
	assert(si->encryption_algorithm == 0); /* No support */

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

	/* Generate the descriptor payload */
	si->descriptor_loop_length = 0;
	for (int i = 0; i < si->descriptor_loop_count; i++) {
		switch(si->descriptors[i]->splice_descriptor_tag) {
		case SCTE35_DTMF_DESCRIPTOR:
			ret = scte35_append_dtmf(si, si->descriptors[i]);
			break;
		default:
			fprintf(stderr, "Cannot pack unknown descriptor 0x%x\n",
				si->descriptors[i]->splice_descriptor_tag);
			continue;
		}
		if (ret != 0) {
			fprintf(stderr, "Failed to serialize descriptor 0x%x\n",
				si->descriptors[i]->splice_descriptor_tag);
		}
	}

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

int alloc_SCTE_35_splice_descriptor(uint8_t tag, struct splice_descriptor **desc)
{
	struct splice_descriptor *sd = calloc(1, sizeof(*sd));
	if (!sd)
		return -1;

	sd->splice_descriptor_tag = tag;
	*desc = sd;

	return 0;
}
