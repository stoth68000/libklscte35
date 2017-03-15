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

#include "libklvanc/vanc.h"
#include "libklvanc/vanc-scte_104.h"
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

static int scte35_generate_spliceinsert(struct packet_scte_104_s *pkt, int momOpNumber,
					struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct scte35_splice_info_section_s *si;

	si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	splices[(*outSpliceNum)++] = si;

	si->splice_insert.splice_event_id = op->sr_data.splice_event_id;
	si->splice_insert.splice_event_cancel_indicator = 0;
	si->splice_insert.out_of_network_indicator = 0;
	si->splice_insert.splice_immediate_flag = 0;
	si->splice_insert.program_splice_flag = 1;
	si->splice_insert.duration_flag = 0;
	si->splice_insert.duration.duration = 0;
	si->splice_insert.duration.auto_return = 0;

	switch(op->sr_data.splice_insert_type) {
	case SPLICESTART_NORMAL:
		si->splice_insert.out_of_network_indicator = 1;
		break;
	case SPLICESTART_IMMEDIATE:
		si->splice_insert.splice_immediate_flag = 1;
		si->splice_insert.out_of_network_indicator = 1;
		break;
	case SPLICEEND_NORMAL:
		break;
	case SPLICEEND_IMMEDIATE:
		si->splice_insert.splice_immediate_flag = 1;
		break;
	case SPLICE_CANCEL:
		si->splice_insert.splice_event_cancel_indicator = 1;
		break;
	default:
		fprintf(stderr, "Unknown Splice insert type %d\n",
			op->sr_data.splice_insert_type);
		return -1;
	}

	if (op->sr_data.splice_insert_type == SPLICESTART_NORMAL ||
	    op->sr_data.splice_insert_type == SPLICEEND_IMMEDIATE) {
		if (op->sr_data.pre_roll_time > 0) {
			/* Set PTS */
		}
	}

	if (op->sr_data.splice_insert_type == SPLICESTART_NORMAL ||
	    op->sr_data.splice_insert_type == SPLICESTART_IMMEDIATE) {
		if (op->sr_data.brk_duration > 0) {
			si->splice_insert.duration_flag = 1;
			si->splice_insert.duration.duration = op->sr_data.brk_duration * 9000;
		}
		si->splice_insert.duration.auto_return = op->sr_data.auto_return_flag;
	}

	si->splice_insert.unique_program_id = op->sr_data.unique_program_id;
	si->splice_insert.avail_num = op->sr_data.avail_num;
	si->splice_insert.avails_expected = op->sr_data.avails_expected;

	return 0;
}

static int scte35_generate_splicenull(struct packet_scte_104_s *pkt, int momOpNumber,
				      struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct scte35_splice_info_section_s *si;

	si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_NULL);
	splices[(*outSpliceNum)++] = si;

	return 0;
}

static int scte35_generate_timesignal(struct packet_scte_104_s *pkt, int momOpNumber,
				      struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct scte35_splice_info_section_s *si;

	si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__TIME_SIGNAL);
	splices[(*outSpliceNum)++] = si;

	si->time_signal.time_specified_flag = 1;
	/* FIXME */
	si->time_signal.pts_time = 0;

	return 0;
}

static int scte35_append_descriptor(struct packet_scte_104_s *pkt, int momOpNumber,
			      struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct insert_descriptor_request_data *des = &op->descriptor_data;
	struct scte35_splice_info_section_s *si;

	/* Append descriptor works with *any* splice type, so just find the most
	   recent descriptor */
	if (*outSpliceNum == 0)
		return -1;

	si = splices[*outSpliceNum - 1];

	/* Append to splice_descriptor (creating if not already allocated) */
	si->splice_descriptor = realloc(si->splice_descriptor,
					des->total_length + si->descriptor_loop_length);
	memcpy(si->splice_descriptor + si->descriptor_loop_length, des->descriptor_bytes,
	       des->total_length);
	si->descriptor_loop_length += des->total_length;

	return 0;
}

static int scte35_append_dtmf(struct packet_scte_104_s *pkt, int momOpNumber,
			      struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct scte35_splice_info_section_s *si;
	unsigned char buffer[256];
	int i;

	/* Find the most recent splice to append the descriptor to */
	for (i = *outSpliceNum - 1; i >= 0; i--) {
		si = splices[i];
		if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {
			break;
		}
	}

	if (i < 0) {
		/* There was no splice earlier in the MOM to append to */
		return -1;
	}

	/* Construct the actual SCTE-35 descriptor payload */
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, 0x01, 8);
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, 'C', 8);
	klbs_write_bits(bs, 'U', 8);
	klbs_write_bits(bs, 'E', 8);
	klbs_write_bits(bs, 'I', 8);
	klbs_write_bits(bs, op->dtmf_data.pre_roll_time, 8);
	klbs_write_bits(bs, op->dtmf_data.dtmf_length, 3);
	klbs_write_bits(bs, 0x1f, 5); /* Reserved */
	for (i = 0; i < op->dtmf_data.dtmf_length; i++) {
		klbs_write_bits(bs, op->dtmf_data.dtmf_char[i], 8);
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

static int scte35_append_segmentation(struct packet_scte_104_s *pkt, int momOpNumber,
				      struct scte35_splice_info_section_s *splices[],
				      int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct segmentation_descriptor_request_data *seg = &op->segmentation_data;
	struct scte35_splice_info_section_s *si;
	unsigned char buffer[256];
	int i;

	/* Find the most recent splice to append the descriptor to */
	for (i = *outSpliceNum - 1; i >= 0; i--) {
		si = splices[i];
		if (si->splice_command_type == SCTE35_COMMAND_TYPE__SPLICE_INSERT) {
			break;
		}
	}

	if (i < 0) {
		/* There was no splice earlier in the MOM to append to */
		return -1;
	}

	/* Construct the actual SCTE-35 descriptor payload */
	struct klbs_context_s *bs = klbs_alloc();

	/* See SCTE-35 2016 Sec 10.3.3, Table 19 */
	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, 0x02, 8); /* Splice Descriptor Tag */
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, 'C', 8);
	klbs_write_bits(bs, 'U', 8);
	klbs_write_bits(bs, 'E', 8);
	klbs_write_bits(bs, 'I', 8);
	klbs_write_bits(bs, seg->event_id, 32);
	klbs_write_bits(bs, seg->event_cancel_indicator, 1);
	klbs_write_bits(bs, 0x7f, 7); /* Reserved */
	if (seg->event_cancel_indicator == 0) {
		klbs_write_bits(bs, 0x01, 1); /* Program Segmentation Flag */
		klbs_write_bits(bs, seg->duration ? 1 : 0, 1);
		klbs_write_bits(bs, seg->delivery_not_restricted_flag, 1);
		if (seg->delivery_not_restricted_flag == 0) {
			klbs_write_bits(bs, seg->web_delivery_allowed_flag, 1);
			klbs_write_bits(bs, seg->no_regional_blackout_flag, 1);
			klbs_write_bits(bs, seg->archive_allowed_flag, 1);
			klbs_write_bits(bs, seg->device_restrictions, 2);
		} else {
			klbs_write_bits(bs, 0x1f, 5); /* Reserved */
		}
		if (0) { /* Program Segmentation Flag not set*/
			/* FIXME: Component mode not currently supported */
		}
		if (seg->duration) {
			/* FIXME: convert to PTS??? */
			klbs_write_bits(bs, seg->duration, 40);
		}
		klbs_write_bits(bs, seg->upid_type, 8);
		klbs_write_bits(bs, seg->upid_length, 8);
		for (i = 0; i < seg->upid_length; i++) {
			klbs_write_bits(bs, seg->upid[i], 8);
		}
		klbs_write_bits(bs, seg->type_id, 8);
		klbs_write_bits(bs, seg->segment_num, 8);
		klbs_write_bits(bs, seg->segments_expected, 8);
		if (seg->type_id == 0x34 || seg->type_id == 0x36) {
			/* FIXME: Sub segment num */
		}
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


int scte35_generate_from_scte104(struct packet_scte_104_s *pkt, struct splice_entries *results)
{
	/* See SCTE-104 Sec 8.3.1.1 Semantics of fields in splice_request_data() */
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct scte35_splice_info_section_s *splices[MAX_SPLICES];
	int num_splices = 0;

	if (pkt->so_msg.opID != 0xffff) {
		/* This is not a Multiple Operation Message, and we don't support
		   any Single Operation Messages */
		return -1;
	}

	/* Iterate over each of the operations in the Multiple Operation Message */
	for (int i = 0; i < m->num_ops; i++) {
		struct multiple_operation_message_operation *o = &m->ops[i];

		switch(o->opID) {
		case MO_SPLICE_REQUEST_DATA:
			scte35_generate_spliceinsert(pkt, i, splices, &num_splices);
			break;
		case MO_SPLICE_NULL_REQUEST_DATA:
			scte35_generate_splicenull(pkt, i, splices, &num_splices);
			break;
		case MO_TIME_SIGNAL_REQUEST_DATA:
			scte35_generate_timesignal(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_DESCRIPTOR_REQUEST_DATA:
			scte35_append_descriptor(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_DTMF_REQUEST_DATA:
			scte35_append_dtmf(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_SEGMENTATION_REQUEST_DATA:
			scte35_append_segmentation(pkt, i, splices, &num_splices);
			break;
		default:
			continue;
		}
	}

	/* Now that we've parsed all the operations in the MOM, convert the splices into
	   sections that can be fed to the mux */
	for (int i = 0; i < num_splices; i++) {
		struct scte35_splice_info_section_s *si = splices[i];

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

		results->splice_entry[i] = buf;
		results->splice_size[i] = packedLength;
		scte35_splice_info_section_free(si);
	}
	results->num_splices = num_splices;

	return 0;
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
	assert(v == 0x3);

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

#define SPLICE_INSERT_START_NORMAL    0x01
#define SPLICE_INSERT_START_IMMEDIATE 0x02
#define SPLICE_INSERT_END_NORMAL      0x03
#define SPLICE_INSERT_END_IMMEDIATE   0x04
#define SPLICE_INSERT_CANCEL          0x05

static int scte104_generate_splice_insert(const struct scte35_splice_insert_s *si,
					  uint8_t **buf, uint16_t *byteCount, uint64_t pts)
{
	uint8_t splice_insert_type;
	uint32_t preroll = 0;
	uint64_t duration = 0;
	uint8_t auto_return = 0;

	if (si->splice_event_cancel_indicator == 1) {
		splice_insert_type = SPLICE_INSERT_CANCEL;
	} else if (si->out_of_network_indicator == 1) {
		/* Out of Network */
		duration = si->duration.duration / 9000;
		auto_return = si->duration.auto_return;
		if (si->splice_immediate_flag == 1) {
			splice_insert_type = SPLICE_INSERT_START_IMMEDIATE;
		} else {
			splice_insert_type = SPLICE_INSERT_START_NORMAL;
			preroll = (si->splice_time.pts_time - pts) / 90;
		}
	} else {
		/* Into Network */
		if (si->splice_immediate_flag == 1) {
			splice_insert_type = SPLICE_INSERT_END_IMMEDIATE;
		} else {
			splice_insert_type = SPLICE_INSERT_END_NORMAL;
			preroll = (si->splice_time.pts_time - pts) / 90;
		}
	}

	uint8_t *b = calloc(1, 31);
	uint8_t *p = b;

	/* multiple_operation_message (Sec 7.2.3) */
	*(p++) = 0x08;			/* SMPTE 2010 Payload Descriptor */

	*(p++) = 0xff;			/* reserved */
	*(p++) = 0xff;			/* ... */

	*(p++) = 0x00;			/* messageSize */
	*(p++) = 0x1e;			/* ... */

	*(p++) = 0x00;			/* protocol_version */

	*(p++) = 0x00;			/* AS_index */

	*(p++) = 0x00;			/* message_number */

	*(p++) = 0x00;			/* DPI_PID_index */
	*(p++) = 0x00;			/* ... */

	*(p++) = 0x00;			/* SCTE35_protocol_version */

	/* timestamp (Sec 11.5) */
	*(p++) = 0x00;			/* time_type */

	*(p++) = 0x01;			/* num_ops */

	*(p++) = 0x01;			/* opID - splice_request_data() */
	*(p++) = 0x01;			/* ... */

	*(p++) = 0x00;			/* data_length */
	*(p++) = 0x0e;			/* ... */

	/* splice_request_data() */
	*(p++) = splice_insert_type;

	/* splice_event_index */
	*(p++) = si->splice_event_id >> 24;
	*(p++) = si->splice_event_id >> 16;
	*(p++) = si->splice_event_id >>  4;
	*(p++) = si->splice_event_id;

	/* unique_program_id */
	*(p++) = si->unique_program_id >> 8;
	*(p++) = si->unique_program_id;

	/* pre_roll_time */
	*(p++) = preroll >> 8;
	*(p++) = preroll;

	if (si->duration_flag) {
		*(p++) = duration >> 8;	/* break_duration in 1/10 secs */
		*(p++) = duration;
	} else {
		*(p++) = 0x00;
		*(p++) = 0x00;
	}

	*(p++) = si->avail_num;		/* avail_num */
	*(p++) = si->avails_expected;	/* avails_expected */
	*(p++) = auto_return;		/* auto_return_flag */

	*buf = b;
	*byteCount = (p - b);
	return 0;
}



int scte35_create_scte104_message(struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount, uint64_t pts)
{
	int ret = -1;

	/* We support some very specific SCTE104 message types. Immediate INTO/OUT-OF messages.
	 * Only 'insert' messages, no other message support. Return an error if we're not sure
	 * what kind of message is being requested.
	 */
	if (s->splice_command_type != SCTE35_COMMAND_TYPE__SPLICE_INSERT)
		return -1;

	struct scte35_splice_insert_s *si = &s->splice_insert;

	ret = scte104_generate_splice_insert(si, buf, byteCount, pts);

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

	si->table_id = SCTE35_TABLE_ID;
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
