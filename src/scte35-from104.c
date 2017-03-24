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
#include "libklscte35/scte35.h"
#include "klbitstream_readwriter.h"

static int scte35_generate_spliceinsert(struct packet_scte_104_s *pkt, int momOpNumber,
					struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct scte35_splice_info_section_s *si;

	si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	if (!si)
		return -1;

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
	if (!si)
		return -1;

	splices[(*outSpliceNum)++] = si;

	return 0;
}

static int scte35_generate_timesignal(struct packet_scte_104_s *pkt, int momOpNumber,
				      struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct scte35_splice_info_section_s *si;

	si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__TIME_SIGNAL);
	if (!si)
		return -1;

	splices[(*outSpliceNum)++] = si;

	si->time_signal.time_specified_flag = 1;
	/* FIXME */
	si->time_signal.pts_time = 0;

	return 0;
}

static int scte35_append_104_descriptor(struct packet_scte_104_s *pkt, int momOpNumber,
					struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct insert_descriptor_request_data *des = &op->descriptor_data;
	struct scte35_splice_info_section_s *si;
	struct splice_descriptor *sd;
	uint8_t len;
	int ret;

	/* Append descriptor works with *any* splice type, so just find the most
	   recent descriptor */
	if (*outSpliceNum == 0)
		return -1;

	si = splices[*outSpliceNum - 1];

	ret = alloc_SCTE_35_splice_descriptor(des->descriptor_bytes[0], &sd);
	if (ret != 0)
		return -1;

	len = des->descriptor_bytes[1];
	if (len > sizeof(sd->extra_data.descriptor_data)) {
		len = sizeof(sd->extra_data.descriptor_data);
	}
	sd->extra_data.descriptor_data_length = len;
	memcpy(&sd->extra_data.descriptor_data, des->descriptor_bytes + 2, len);

	si->descriptors[si->descriptor_loop_count++] = sd;

	return 0;
}

static int scte35_append_104_dtmf(struct packet_scte_104_s *pkt, int momOpNumber,
				  struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct scte35_splice_info_section_s *si;
	struct splice_descriptor *sd;
	int ret, i;

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

	if (si->descriptor_loop_count > SCTE35_MAX_DESCRIPTORS) {
		return -1;
	}

	ret = alloc_SCTE_35_splice_descriptor(SCTE35_DTMF_DESCRIPTOR, &sd);
	if (ret != 0)
		return -1;

	sd->identifier = 0x43554549; /* CUEI */
	sd->dtmf_data.preroll = op->dtmf_data.pre_roll_time;
	sd->dtmf_data.dtmf_count = op->dtmf_data.dtmf_length;

	if (sd->dtmf_data.dtmf_count > 8)
		sd->dtmf_data.dtmf_count = 8;

	for (i = 0; i < sd->dtmf_data.dtmf_count; i++) {
		sd->dtmf_data.dtmf_char[i] = op->dtmf_data.dtmf_char[i];
	}

	si->descriptors[si->descriptor_loop_count++] = sd;

	return 0;
}

static int scte35_append_104_avail(struct packet_scte_104_s *pkt, int momOpNumber,
				   struct scte35_splice_info_section_s *splices[], int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct scte35_splice_info_section_s *si;
	struct splice_descriptor *sd;
	int ret, i;

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

	/* We need to create an SCTE-35 descriptor for each Avail listed in the
	   MOM Operation */
	for (int j = 0; j < op->avail_descriptor_data.num_provider_avails; j++) {
		if (si->descriptor_loop_count > SCTE35_MAX_DESCRIPTORS) {
			return -1;
		}

		ret = alloc_SCTE_35_splice_descriptor(SCTE35_AVAIL_DESCRIPTOR, &sd);
		if (ret != 0)
			return -1;

		sd->identifier = 0x43554549; /* CUEI */
		sd->avail_data.provider_avail_id = op->avail_descriptor_data.provider_avail_id[j];

		si->descriptors[si->descriptor_loop_count++] = sd;
	}

	return 0;
}

static int scte35_append_104_segmentation(struct packet_scte_104_s *pkt, int momOpNumber,
					  struct scte35_splice_info_section_s *splices[],
					  int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct segmentation_descriptor_request_data *seg = &op->segmentation_data;
	struct scte35_splice_info_section_s *si;
	struct splice_descriptor *sd;
	int ret, i;

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

	if (si->descriptor_loop_count > SCTE35_MAX_DESCRIPTORS) {
		return -1;
	}

	ret = alloc_SCTE_35_splice_descriptor(SCTE35_SEGMENTATION_DESCRIPTOR, &sd);
	if (ret != 0)
		return -1;

	sd->identifier = 0x43554549; /* CUEI */
	sd->seg_data.event_id = seg->event_id;
	sd->seg_data.event_cancel_indicator = seg->event_cancel_indicator;
	sd->seg_data.program_segmentation_flag = 1; /* FIXME: Component mode */
	sd->seg_data.delivery_not_restricted_flag = seg->delivery_not_restricted_flag;
	sd->seg_data.web_delivery_allowed_flag = seg->web_delivery_allowed_flag;
	sd->seg_data.no_regional_blackout_flag = seg->no_regional_blackout_flag;
	sd->seg_data.archive_allowed_flag = seg->archive_allowed_flag;
	sd->seg_data.device_restrictions = seg->device_restrictions;
	sd->seg_data.segmentation_duration = seg->duration;
	sd->seg_data.upid_type = seg->upid_type;
	sd->seg_data.upid_length = seg->upid_length;
	for (i = 0; i < sd->seg_data.upid_length; i++)
		sd->seg_data.upid[i] = seg->upid[i];
	sd->seg_data.type_id = seg->type_id;
	sd->seg_data.segment_num = seg->segment_num;
	sd->seg_data.segments_expected = seg->segments_expected;
	sd->seg_data.sub_segment_num = 0;
	sd->seg_data.sub_segments_expected = 0;

	si->descriptors[si->descriptor_loop_count++] = sd;

	return 0;
}

static int scte35_append_104_tier(struct packet_scte_104_s *pkt, int momOpNumber,
				  struct scte35_splice_info_section_s *splices[],
				  int *outSpliceNum)
{
	struct multiple_operation_message *m = &pkt->mo_msg;
	struct multiple_operation_message_operation *op = &m->ops[momOpNumber];
	struct tier_data *tier = &op->tier_data;
	struct scte35_splice_info_section_s *si;
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

	/* Unlike most Ops, this one modifies the properties of the splice_info,
	   as opposed to appending a descriptor */
	si->tier = tier->tier_data;

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
		case MO_SPLICE_NULL_REQUEST_DATA:
		case MO_TIME_SIGNAL_REQUEST_DATA:
			if (num_splices == (MAX_SPLICES - 1))
				continue;
		}

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
			scte35_append_104_descriptor(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_DTMF_REQUEST_DATA:
			scte35_append_104_dtmf(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_AVAIL_DESCRIPTOR_REQUEST_DATA:
			scte35_append_104_avail(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_SEGMENTATION_REQUEST_DATA:
			scte35_append_104_segmentation(pkt, i, splices, &num_splices);
			break;
		case MO_INSERT_TIER_DATA:
			scte35_append_104_tier(pkt, i, splices, &num_splices);
			break;
		default:
			continue;
		}
	}

	/* Now that we've parsed all the operations in the MOM, convert the splices into
	   sections that can be fed to the mux */
	for (int i = 0; i < num_splices; i++) {
		struct scte35_splice_info_section_s *si = splices[i];

		/* We shouldn't need a null pointer check here, as we should never have nulls
		 * in the list. Fixed the list to never include nulls.
		 * So the static code analyzer don'es complain.
		 */

		int l = 4096;
		uint8_t *buf = calloc(1, l);
		if (!buf) {
			scte35_splice_info_section_free(si);
			continue;
		}

		ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
		if (packedLength < 0) {
			free(buf);
			scte35_splice_info_section_free(si);
			continue;
		}
		scte35_splice_info_section_free(si);

		results->splice_entry[i] = buf;
		results->splice_size[i] = packedLength;
	}
	results->num_splices = num_splices;

	return 0;
}
