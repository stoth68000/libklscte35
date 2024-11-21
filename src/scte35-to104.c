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

#include "libklvanc/vanc.h"
#include "libklvanc/vanc-scte_104.h"
#include "libklscte35/scte35.h"
#include "klbitstream_readwriter.h"

#define SPLICE_INSERT_START_NORMAL    0x01
#define SPLICE_INSERT_START_IMMEDIATE 0x02
#define SPLICE_INSERT_END_NORMAL      0x03
#define SPLICE_INSERT_END_IMMEDIATE   0x04
#define SPLICE_INSERT_CANCEL          0x05

static int scte104_generate_splice_request(const struct scte35_splice_insert_s *si, uint64_t pts,
					   struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	uint8_t splice_insert_type;
	uint32_t preroll = 0;
	uint64_t duration = 0;
	uint8_t auto_return = 0;
	int ret;

	if (si->splice_event_cancel_indicator == 1) {
		splice_insert_type = SPLICE_INSERT_CANCEL;
	} else if (si->out_of_network_indicator == 1) {
		/* Out of Network */
		duration = si->duration.duration / 9000;
		if (si->duration.duration % 9000 >= 4500)
			duration++;

		auto_return = si->duration.auto_return;
		if (si->splice_immediate_flag == 1) {
			splice_insert_type = SPLICE_INSERT_START_IMMEDIATE;
		} else {
			splice_insert_type = SPLICE_INSERT_START_NORMAL;
			if (si->splice_time.pts_time > pts)
				preroll = (si->splice_time.pts_time - pts) / 90;
			else
				preroll = 0;
		}
	} else {
		/* Into Network */
		if (si->splice_immediate_flag == 1) {
			splice_insert_type = SPLICE_INSERT_END_IMMEDIATE;
		} else {
			splice_insert_type = SPLICE_INSERT_END_NORMAL;
			if (si->splice_time.pts_time > pts)
				preroll = (si->splice_time.pts_time - pts) / 90;
			else
				preroll = 0;
		}
	}

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_SPLICE_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	op->sr_data.splice_insert_type = splice_insert_type;
	op->sr_data.splice_event_id = si->splice_event_id;
	op->sr_data.unique_program_id = si->unique_program_id;
	op->sr_data.pre_roll_time = preroll;
	op->sr_data.brk_duration = duration;
	op->sr_data.avail_num = si->avail_num;
	op->sr_data.avails_expected = si->avails_expected;
	op->sr_data.auto_return_flag = auto_return;

	return 0;
}

static int scte104_generate_splice_null(const struct scte35_splice_null_s *si, uint64_t pts,
					struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_SPLICE_NULL_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	/* Splice NULL requests have no actual properties to fill out */

	return 0;
}

static int scte104_generate_time_signal(const struct scte35_splice_time_s *si, uint64_t pts,
					struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_TIME_SIGNAL_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	if (si->time_specified_flag != 0) {
		if (si->pts_time > pts)
			op->timesignal_data.pre_roll_time = (si->pts_time - pts) / 90;
		else
			op->timesignal_data.pre_roll_time = 0;
	}

	return 0;
}

static int scte104_generate_proprietary(const struct scte35_splice_private_s *si, uint64_t pts,
					struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_PROPRIETARY_COMMAND_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	op->proprietary_data.proprietary_id = si->identifier;
	op->proprietary_data.data_length = si->private_length;
	for (int i = 0; i < op->proprietary_data.data_length; i++) {
		op->proprietary_data.proprietary_data[i] = si->private_byte[i];
	}

	return 0;
}

static int scte35_append_descriptor(struct splice_descriptor *sd, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_DESCRIPTOR_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	op->descriptor_data.descriptor_count = 1;
	op->descriptor_data.total_length = sd->extra_data.descriptor_data_length + 6;
	// 1 byte tag + 1 byte len + 4 bytes identifier = 6 bytes

	op->descriptor_data.descriptor_bytes[0] = sd->splice_descriptor_tag;
	op->descriptor_data.descriptor_bytes[1] = sd->extra_data.descriptor_data_length + 4;
	// Data + 4 bytes identifier
	op->descriptor_data.descriptor_bytes[2] = (uint8_t)((sd->identifier >> 24) & 0xff);
	op->descriptor_data.descriptor_bytes[3] = (uint8_t)((sd->identifier >> 16) & 0xff);
	op->descriptor_data.descriptor_bytes[4] = (uint8_t)((sd->identifier >> 8) & 0xff);
	op->descriptor_data.descriptor_bytes[5] = (uint8_t)(sd->identifier & 0xff);

	for (int i = 0; i < sd->extra_data.descriptor_data_length; i++) {
		op->descriptor_data.descriptor_bytes[6 + i] = sd->extra_data.descriptor_data[i];
	}

	return 0;
}

static int scte35_append_dtmf(struct splice_descriptor *sd, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_DTMF_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	op->dtmf_data.pre_roll_time = sd->dtmf_data.preroll;
	op->dtmf_data.dtmf_length = sd->dtmf_data.dtmf_count;
	if (op->dtmf_data.dtmf_length > 8)
		op->dtmf_data.dtmf_length = 8;
	for (int i = 0; i < op->dtmf_data.dtmf_length; i++) {
		op->dtmf_data.dtmf_char[i] = sd->dtmf_data.dtmf_char[i];
	}

	return 0;
}

static int scte35_append_avail(struct splice_descriptor *sd, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_AVAIL_DESCRIPTOR_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	op->avail_descriptor_data.num_provider_avails = 1;
	op->avail_descriptor_data.provider_avail_id[0] = sd->avail_data.provider_avail_id;

	return 0;
}

static int scte35_append_segmentation(struct splice_descriptor *sd, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	struct klvanc_segmentation_descriptor_request_data *seg;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_SEGMENTATION_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;
	seg = &op->segmentation_data;

	seg->event_id = sd->seg_data.event_id;
	seg->event_cancel_indicator = sd->seg_data.event_cancel_indicator;
	seg->delivery_not_restricted_flag = sd->seg_data.delivery_not_restricted_flag;
	seg->web_delivery_allowed_flag = sd->seg_data.web_delivery_allowed_flag;
	seg->no_regional_blackout_flag = sd->seg_data.no_regional_blackout_flag;
	seg->archive_allowed_flag = sd->seg_data.archive_allowed_flag;
	seg->device_restrictions = sd->seg_data.device_restrictions;
	seg->duration = sd->seg_data.segmentation_duration / 90000;
	seg->upid_type = sd->seg_data.upid_type;
	seg->upid_length = sd->seg_data.upid_length;
	for (int i = 0; i < seg->upid_length; i++)
		seg->upid[i] = sd->seg_data.upid[i];
	seg->type_id = sd->seg_data.type_id;
	seg->segment_num = sd->seg_data.segment_num;
	seg->segments_expected = sd->seg_data.segments_expected;

	return 0;
}

static int scte35_append_tier(struct scte35_splice_info_section_s *s, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_TIER_DATA, &op);
	if (ret != 0)
		return -1;

	op->tier_data.tier_data = s->tier;

	return 0;
}

static int scte35_append_time(struct splice_descriptor *sd, struct klvanc_packet_scte_104_s *pkt)
{
	struct klvanc_multiple_operation_message_operation *op;
	struct klvanc_time_descriptor_data *t;
	int ret;

	ret = klvanc_SCTE_104_Add_MOM_Op(pkt, MO_INSERT_TIME_DESCRIPTOR, &op);
	if (ret != 0)
		return -1;
	t = &op->time_data;

	t->TAI_seconds = sd->time_data.TAI_seconds;
	t->TAI_ns = sd->time_data.TAI_ns;
	t->UTC_offset = sd->time_data.UTC_offset;

	return 0;
}

int scte35_create_scte104_message(struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount, uint64_t pts)
{
	struct klvanc_context_s *ctx;
	struct klvanc_packet_scte_104_s *pkt;
	int ret = -1;

	ret = klvanc_context_create(&ctx);
	if (ret != 0)
		return ret;

	/* Create a Multiple Operation Message SCTE-104 packet */
	ret = klvanc_alloc_SCTE_104(0xffff, &pkt);
	if (ret != 0)
		return ret;

	/* Compensate for any adjustments intermediate processors may have
	   made to the PTS before using the value in any calculations */
	pts -= s->pts_adjustment;

	switch(s->splice_command_type) {
	case SCTE35_COMMAND_TYPE__SPLICE_INSERT:
		ret = scte104_generate_splice_request(&s->splice_insert, pts, pkt);
		break;
	case SCTE35_COMMAND_TYPE__SPLICE_NULL:
		ret = scte104_generate_splice_null(&s->splice_null, pts, pkt);
		break;
	case SCTE35_COMMAND_TYPE__TIME_SIGNAL:
		ret = scte104_generate_time_signal(&s->time_signal, pts, pkt);
		break;
	case SCTE35_COMMAND_TYPE__PRIVATE:
		ret = scte104_generate_proprietary(&s->private_command, pts, pkt);
		break;
	case SCTE35_COMMAND_TYPE__BW_RESERVATION:
		/* No equivalent command in SCTE-104, so indicate success but don't
		   actually return a SCTE-104 message */
		*byteCount = 0;
		klvanc_free_SCTE_104(pkt);
		klvanc_context_destroy(ctx);
		return 0;
	default:
		fprintf(stderr, "%s: Unsupported command type %d\n", __func__,
			s->splice_command_type);
		return -1;
	}

	/* The tier field is a bit unusual, because we need to create an extra MOM Operation
	   based on the tier value in the splice_info section, as opposed to the presence of a
	   splice descriptor. */
	if (s->tier != 0x0fff) {
		scte35_append_tier(s, pkt);
	}

	for (int i = 0; i < s->descriptor_loop_count; i++) {
		struct splice_descriptor *sd = s->descriptors[i];
		switch(sd->splice_descriptor_tag) {
		case SCTE35_AVAIL_DESCRIPTOR:
			scte35_append_avail(sd, pkt);
			break;
		case SCTE35_DTMF_DESCRIPTOR:
			scte35_append_dtmf(sd, pkt);
			break;
		case SCTE35_SEGMENTATION_DESCRIPTOR:
			scte35_append_segmentation(sd, pkt);
			break;
		case SCTE35_TIME_DESCRIPTOR:
			scte35_append_time(sd, pkt);
			break;
		default:
			/* Any SCTE-35 descriptor we don't recognize should be pushed
			   out over SCTE-104 using insert_descriptor_request */
			scte35_append_descriptor(sd, pkt);
			break;
		}

	}

	/* Serialize the Multiple Operation Message out to a VANC array */
	ret = klvanc_convert_SCTE_104_to_packetBytes(ctx, pkt, buf, byteCount);

	klvanc_free_SCTE_104(pkt);

	klvanc_context_destroy(ctx);

	return ret;
}
