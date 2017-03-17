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
					   struct packet_scte_104_s *pkt)
{
	struct multiple_operation_message_operation *op;
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
					struct packet_scte_104_s *pkt)
{
	struct multiple_operation_message_operation *op;
	int ret;

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_SPLICE_NULL_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	/* Splice NULL requests have no actual properties to fill out */

	return 0;
}

static int scte104_generate_time_signal(const struct scte35_splice_time_s *si, uint64_t pts,
					struct packet_scte_104_s *pkt)
{
	struct multiple_operation_message_operation *op;
	int ret;

	ret =  klvanc_SCTE_104_Add_MOM_Op(pkt, MO_TIME_SIGNAL_REQUEST_DATA, &op);
	if (ret != 0)
		return -1;

	/* FIXME: Pre-roll value */

	return 0;
}


int scte35_create_scte104_message(struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount, uint64_t pts)
{
	struct packet_scte_104_s *pkt;
	int ret = -1;

	/* Create a Multiple Operation Message SCTE-104 packet */
	ret = alloc_SCTE_104(0xffff, &pkt);
	if (ret != 0)
		return ret;

	/* We support some very specific SCTE104 message types. Immediate INTO/OUT-OF messages.
	 * Only 'insert' messages, no other message support. Return an error if we're not sure
	 * what kind of message is being requested.
	 */
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
	default:
		fprintf(stderr, "%s: Unsupported command type %d\n", __func__,
			s->splice_command_type);
		return -1;
	}

	/* FIXME: loop through descriptors and create an MOM Op for each */

	/* Serialize the Multiple Operation Message out to a VANC array */
	ret = convert_SCTE_104_to_packetBytes(pkt, buf, byteCount);
	return ret;
}
