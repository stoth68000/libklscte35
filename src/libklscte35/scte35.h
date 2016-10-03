/*****************************************************************************
 * Copyright (c) 2016 Kernel Labs Inc.
 *
 * Authors:
 *   Steven Toth <stoth@kernellabs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111, USA.
 *
 *****************************************************************************/

#ifndef SCTE35_H
#define SCTE35_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scte35_break_duration_s
{
	uint8_t  auto_return;
	uint64_t duration;
};

struct scte35_splice_null_s
{
};

struct scte35_splice_time_s
{
	uint8_t  time_specified_flag;
	uint64_t pts_time;
};

struct scte35_splice_component_s
{
	uint8_t component_tag;
	struct scte35_splice_time_s splice_time;
};

struct scte35_splice_insert_s
{
	uint32_t splice_event_id;
	uint8_t  splice_event_cancel_indicator;
	uint8_t  out_of_network_indicator;
	uint8_t  program_splice_flag;
	uint8_t  duration_flag;
	uint8_t  splice_immediate_flag;
	struct scte35_splice_time_s splice_time;

	/* We don't support program_splice_flag == 0 */

	/* We don't support component counts */
	uint8_t   component_count;
	struct scte35_splice_component_s components[256];

	struct scte35_break_duration_s duration;

	uint16_t  unique_program_id;
	uint8_t   avail_num;
	uint8_t   avails_expected;
};


struct scte35_splice_info_section_s
{
	uint8_t  table_id;
	uint8_t  section_syntax_indicator;
	uint8_t  private_indicator;
	uint16_t section_length;
	uint8_t  protocol_version;
	uint8_t  encrypted_packet;
	uint8_t  encryption_algorithm;
	uint64_t pts_adjustment;
	uint8_t  cw_index;
	uint16_t tier;
	uint16_t splice_command_length;
	uint8_t  splice_command_type;
	union {
		struct scte35_splice_null_s splice_null;
		struct scte35_splice_insert_s splice_insert;
	};

	/* We don't support descriptor parsing. */
	uint16_t descriptor_loop_length;

	uint32_t e_crc_32;
	uint32_t crc_32;
};

struct scte35_context_s
{
	/* User visible fields */
	uint8_t pkt[188]; /* Assumption, sections always < this array size */
	uint8_t section[4096];
	uint16_t section_length;

	/* Private content, caller should not modify or inspect. */
	int verbose;
	uint16_t outputPid;
	uint8_t cc;
	uint32_t eventId;
	uint16_t uniqueProgramId;
};

void scte35_initialize(struct scte35_context_s *ctx, uint16_t outputPid);

/* Go into Ad, switch away from the network.
 * Return the number of TS packets generated in ctx->pkt, typically 1, or
 * < 0 on error.
 */
int scte35_generate_immediate_out_of_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId);

/* Go out of Ad break, return back to the network.
 * Return the number of TS packets generated in ctx->pkt, typically 1, or
 * < 0 on error.
 */
int scte35_generate_immediate_in_to_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId);

/* Generate a splice_null() heartbeat packet. This typically keeps the
 * downstream slicer alive, not specifically in the spec. 
 * Return the number of TS packets generated in ctx->pkt, typically 1, or
 * < 0 on error.
 */
int scte35_generate_heartbeat(struct scte35_context_s *ctx);

/* Allow the next event ID to be set, so that SCTE104 translated
 * packets, that contain their own eventID, we will to honor.
 * Return the number of TS packets generated in ctx->pkt, typically 1, or
 * < 0 on error.
 */
int scte35_set_next_event_id(struct scte35_context_s *ctx, uint32_t eventId);

/* Caller must call scte35_splice_info_section_free() after they're done with the parse result. */
struct scte35_splice_info_section_s *scte35_splice_info_section_parse(uint8_t *section, unsigned int byteCount);
void scte35_splice_info_section_free(struct scte35_splice_info_section_s *s);

#ifdef __cplusplus
};
#endif

#endif /* SCTE35_H */
