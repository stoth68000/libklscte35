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

/**
 * @file	scte35.h
 * @author	Steven Toth <stoth@kernellabs.com>
 * @copyright	Copyright (c) 2016 Kernel Labs Inc. All Rights Reserved.
 * @brief	TODO - Brief description goes here.
 */

#ifndef SCTE35_H
#define SCTE35_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	TODO - Brief description goes here.
 */
struct scte35_break_duration_s
{
	uint8_t  auto_return;
	uint64_t duration;
};

/**
 * @brief       TODO - Brief description goes here.
 */
struct scte35_splice_null_s
{
};

/**
 * @brief       TODO - Brief description goes here.
 */
struct scte35_splice_time_s
{
	uint8_t  time_specified_flag;
	uint64_t pts_time;
};

/**
 * @brief       TODO - Brief description goes here.
 */
struct scte35_splice_component_s
{
	uint8_t component_tag;
	struct  scte35_splice_time_s splice_time;
};

/**
 * @brief       TODO - Brief description goes here.
 */
struct scte35_splice_insert_s
{
	uint32_t splice_event_id;
	uint8_t  splice_event_cancel_indicator;
	uint8_t  out_of_network_indicator;
	uint8_t  program_splice_flag;
	uint8_t  duration_flag;
	uint8_t  splice_immediate_flag;
	struct   scte35_splice_time_s splice_time;

	/* We don't support program_splice_flag == 0 */

	/* We don't support component counts */
	uint8_t  component_count;
	struct   scte35_splice_component_s components[256];

	struct   scte35_break_duration_s duration;

	uint16_t unique_program_id;
	uint8_t  avail_num;
	uint8_t  avails_expected;
};

/**
 * @brief       TODO - Brief description goes here.
 */
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

/**
 * @brief       TODO - Brief description goes here.
 */
struct scte35_context_s
{
	/* User visible fields */
	uint8_t  pkt[188]; /* Assumption, sections always < this array size */
	uint8_t  section[4096];
	uint16_t section_length;

	/* Private content, caller should not modify or inspect. */
	int      verbose;
	uint16_t outputPid;
	uint8_t  cc;
	uint32_t eventId;
	uint16_t uniqueProgramId;
};

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @param[in]	uint16_t outputPid - Brief description goes here.
 */
void scte35_initialize(struct scte35_context_s *ctx, uint16_t outputPid);

/**
 * @brief	Go into Ad, switch away from the network.
 *		Return the number of TS packets generated in ctx->pkt.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @param[in]	uint16_t uniqueProgramId - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_immediate_out_of_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId);

/**
 * @brief	Go out of Ad break, return back to the network.
 *		Return the number of TS packets generated in ctx->pkt.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @param[in]	uint16_t uniqueProgramId - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_immediate_in_to_network(struct scte35_context_s *ctx, uint16_t uniqueProgramId);

/**
 * @brief	Generate a splice_null() heartbeat packet. This typically keeps the
 *		downstream slicer alive, not specifically in the spec.
 *		Return the number of TS packets generated in ctx->pkt.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_heartbeat(struct scte35_context_s *ctx);

/**
 * @brief	Allow the next event ID to be set, so that SCTE104 translated
 *		packets, that contain their own eventID, we will to honor.
 *		Return the number of TS packets generated in ctx->pkt.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @param[in]	uint32_t eventId - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_set_next_event_id(struct scte35_context_s *ctx, uint32_t eventId);

/* Caller must call scte35_splice_info_section_free() after they're done with the parse result. */
/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	uint8_t *section - Brief description goes here.
 * @param[in]	unsigned int byteCount - Brief description goes here.
 */
struct scte35_splice_info_section_s *scte35_splice_info_section_parse(uint8_t *section, unsigned int byteCount);

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 */
void scet35_splice_info_section_print(struct scte35_splice_info_section_s *s);

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 */
void scte35_splice_info_section_free(struct scte35_splice_info_section_s *s);

/**
 * @brief	Convert SCTE35 to SCTE104.
 * @param[in]	struct scte35_context_s *ctx - Brief description goes here.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 * @param[in]	uint8_t **buf - Brief description goes here.
 * @param[in]	uint16_t *byteCount - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_create_scte104_message(struct scte35_context_s *ctx,
        struct scte35_splice_info_section_s *s, uint8_t **buf, uint16_t *byteCount);

#ifdef __cplusplus
};
#endif

#endif /* SCTE35_H */
