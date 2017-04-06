/*
 * Copyright (c) 2016-2017 Kernel Labs Inc. All Rights Reserved
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
 * @copyright	Copyright (c) 2016-2017 Kernel Labs Inc. All Rights Reserved.
 * @brief	Pack, unpack DVB SCTE35 table sections. Helper functions to create common table types.
 */

#ifndef SCTE35_H
#define SCTE35_H

#include <stdint.h>
#include <libklvanc/vanc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCTE35_COMMAND_TYPE__SPLICE_NULL	0x00
#define SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE	0x04
#define SCTE35_COMMAND_TYPE__SPLICE_INSERT	0x05
#define SCTE35_COMMAND_TYPE__TIME_SIGNAL	0x06
#define SCTE35_COMMAND_TYPE__BW_RESERVATION	0x07
#define SCTE35_COMMAND_TYPE__PRIVATE		0xff

#define SCTE35_TABLE_ID 0xFC

/* Maximum number of extra descriptors that can be associated with an SCTE-35
   splice section */
#define SCTE35_MAX_DESCRIPTORS 64

/* SCTE-35 Sec 10.1, Table 15 */
#define SCTE35_AVAIL_DESCRIPTOR 0x00
#define SCTE35_DTMF_DESCRIPTOR 0x01
#define SCTE35_SEGMENTATION_DESCRIPTOR 0x02
#define SCTE35_TIME_DESCRIPTOR 0x03

/**
 * @brief	TODO - Brief description goes here.
 */
struct scte35_break_duration_s
{
	uint8_t  auto_return;
	uint64_t duration;
};

/* SCTE-35 Sec 10.3.1 */
struct splice_descriptor_avail
{
	uint32_t provider_avail_id;
};

/* SCTE-35 Sec 10.3.2 */
struct splice_descriptor_dtmf
{
	uint8_t preroll;
	uint8_t dtmf_count;
	uint8_t dtmf_char[8];
};

/* SCTE-35 Sec 10.3.3 */
struct splice_descriptor_segmentation
{
	uint32_t event_id;
	uint8_t event_cancel_indicator;
	uint8_t program_segmentation_flag;
	uint8_t segmentation_duration_flag;
	uint8_t delivery_not_restricted_flag;
	uint8_t web_delivery_allowed_flag;
	uint8_t no_regional_blackout_flag;
	uint8_t archive_allowed_flag;
	uint8_t device_restrictions;
	uint64_t segmentation_duration;
	uint8_t upid_type;
	uint8_t upid_length;
	uint8_t upid[255];
	uint8_t type_id;
	uint8_t segment_num;
	uint8_t segments_expected;
	uint8_t sub_segment_num;
	uint8_t sub_segments_expected;
};

/* SCTE-35 Sec 10.3.4 */
struct splice_descriptor_time
{
	uint64_t TAI_seconds;
	uint32_t TAI_ns;
	uint16_t UTC_offset;
};

/* Used for protocol extensions (e.g. arbitrary/new descriptors not in current spec) */
struct splice_descriptor_arbitrary
{
	uint8_t descriptor_data_length;
	uint8_t descriptor_data[255];
};


struct splice_descriptor {
	uint8_t splice_descriptor_tag;
	uint8_t descriptor_length;
	uint32_t identifier;
	union {
		struct splice_descriptor_avail avail_data;
		struct splice_descriptor_dtmf dtmf_data;
		struct splice_descriptor_segmentation seg_data;
		struct splice_descriptor_time time_data;
		struct splice_descriptor_arbitrary extra_data;
	};
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

struct scte35_splice_private_s
{
	uint32_t identifier;
	uint8_t private_length;
	uint8_t private_byte[255];
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
		struct scte35_splice_time_s time_signal;
		struct scte35_splice_private_s private_command;
	};

	uint16_t descriptor_loop_count;
	struct splice_descriptor *descriptors[SCTE35_MAX_DESCRIPTORS];

	/* Raw data (for debugging/reference only) */
	uint16_t descriptor_loop_length;
	uint8_t  *splice_descriptor;

	uint32_t e_crc_32;
	uint32_t crc_32;
	uint32_t crc_32_is_valid;
};

/* This is used for passing around lists of splices */
#define MAX_SPLICES 64
struct splice_entries
{
	uint32_t num_splices;
	uint8_t  *splice_entry[MAX_SPLICES];
	uint32_t splice_size[MAX_SPLICES];
};

int scte35_generate_from_scte104(struct packet_scte_104_s *pkt, struct splice_entries *results,
				 uint64_t pts);

/**
 * @brief	Go into Ad, switch away from the network.
 *		Create a buffer dst containing the DVB section table, and return it to caller. Caller must free after use.
 * @param[in]	uint16_t uniqueProgramId - Brief description goes here.
 * @param[in]	uint32_t eventId - Brief description goes here.
 * @param[out]	uint8_t **dst - New allocation contacting the SCTE35 constructed section.
 * @param[out]	uint32_t **dstLengthBytes - Number of bytes at dst
 * @param[in]	uint32_t immediate - Perform an immediate switch away from network?
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_out_of_network(uint16_t uniqueProgramId, uint32_t eventId,
				   uint8_t **dst, uint32_t *dstLengthBytes, uint32_t immediate,
				   uint16_t availNum, uint16_t availsExpected);

/**
 * @brief	Go into Ad, switch away from the network for a period of time.
 *		Create a buffer dst containing the DVB section table, and return it to caller. Caller must free after use.
 * @param[in]	uint16_t uniqueProgramId - Brief description goes here.
 * @param[in]	uint32_t eventId - Brief description goes here.
 * @param[in]	uint32_t duration - in 1/100ths of seconds.
 * @param[in]	int autoReturn - Automatically return to network after break?
 * @param[out]	uint8_t **dst - New allocation contacting the SCTE35 constructed section.
 * @param[out]	uint32_t **dstLengthBytes - Number of bytes at dst
 * @param[in]	uint32_t immediate - Perform an immediate switch away from network?
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_out_of_network_duration(uint16_t uniqueProgramId, uint32_t eventId, uint32_t duration, int autoReturn,
					    uint8_t **dst, uint32_t *dstLengthBytes, uint32_t immediate,
					    uint16_t availNum, uint16_t availsExpected);

/**
 * @brief	Go out of Ad break, return back to the network.
 *		Create a buffer dst containing the DVB section table, and return it to caller. Caller must free after use.
 * @param[in]	uint16_t uniqueProgramId - Brief description goes here.
 * @param[in]	uint32_t eventId - Brief description goes here.
 * @param[out]	uint8_t **dst - New allocation contacting the SCTE35 constructed section.
 * @param[out]	uint32_t **dstLengthBytes - Number of bytes at dst
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_generate_immediate_in_to_network(uint16_t uniqueProgramId, uint32_t eventId,
					    uint8_t **dst, uint32_t *dstLengthBytes,
					    uint16_t availNum, uint16_t availsExpected);

/**
 * @brief	Serialize object si out to buffer as a scte35 table section.
 * @param[in]	struct scte35_splice_info_section_s *si - object.
 * @param[in]	uint8_t *buffer - Destination.
 * @param[out]	uint32_t buffer_length_bytes - Maximum size of buffer
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_splice_info_section_packTo(struct scte35_splice_info_section_s *si, uint8_t *buffer, uint32_t buffer_length_bytes);

/**
 * @brief	Read buffer and de-serialize out to struct si.
 * @param[in]	struct scte35_splice_info_section_s *si - object.
 * @param[in]	uint8_t *src - Source of a scte35 table section..
 * @param[out]	uint32_t srcLengthBytes - Maximum size of buffer
 * @return	0 - Success
 * @return	< 0 - Error
 */
ssize_t scte35_splice_info_section_unpackFrom(struct scte35_splice_info_section_s *si,
	uint8_t *src, uint32_t srcLengthBytes);

/**
 * @brief	TODO - Brief description goes here.
 *              Caller must call scte35_splice_info_section_free() after they're done with the parse result.
 * @param[in]	uint8_t *section - Brief description goes here.
 * @param[in]	unsigned int byteCount - Brief description goes here.
 */
struct scte35_splice_info_section_s *scte35_splice_info_section_parse(uint8_t *section, unsigned int byteCount);

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 */
void scte35_splice_info_section_print(struct scte35_splice_info_section_s *s);

/**
 * @brief	Allocate a clean structure and populate any mandatory fixed fields.
 * @param[in]	uint8_t command_type - Eg. SCTE35_COMMAND_TYPE__SPLICE_NULL
 */
struct scte35_splice_info_section_s *scte35_splice_info_section_alloc(uint8_t command_type);

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 */
void scte35_splice_info_section_free(struct scte35_splice_info_section_s *s);

/**
 * @brief	Convert SCTE35 to SCTE104.
 * @param[in]	struct scte35_splice_info_section_s *s - Brief description goes here.
 * @param[in]	uint8_t **buf - Brief description goes here.
 * @param[in]	uint16_t *byteCount - Brief description goes here.
 * @param[in]	uint64_t pts - Current PTS of SCTE-35 splice (used for SCTE-104 pre-roll calculation)
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_create_scte104_message(struct scte35_splice_info_section_s *s, uint8_t **buf,
				  uint16_t *byteCount, uint64_t pts);

/**
 * @brief	Return a human readable label for the command type. Eg. SPLICE_NULL.
 * @param[in]	uint32_t command_type - A valid command_type code according to the spec.
 * @return	"Reserved" or a valid description. A valid string is guaranteed to be returned.
 */
const char *scte35_description_command_type(uint32_t command_type);

int alloc_SCTE_35_splice_descriptor(uint8_t tag, struct splice_descriptor **desc);

#ifdef __cplusplus
};
#endif

#endif /* SCTE35_H */
