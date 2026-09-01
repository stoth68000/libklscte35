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
 *
 * SPEC COMPLIANCE SUMMARY (checked against ANSI/SCTE 35:2019, "Digital
 * Program Insertion Cueing Message for Cable"; section numbers below refer
 * to that edition unless noted). This is a deliberate subset of the spec,
 * not a full implementation. Each GAP/ASSUMPTION callout below has a
 * matching, more detailed comment at the point in the .c files where it
 * actually applies -- this block is the index.
 *
 * GAPS (spec-defined behavior this library does not implement):
 *
 *  - splice_schedule() (Sec 9.7.2, splice_command_type 0x04) is not
 *    implemented at all. Both scte35_splice_info_section_unpackFrom() and
 *    scte35_splice_info_section_packTo() return -KLSCTE35_ERR_NOTSUPPORTED
 *    for it. See src/scte35.c.
 *
 *  - Component splicing in splice_insert() (Sec 9.7.3, the
 *    program_splice_flag == 0 case: per-component splice_time() loop) is
 *    not implemented. See struct scte35_splice_insert_s below and
 *    src/scte35.c (search "component_count").
 *
 *  - Encrypted messages are not supported, and packing vs. parsing handle
 *    that asymmetrically: scte35_splice_info_section_packTo() rejects any
 *    nonzero protocol_version, encrypted_packet or encryption_algorithm
 *    outright, but scte35_splice_info_section_unpackFrom() does not -- it
 *    silently parses the command/descriptor loop as if the section were
 *    unencrypted, which for a genuinely encrypted section means
 *    misinterpreting ciphertext as a real command. alignment_stuffing()
 *    and E_CRC_32 (Sec 9.6, present only when encrypted_packet == 1) are
 *    never produced or consumed either way; e_crc_32 in struct
 *    scte35_splice_info_section_s is always 0. Callers that need to
 *    detect an encrypted section on the parse path must check
 *    si->encrypted_packet themselves. See src/scte35.c,
 *    scte35_splice_info_section_packTo()/_unpackFrom().
 *
 *  - segmentation_descriptor() sub_segment_num/sub_segments_expected
 *    (Sec 10.3.3, present when segmentation_type_id is a Provider/
 *    Distributor Placement Opportunity Start, 0x34 or 0x36) are declared
 *    in struct splice_descriptor_segmentation below but are never read or
 *    written on the wire. See src/scte35.c,
 *    scte35_append_segmentation()/scte35_parse_segmentation().
 *
 *  - segmentation_upid() (Sec 10.3.3.1) is stored and round-tripped as an
 *    opaque byte blob for every upid_type. Type-specific structure is not
 *    decoded: fixed-length UPID types (e.g. UMID, UUID) aren't validated
 *    against their mandated length, and upid_type 0x0D (MID, a nested
 *    list of sub-UPIDs) is not expanded into its component UPIDs -- the
 *    concatenated sub-UPID bytes are exposed as-is. See
 *    struct splice_descriptor_segmentation below.
 *
 *  - segmentation_event_id_compliance_indicator and
 *    splice_event_id_compliance_indicator, added in later SCTE-35
 *    revisions by repurposing one bit of the "reserved" field that
 *    follows event_cancel_indicator in segmentation_descriptor() and
 *    splice_insert(), are not recognized -- this library always treats
 *    that entire field as reserved and discards it.
 *
 * ASSUMPTIONS (choices made where the spec is ambiguous, silent, or where
 * this library deliberately narrows/deviates from recommended behavior):
 *
 *  - protocol_version (Sec 9.6): the spec's intent for forward
 *    compatibility is that a decoder encountering an unknown protocol
 *    version should ignore the section rather than treat it as an error.
 *    This library instead hard-rejects any splice_info_section() with
 *    protocol_version != 0 when *packing* one -- but, inconsistently,
 *    _unpackFrom() doesn't check it at all on the parse side and will
 *    happily attempt to decode a section with a nonzero protocol_version
 *    as if it were 0 (see the encryption bullet above for the related
 *    parse-side gap).
 *
 *  - segmentation_descriptor() delivery restriction flags (Sec 10.3.3):
 *    when delivery_not_restricted_flag == 1, web_delivery_allowed_flag,
 *    no_regional_blackout_flag, archive_allowed_flag and
 *    device_restrictions are not present on the wire (just reserved
 *    bits). This library fabricates values for them on parse
 *    (all "allowed" / device_restrictions = 0x03 "None") so callers
 *    always see a fully-populated struct; that's an interpretation of
 *    "not restricted", not a value the bitstream actually carries.
 *
 *  - Unrecognized splice_descriptor_tag values (with or without the CUEI
 *    identifier) are treated as opaque/private and passed through as raw
 *    bytes via struct splice_descriptor_arbitrary, rather than rejected.
 *    This matches the spec's intended extensibility model for
 *    descriptors, so it's listed here as a documented assumption rather
 *    than a gap.
 *
 *  - SCTE35_MAX_DESCRIPTORS (64) and the various fixed-size byte arrays
 *    below (e.g. upid[255], private_byte[255]) are practical caps chosen
 *    to match the maximum a single 8-bit length field can express (255)
 *    or a generous real-world descriptor count -- they are not values
 *    mandated by the spec, which places no fixed upper bound on
 *    descriptor_loop_count itself.
 */

#ifndef SCTE35_H
#define SCTE35_H

#include <stdint.h>
#include <sys/types.h>

/* We use an extern here so we can build successfully even if libklvanc isn't available */
extern struct klvanc_packet_scte_104_s *pkt;

#ifdef __cplusplus
extern "C" {
#endif

/* Possible error return values */
#define KLSCTE35_ERR_NOMEM 1
#define KLSCTE35_ERR_INVAL 2
#define KLSCTE35_ERR_NOTSUPPORTED 3

#define SCTE35_COMMAND_TYPE__SPLICE_NULL	0x00
/* GAP: recognized as a valid command_type (e.g. by scte35_splice_info_section_
   alloc()) but splice_schedule() itself (Sec 9.7.2) is not implemented --
   scte35_splice_info_section_packTo()/_unpackFrom() both return
   -KLSCTE35_ERR_NOTSUPPORTED for it in src/scte35.c. */
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
struct component_info
{
	uint8_t component_tag;
	uint64_t pts_offset;
};

struct splice_descriptor_segmentation
{
	uint32_t event_id;
	uint8_t event_cancel_indicator;
	/* GAP: newer SCTE-35 revisions add segmentation_event_id_compliance_indicator
	   as one bit of the 7 reserved bits that follow event_cancel_indicator on the
	   wire. Not represented here -- src/scte35.c reads/writes all 7 bits as pure
	   reserved (see scte35_parse_segmentation()/scte35_append_segmentation()). */
	uint8_t program_segmentation_flag;
	uint8_t segmentation_duration_flag;
	uint8_t delivery_not_restricted_flag;
	/* ASSUMPTION: when delivery_not_restricted_flag == 1, the next 3 flags and
	   device_restrictions are not actually present on the wire (just reserved
	   bits per Sec 10.3.3). src/scte35.c's parser fabricates "fully allowed" /
	   device_restrictions = 0x03 in that case so this struct is always fully
	   populated -- that's an interpretation, not a transmitted value. */
	uint8_t web_delivery_allowed_flag;
	uint8_t no_regional_blackout_flag;
	uint8_t archive_allowed_flag;
	uint8_t device_restrictions;
	uint8_t component_count;
	struct component_info components[255];
	uint64_t segmentation_duration;
	uint8_t upid_type;
	uint8_t upid_length;
	/* GAP: segmentation_upid() (Sec 10.3.3.1) is stored here as an opaque byte
	   blob regardless of upid_type. Fixed-length UPID types (e.g. upid_type
	   0x04 UMID = 32 bytes, 0x10 UUID = 16 bytes) are not validated against
	   their mandated length, and upid_type 0x0D (MID -- a nested list of
	   sub-UPIDs, each with its own upid_type/upid_length/upid) is not expanded;
	   its concatenated sub-UPID bytes are exposed here exactly as received. */
	uint8_t upid[255];
	uint8_t type_id;
	uint8_t segment_num;
	uint8_t segments_expected;
	/* GAP: these two fields exist in the struct but src/scte35.c never reads or
	   writes them on the wire, even when type_id is 0x34 or 0x36 (Provider/
	   Distributor Placement Opportunity Start), the case the spec defines them
	   for (Sec 10.3.3). They are always 0 after a parse, and packing never
	   emits them regardless of what a caller sets here. See "FIXME: Sub
	   segment num" in scte35_parse_segmentation()/scte35_append_segmentation(). */
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
	/* GAP: as with segmentation_descriptor(), later SCTE-35 revisions add a
	   splice_event_id_compliance_indicator bit to the reserved field that
	   follows splice_event_cancel_indicator. Not represented -- treated as
	   pure reserved on both parse and pack. */
	uint8_t  out_of_network_indicator;
	uint8_t  program_splice_flag;
	uint8_t  duration_flag;
	uint8_t  splice_immediate_flag;
	struct   scte35_splice_time_s splice_time;

	/* GAP: Sec 9.7.3 defines component splicing when program_splice_flag == 0:
	   a component_count(8) followed by that many {component_tag(8), splice_time()}
	   entries, letting a splice apply to specific elementary streams instead of
	   the whole program. This library does not implement it -- when
	   program_splice_flag == 0, scte35_splice_info_section_unpackFrom() reads
	   and discards a single fixed 8-bit field instead of the real
	   component_count + per-component loop, and
	   scte35_splice_info_section_packTo() always writes that field as 0. The
	   component_count/components[] fields below are consequently never
	   populated by this library; program_splice_flag == 0 input round-trips
	   incorrectly. See src/scte35.c (search "component_count"). */
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
	/* ASSUMPTION: Sec 9.6 intends protocol_version as a forward-compatibility
	   field -- a decoder seeing a value it doesn't recognize should ignore the
	   section, not reject the stream outright. This library instead hard-fails
	   (-KLSCTE35_ERR_INVAL) any section where protocol_version != 0, on both
	   parse and pack. */
	uint8_t  protocol_version;
	/* GAP: encrypted_packet/encryption_algorithm are read/written, but a
	   nonzero value on either is always rejected -- encrypted messages
	   (Sec 9.6, including alignment_stuffing() and E_CRC_32) are not
	   supported at all. See scte35_splice_info_section_packTo()/
	   _unpackFrom() in src/scte35.c. */
	uint8_t  encrypted_packet;
	uint8_t  encryption_algorithm;
	uint64_t pts_adjustment;
	uint8_t  cw_index;
	uint16_t tier;
	uint16_t splice_command_length;
	uint8_t  splice_command_type;
	/* GAP: no member here for splice_schedule() (Sec 9.7.2,
	   splice_command_type 0x04) -- it isn't implemented, see
	   SCTE35_COMMAND_TYPE__SPLICE_SCHEDULE below. bandwidth_reservation()
	   correctly has no member since Sec 9.7.5 defines it as an empty
	   structure. */
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

	/* GAP: always 0. E_CRC_32 (Sec 9.6) only exists in encrypted sections,
	   which this library doesn't support -- see encrypted_packet above. */
	uint32_t e_crc_32;
	uint32_t crc_32;
	uint32_t crc_32_is_valid;

	/* User can optionally set this value to represent the
	 * video PTS time, if they have it, of the last video packet
	 * received on the corresponding pid. If this is non-zero,
	 * during calls to scte35_splice_info_section_print(), the framework
	 * will augment the output, computing current vs preroll trigger times,
	 * and show the information in the output.
	 * The value defaults to zero, and is only interpreted when non-zero.
	 */
	uint64_t user_current_video_pts;
};

/* This is used for passing around lists of splices */
#define MAX_SPLICES 64
struct splice_entries
{
	uint32_t num_splices;
	uint8_t  *splice_entry[MAX_SPLICES];
	uint32_t splice_size[MAX_SPLICES];
};

int scte35_generate_from_scte104(struct klvanc_packet_scte_104_s *pkt, struct splice_entries *results,
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
					      const uint8_t *src, uint32_t srcLengthBytes);

/**
 * @brief	TODO - Brief description goes here.
 *              Caller must call scte35_splice_info_section_free() after they're done with the parse result.
 * @param[in]	uint8_t *section - Brief description goes here.
 * @param[in]	unsigned int byteCount - Brief description goes here.
 */
struct scte35_splice_info_section_s *scte35_splice_info_section_parse(const uint8_t *section, unsigned int byteCount);

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
 * @brief	Convert SCTE35 to JSON representation.
 * @param[in]	struct scte35_splice_info_section_s *s - SCTE-35 packet
 * @param[in]	char **buf - NULL terminated string will be allocated and pointer returned here
 * @param[in]	uint16_t *byteCount - Length of buf pointer will be returned here
 * @param[in]	uint64_t pts - Current PTS of SCTE-35 splice (used for SCTE-104 pre-roll calculation)
 * @param[in]	int compressed - Request the output string in a compressed format (else its pretty)
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_create_json_message(struct scte35_splice_info_section_s *s, char **buf,
			       uint16_t *byteCount, int compressed);

/**
 * @brief	Convert SCTE35 to Base64 representation.
 * @param[in]	struct scte35_splice_info_section_s *s - SCTE-35 packet
 * @param[out]	char **buf - NULL terminated string will be allocated and pointer returned here
 * @param[out]	uint16_t *byteCount - Length of buf pointer will be returned here
 * @return	0 - Success
 * @return	< 0 - Error
 */
int scte35_create_base64_message(struct scte35_splice_info_section_s *s, char **buf,
				 uint32_t *byteCount);

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
