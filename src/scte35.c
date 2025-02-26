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

/* Forward declarations */
int scte35_parse_avail(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength);
int scte35_parse_dtmf(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength);
int scte35_parse_segmentation(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength);
int scte35_parse_time(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength);
int scte35_parse_descriptor(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength);

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
	/* SCTE-35:2019 Table 6 */
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

static const char *scte35_description_identifier_name(uint32_t id)
{
	switch(id) {
	case 0x43554549: return "SCTE"; /* CUEI */
	default: return "Unknown";
	}
}

static const char *scte35_description_descriptor_name(uint8_t descriptor)
{
	/* SCTE-35:2019 Table 15 */
	switch(descriptor) {
	case SCTE35_AVAIL_DESCRIPTOR: return "AVAIL";
	case SCTE35_DTMF_DESCRIPTOR: return "DTMF";
	case SCTE35_SEGMENTATION_DESCRIPTOR: return "SEGMENTATION";
	case SCTE35_TIME_DESCRIPTOR: return "TIME";
	default: return "Unknown";
	}
}

static const char *scte35_seg_device_restrictions(uint8_t val) {
	/* SCTE-35:2019 Table 20 */
	switch(val) {
	case 0x00: return "Restrict Group 0";
	case 0x01: return "Restrict Group 1";
	case 0x02: return "Restrict Group 2";
	case 0x03: return "None";
	default:   return "Unknown";
	}
}

static const char *scte35_seg_upid_type(uint8_t upid_type) {
	/* SCTE-35:2019 Table 21 */
	switch(upid_type) {
	case 0x00: return "Not Used";
	case 0x01: return "User Defined (Deprecated)";
	case 0x02: return "ISCI (Deprecated)";
	case 0x03: return "Ad-ID (Advertising Digital Identification, LLC)";
	case 0x04: return "UMID (SMPTE 330)";
	case 0x05: return "ISAN (Deprecated)";
	case 0x06: return "ISAN (Formerly V-ISAN)";
	case 0x07: return "TID (Tribune Media Systems)";
	case 0x08: return "TI (AiringID, formerly Turner ID)";
	case 0x09: return "ADI (CableLabs)";
	default: return "Reserved";
	}
}

static const char *scte35_seg_type_id(uint8_t type_id) {
	/* SCTE-35:2019 Table 22 */
	switch(type_id) {
	case 0x00: return "Not indicated";
	case 0x01: return "Content Identification";
	case 0x10: return "Program Start";
	case 0x11: return "Program End";
	case 0x12: return "Program Early Termination";
	case 0x13: return "Program Breakaway";
	case 0x14: return "Program Resumption";
	case 0x15: return "Program Runover Planned";
	case 0x16: return "Program Runover Unplanned";
	case 0x17: return "Program Overlap Start";
	case 0x18: return "Program Blackout Override";
	case 0x19: return "Program Start - In Progress";
	case 0x20: return "Chapter Start";
	case 0x21: return "Chapter End";
	case 0x22: return "Break Start";
	case 0x23: return "Break End";
	case 0x24: return "Opening Credit Start";
	case 0x25: return "Opening Credit End";
	case 0x26: return "Closing Credit Start";
	case 0x27: return "Closing Credit End";
	case 0x30: return "Provider Advertisement Start";
	case 0x31: return "Provider Advertisement End";
	case 0x32: return "Distributor Advertisement Start";
	case 0x33: return "Distributor Advertisement End";
	case 0x34: return "Provider Placement Opportunity Start";
	case 0x35: return "Provider Placement Opportunity End";
	case 0x36: return "Distributor Placement Opportunity Start";
	case 0x37: return "Distributor Placement Opportunity End";
	case 0x38: return "Provider Overlay Placement Opportunity Start";
	case 0x39: return "Provider Overlay Placement Opportunity End";
	case 0x3A: return "Distributor Overlay Placement Opportunity Start";
	case 0x3B: return "Distributor Overlay Placement Opportunity End";
	case 0x40: return "Unscheduled Event Start";
	case 0x41: return "Unscheduled Event End";
	case 0x50: return "Network Start";
	case 0x51: return "Network End";
	default:   return "Unknown";
	}
}

static const char *scte35_encryption_algorithms(uint8_t val) {
	/* SCTE-35:2019 Table 27 */
	switch(val) {
	case 0x00: return "No encryption";
	case 0x01: return "DES - ECB mode";
	case 0x02: return "DES - CBC mode";
	case 0x03: return "Triple DES EDE3 - ECB mode";
	default:
		if (val >= 4 && val <= 31)
			return "Reserved";
		else
			return "User Private";
	}
}

int scte35_generate_out_of_network_duration(uint16_t uniqueProgramId, uint32_t eventId, uint32_t duration, int autoReturn,
					    uint8_t **dst, uint32_t *dstLengthBytes, uint32_t immediate, uint16_t availNum,
					    uint16_t availsExpected)
{
	struct scte35_splice_info_section_s *si = scte35_splice_info_section_alloc(SCTE35_COMMAND_TYPE__SPLICE_INSERT);
	if (si == NULL)
		return -KLSCTE35_ERR_NOMEM;
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
		return -KLSCTE35_ERR_NOMEM;
	}

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -KLSCTE35_ERR_INVAL;
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
		return -KLSCTE35_ERR_NOMEM;
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
		return -KLSCTE35_ERR_NOMEM;
	}

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -KLSCTE35_ERR_INVAL;
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
		return -KLSCTE35_ERR_NOMEM;
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
		return -KLSCTE35_ERR_NOMEM;
	}

	ssize_t packedLength = scte35_splice_info_section_packTo(si, buf, l);
	if (packedLength < 0) {
		free(buf);
		scte35_splice_info_section_free(si);
		return -KLSCTE35_ERR_INVAL;
	}

	*dst = buf;
	*dstLengthBytes = packedLength;
	scte35_splice_info_section_free(si);

	return 0;
}

#define SHOW_LINE_U32(indent, field) printf("%s%s = 0x%x (%d)\n", indent, #field, field, field);
#define SHOW_LINE_U32_SUFFIX(indent, field, suffix) printf("%s%s = 0x%x (%d) [%s]\n", indent, #field, field, field, suffix);
#define SHOW_LINE_U64(indent, field) printf("%s%s = %" PRIu64 "\n", indent, #field, field);
#define SHOW_LINE_U64_NOCR(indent, field) printf("%s%s = %" PRIu64, indent, #field, field);
void scte35_splice_info_section_print(struct scte35_splice_info_section_s *s)
{
	SHOW_LINE_U32("", s->table_id);
	SHOW_LINE_U32("", s->section_syntax_indicator);
	SHOW_LINE_U32("", s->private_indicator);
	SHOW_LINE_U32("", s->section_length);
	SHOW_LINE_U32("", s->protocol_version);
	SHOW_LINE_U32("", s->encrypted_packet);
	SHOW_LINE_U32_SUFFIX("", s->encryption_algorithm, scte35_encryption_algorithms(s->encryption_algorithm));
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
			if (!s->user_current_video_pts) {
				SHOW_LINE_U64("\t", s->splice_insert.splice_time.pts_time);
			} else {
				SHOW_LINE_U64_NOCR("\t", s->splice_insert.splice_time.pts_time);
				printf( ", begins in %" PRIu64 " (ms)\n", (s->splice_insert.splice_time.pts_time - s->user_current_video_pts) / 90);
			}
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
		if (s->time_signal.time_specified_flag == 1) {
			if (!s->user_current_video_pts) {
				SHOW_LINE_U64("", s->time_signal.pts_time);
			} else {
				SHOW_LINE_U64_NOCR("", s->time_signal.pts_time);
				printf( ", begins in %" PRIu64 " (ms)\n", (s->time_signal.pts_time - s->user_current_video_pts) / 90);
			}
		}
	} else
	if (s->splice_command_type == SCTE35_COMMAND_TYPE__BW_RESERVATION) {
		/* Nothing to do */
	} else {
		fprintf(stderr, "No dump support for command type 0x%02x\n", s->splice_command_type);
	}

        /* We don't support descriptor parsing. */
	SHOW_LINE_U32("", s->descriptor_loop_length);
	hexdump(s->splice_descriptor, s->descriptor_loop_length, 16);

        for (int i = 0; i < s->descriptor_loop_count; i++) {
		struct splice_descriptor *sd = s->descriptors[i];
		printf("Descriptor:\n");
		SHOW_LINE_U32_SUFFIX("\t", sd->splice_descriptor_tag,
				     scte35_description_descriptor_name(sd->splice_descriptor_tag));
		SHOW_LINE_U32("\t", sd->descriptor_length);
		SHOW_LINE_U32_SUFFIX("\t", sd->identifier,
				     scte35_description_identifier_name(sd->identifier));
		switch (sd->identifier) {
		case 0x43554549: /* CUEI */
			switch (sd->splice_descriptor_tag) {
			case SCTE35_AVAIL_DESCRIPTOR:
				SHOW_LINE_U32("\t", sd->avail_data.provider_avail_id);
				break;
			case SCTE35_DTMF_DESCRIPTOR:
				SHOW_LINE_U32("\t", sd->dtmf_data.preroll);
				SHOW_LINE_U32("\t", sd->dtmf_data.dtmf_count);
				printf("\tsd->dtmf_data.dtmf_char = [");
				for (int j = 0; j < sd->dtmf_data.dtmf_count; j++) {
					printf("%c", sd->dtmf_data.dtmf_char[i]);
				}
				printf("]\n");
				break;
			case SCTE35_SEGMENTATION_DESCRIPTOR:
				SHOW_LINE_U32("\t", sd->seg_data.event_id);
				SHOW_LINE_U32("\t", sd->seg_data.event_cancel_indicator);
				if (sd->seg_data.event_cancel_indicator == 0) {
					SHOW_LINE_U32("\t", sd->seg_data.program_segmentation_flag);
					SHOW_LINE_U32("\t", sd->seg_data.segmentation_duration_flag);
					SHOW_LINE_U32("\t", sd->seg_data.delivery_not_restricted_flag);
					SHOW_LINE_U32("\t", sd->seg_data.web_delivery_allowed_flag);
					SHOW_LINE_U32("\t", sd->seg_data.no_regional_blackout_flag);
					SHOW_LINE_U32("\t", sd->seg_data.archive_allowed_flag);
					SHOW_LINE_U32_SUFFIX("\t", sd->seg_data.device_restrictions,
							     scte35_seg_device_restrictions(sd->seg_data.device_restrictions));
					if (sd->seg_data.program_segmentation_flag == 0) {
						SHOW_LINE_U32("\t", sd->seg_data.component_count);
						for (int j = 0; j < sd->seg_data.component_count; j++) {
							SHOW_LINE_U32("\t", sd->seg_data.components[j].component_tag);
							SHOW_LINE_U64("\t", sd->seg_data.components[j].pts_offset);
						}
					}
					if (sd->seg_data.segmentation_duration_flag) {
						SHOW_LINE_U64("\t", sd->seg_data.segmentation_duration);
					}
					SHOW_LINE_U32_SUFFIX("\t", sd->seg_data.upid_type,
							     scte35_seg_upid_type(sd->seg_data.upid_type));
					SHOW_LINE_U32("\t", sd->seg_data.upid_length);
					if (sd->seg_data.upid_length > 0) {
						printf("\t");
						hexdump(sd->seg_data.upid, sd->seg_data.upid_length, 16);
					}
					SHOW_LINE_U32_SUFFIX("\t", sd->seg_data.type_id,
							     scte35_seg_type_id(sd->seg_data.type_id));
					SHOW_LINE_U32("\t", sd->seg_data.segment_num);
					SHOW_LINE_U32("\t", sd->seg_data.segments_expected);
				}
				break;
			case SCTE35_TIME_DESCRIPTOR:
				SHOW_LINE_U64("\t", sd->time_data.TAI_seconds);
				SHOW_LINE_U32("\t", sd->time_data.TAI_ns);
				SHOW_LINE_U32("\t", sd->time_data.UTC_offset);
				break;
			default:
				break;
			}
			break;
		default:
			printf("\tUnknown identifier, cannot parser further\n");
			break;
		}
        }

	SHOW_LINE_U32("", s->e_crc_32);
	SHOW_LINE_U32("", s->crc_32);
	SHOW_LINE_U32("", s->crc_32_is_valid);
}

/* Take the raw descriptor bytes and convert into parseable structs */
ssize_t scte35_parse_descriptors(struct scte35_splice_info_section_s *si, uint8_t *desc, uint32_t descLengthBytes)
{
	uint8_t buf[255];
	struct splice_descriptor *sd;
	unsigned int bytesRead = 0;
	int ret;
#if 0
	printf("SCTE-35 descriptors:\n");
	for (size_t i = 0; i < descLengthBytes; i++)
		printf("%02x ", desc[i]);
	printf("\n");
#endif
	struct klbs_context_s *bs = klbs_alloc();
	klbs_read_set_buffer(bs, desc, descLengthBytes);

	while (bytesRead < descLengthBytes) {
		uint8_t desc_tag;
		uint8_t priv_len;

		if (klbs_get_buffer_size(bs) - klbs_get_byte_count(bs) < 6) {
			/* Insufficient bytes remaining to parse */
			break;
		}

		/* SCTE 35 Section 10.2, Table 16 */
		desc_tag = klbs_read_bits(bs, 8); /* Splice Descriptor Tag */
		ret = alloc_SCTE_35_splice_descriptor(desc_tag, &sd);
		if (ret != 0)
			break;

		sd->descriptor_length = klbs_read_bits(bs, 8); /* Descriptor Length */
		sd->identifier = klbs_read_bits(bs, 32);
		priv_len = sd->descriptor_length - 4;
		for (int i = 0; i < priv_len; i++) {
			buf[i] = klbs_read_bits(bs, 8); /* Identifier + Private Bytes */
		}

		switch (sd->identifier) {
		case 0x43554549:
			/* SCTE */
			switch (sd->splice_descriptor_tag) {
			case SCTE35_AVAIL_DESCRIPTOR:
				ret = scte35_parse_avail(sd, buf, priv_len);
				break;
			case SCTE35_DTMF_DESCRIPTOR:
				ret = scte35_parse_dtmf(sd, buf, priv_len);
				break;
			case SCTE35_SEGMENTATION_DESCRIPTOR:
				ret = scte35_parse_segmentation(sd, buf, priv_len);
				break;
			case SCTE35_TIME_DESCRIPTOR:
				ret = scte35_parse_time(sd, buf, priv_len);
				break;
			default:
				ret = scte35_parse_descriptor(sd, buf, priv_len);
				break;
			}
			break;
		default:
			ret = scte35_parse_descriptor(sd, buf, priv_len);
		}

		if (ret == 0) {
			si->descriptors[si->descriptor_loop_count++] = sd;
		} else {
			free(sd);
		}

		bytesRead += (sd->descriptor_length + 2);
	}

	klbs_free(bs);

	return 0;

}

ssize_t scte35_splice_info_section_unpackFrom(struct scte35_splice_info_section_s *si, const uint8_t *src, uint32_t srcLengthBytes)
{
	uint32_t v;

	if ((!si) || (!src) || (srcLengthBytes == 0))
		return -KLSCTE35_ERR_INVAL;

	struct klbs_context_s *bs = klbs_alloc();
	klbs_read_set_buffer(bs, (uint8_t *)src, srcLengthBytes);

	si->table_id = klbs_read_bits(bs, 8);
	if (si->table_id != SCTE35_TABLE_ID) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	si->section_syntax_indicator = klbs_read_bits(bs, 1);
	if (si->section_syntax_indicator != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	si->private_indicator = klbs_read_bits(bs, 1);
	if (si->private_indicator != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_read_bits(bs, 2); /* Reserved */

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
		klbs_free(bs);
		return -KLSCTE35_ERR_NOTSUPPORTED;
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
			if (v != 0x3f) {
				klbs_free(bs);
				return -KLSCTE35_ERR_INVAL;
			}
			si->time_signal.pts_time = klbs_read_bits(bs, 33);
		} else {
			v = klbs_read_bits(bs, 7); /* Reserved */
			if (v != 0x7f) {
				klbs_free(bs);
				return -KLSCTE35_ERR_INVAL;
			}
		}
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__BW_RESERVATION) {
		/* Nothing to do */
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__PRIVATE) {
		si->private_command.identifier = klbs_read_bits(bs, 32);
		si->private_command.private_length = si->splice_command_length - 4;
		for (int i = 0; i < si->private_command.private_length; i++) {
			si->private_command.private_byte[i] = klbs_read_bits(bs, 8);
		}
	} else {
		klbs_free(bs);
		return -KLSCTE35_ERR_NOTSUPPORTED;
	}

	int posb = klbs_get_byte_count(bs);
	if (si->splice_command_length != 0xfff) {
		/* If we deserialized a packet which had the reserved value 0xfff,
		   pass that through in packets we generate for consistency.  See
		   Sec 9.6 description of "splice_command_length" */
		si->splice_command_length = posb - posa;
	}

	si->descriptor_loop_length = klbs_read_bits(bs, 16);
	if (si->descriptor_loop_length) {
		si->splice_descriptor = malloc(si->descriptor_loop_length);
		if (si->splice_descriptor == NULL) {
			klbs_free(bs);
			return -KLSCTE35_ERR_NOMEM;
		}
		for (int i = 0; i < si->descriptor_loop_length; i++) {
			si->splice_descriptor[i] = klbs_read_bits(bs, 8);
		}
		scte35_parse_descriptors(si, si->splice_descriptor,
					 si->descriptor_loop_length);
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

struct scte35_splice_info_section_s *scte35_splice_info_section_parse(const uint8_t *section, unsigned int byteCount)
{
	int ret;

	if (*(section + 0) != SCTE35_TABLE_ID)
		return NULL;

	struct scte35_splice_info_section_s *s = calloc(1, sizeof(*s));
	ret = scte35_splice_info_section_unpackFrom(s, section, byteCount);
	if (ret < 0) {
		free(s);
		return NULL;
	}

	return s;
}

void scte35_splice_info_section_free(struct scte35_splice_info_section_s *s)
{
	for (int i = 0; i < SCTE35_MAX_DESCRIPTORS; i++) {
		if (s->descriptors[i] != NULL)
			free(s->descriptors[i]);
	}
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
		return NULL;
	}

	struct scte35_splice_info_section_s *si = calloc(1, sizeof(*si));
	if (!si)
		return NULL;

	si->table_id = SCTE35_TABLE_ID;
	si->splice_command_type = command_type;
	si->tier = 0xFFF; /* Set default tier.  This may be modified when converting
			     from SCTE-104 via the insert_tier_data() MOM Operation */

	return si;
}

int scte35_append_avail(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, SCTE35_AVAIL_DESCRIPTOR, 8);
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, desc->identifier, 32);
	klbs_write_bits(bs, desc->avail_data.provider_avail_id, 32);
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

int scte35_parse_avail(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength)
{
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buf, bufLength);

	desc->avail_data.provider_avail_id = klbs_read_bits(bs, 32);

	klbs_free(bs);

	return 0;
}

int scte35_append_dtmf(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, SCTE35_DTMF_DESCRIPTOR, 8);
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

int scte35_parse_dtmf(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength)
{
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buf, bufLength);

	desc->dtmf_data.preroll = klbs_read_bits(bs, 8);
	desc->dtmf_data.dtmf_count = klbs_read_bits(bs, 3);
	klbs_read_bits(bs, 5); /* Reserved */

	for (int i = 0; i < desc->dtmf_data.dtmf_count; i++) {
		desc->dtmf_data.dtmf_char[i] = 	klbs_read_bits(bs, 8);
	}

	klbs_free(bs);
	return 0;
}

int scte35_append_segmentation(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	struct splice_descriptor_segmentation *seg = &desc->seg_data;
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, SCTE35_SEGMENTATION_DESCRIPTOR, 8); /* Splice Descriptor Tag */
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, desc->identifier, 32);
	klbs_write_bits(bs, seg->event_id, 32);
	klbs_write_bits(bs, seg->event_cancel_indicator, 1);
	klbs_write_bits(bs, 0x7f, 7); /* Reserved */
	if (seg->event_cancel_indicator == 0) {
		klbs_write_bits(bs, seg->program_segmentation_flag, 1);
		klbs_write_bits(bs, seg->segmentation_duration_flag ? 1 : 0, 1);
		klbs_write_bits(bs, seg->delivery_not_restricted_flag, 1);
		if (seg->delivery_not_restricted_flag == 0) {
			klbs_write_bits(bs, seg->web_delivery_allowed_flag, 1);
			klbs_write_bits(bs, seg->no_regional_blackout_flag, 1);
			klbs_write_bits(bs, seg->archive_allowed_flag, 1);
			klbs_write_bits(bs, seg->device_restrictions, 2);
		} else {
			klbs_write_bits(bs, 0x1f, 5); /* Reserved */
		}
		if (seg->program_segmentation_flag == 0) {
			klbs_write_bits(bs, seg->component_count, 8);
			for (int i = 0; i < seg->component_count; i++) {
				klbs_write_bits(bs, seg->components[i].component_tag, 8);
				klbs_write_bits(bs, 0x7f, 7); /* Reserved */
				klbs_write_bits(bs, seg->components[i].pts_offset, 33);
			}

			/* FIXME: Component mode not currently supported */
		}
		if (seg->segmentation_duration_flag) {
			klbs_write_bits(bs, seg->segmentation_duration, 40);
		}
		klbs_write_bits(bs, seg->upid_type, 8);
		klbs_write_bits(bs, seg->upid_length, 8);
		for (int i = 0; i < seg->upid_length; i++) {
			klbs_write_bits(bs, seg->upid[i], 8);
		}
		klbs_write_bits(bs, seg->type_id, 8);
		klbs_write_bits(bs, seg->segment_num, 8);
		klbs_write_bits(bs, seg->segments_expected, 8);
		if (seg->type_id == 0x34 || seg->type_id == 0x36) {
			/* FIXME: Sub segment num */
		}
	}
	klbs_write_buffer_complete(bs);

	buffer[1] = klbs_get_byte_count(bs) - 2;

	/* Append to splice_descriptor (creating if not already allocated) */
	si->splice_descriptor = realloc(si->splice_descriptor,
					klbs_get_byte_count(bs) + si->descriptor_loop_length);
	memcpy(si->splice_descriptor + si->descriptor_loop_length, buffer, klbs_get_byte_count(bs));
	si->descriptor_loop_length += klbs_get_byte_count(bs);

	klbs_free(bs);

	return 0;
}

int scte35_parse_segmentation(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength)
{
	struct splice_descriptor_segmentation *seg = &desc->seg_data;
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buf, bufLength);

	seg->event_id = klbs_read_bits(bs, 32);
	seg->event_cancel_indicator = klbs_read_bits(bs, 1);
	klbs_read_bits(bs, 7); /* Reserved */

	if (seg->event_cancel_indicator == 0) {
		seg->program_segmentation_flag = klbs_read_bits(bs, 1);
		seg->segmentation_duration_flag = klbs_read_bits(bs, 1);
		seg->delivery_not_restricted_flag = klbs_read_bits(bs, 1);
		if (seg->delivery_not_restricted_flag == 0) {
			seg->web_delivery_allowed_flag = klbs_read_bits(bs, 1);
			seg->no_regional_blackout_flag = klbs_read_bits(bs, 1);
			seg->archive_allowed_flag = klbs_read_bits(bs, 1);
			seg->device_restrictions =  klbs_read_bits(bs, 2);
		} else {
			klbs_read_bits(bs, 5); /* Reserved */
			seg->web_delivery_allowed_flag = 1;
			seg->no_regional_blackout_flag = 1;
			seg->archive_allowed_flag = 1;
			seg->device_restrictions = 0x03; /* None */
		}
		if (seg->program_segmentation_flag == 0) {
			seg->component_count = klbs_read_bits(bs, 8);
			for (int i = 0; i < seg->component_count; i++) {
				seg->components[i].component_tag = klbs_read_bits(bs, 8);
				klbs_read_bits(bs, 7); /* Reserved */
				seg->components[i].pts_offset = klbs_read_bits(bs, 33);
			}
		}
		if (seg->segmentation_duration_flag) {
			seg->segmentation_duration = klbs_read_bits(bs, 40);
		}
		seg->upid_type = klbs_read_bits(bs, 8);
		seg->upid_length = klbs_read_bits(bs, 8);
		for (int i = 0; i < seg->upid_length; i++) {
			seg->upid[i] = klbs_read_bits(bs, 8);
		}
		seg->type_id = klbs_read_bits(bs, 8);
		seg->segment_num = klbs_read_bits(bs, 8);
		seg->segments_expected = klbs_read_bits(bs, 8);
		if (seg->type_id == 0x34 || seg->type_id == 0x36) {
			/* FIXME: Sub segment num */
		}
	}

	klbs_free(bs);
	return 0;
}

int scte35_append_time(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, SCTE35_TIME_DESCRIPTOR, 8);
	klbs_write_bits(bs, 0x00, 8); // Length, fill out afterward
	klbs_write_bits(bs, desc->identifier, 32);
	klbs_write_bits(bs, desc->time_data.TAI_seconds, 48);
	klbs_write_bits(bs, desc->time_data.TAI_ns, 32);
	klbs_write_bits(bs, desc->time_data.UTC_offset, 16);
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

int scte35_parse_time(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength)
{
	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buf, bufLength);

	desc->time_data.TAI_seconds = klbs_read_bits(bs, 48);
	desc->time_data.TAI_ns = klbs_read_bits(bs, 32);
	desc->time_data.UTC_offset = klbs_read_bits(bs, 16);

	klbs_free(bs);

	return 0;
}

/* Generic handling for unrecognized descriptors */
int scte35_parse_descriptor(struct splice_descriptor *desc, uint8_t *buf, unsigned int bufLength)
{
	struct splice_descriptor_arbitrary *arb = &desc->extra_data;

	arb->descriptor_data_length = bufLength;
	memcpy(arb->descriptor_data, buf, bufLength);

	return 0;
}

int scte35_append_descriptor(struct scte35_splice_info_section_s *si, struct splice_descriptor *desc)
{
	struct klbs_context_s *bs = klbs_alloc();
	unsigned char buffer[256];

	klbs_write_set_buffer(bs, buffer, sizeof(buffer));
	klbs_write_bits(bs, desc->splice_descriptor_tag, 8);
	klbs_write_bits(bs, desc->descriptor_length, 8);
	klbs_write_bits(bs, desc->identifier, 32);
	for (int i = 0; i < desc->extra_data.descriptor_data_length; i++) {
		klbs_write_bits(bs, desc->extra_data.descriptor_data[i], 8);
	}

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
		return -KLSCTE35_ERR_INVAL;

	struct klbs_context_s *bs = klbs_alloc();
	klbs_write_set_buffer(bs, buffer, buffer_length_bytes);

	klbs_write_bits(bs, si->table_id, 8);
	if (si->table_id != SCTE35_TABLE_ID) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_write_bits(bs, si->section_syntax_indicator, 1);
	if (si->section_syntax_indicator != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_write_bits(bs, si->private_indicator, 1);
	if (si->private_indicator != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_write_bits(bs, 0xff, 2); /* Reserved */
	klbs_write_bits(bs, 0, 12); /* Section length, to be filled later */

	/* Technically SCTE104 can pass us an arbitrary protocol version and the SCTE104 Figure 8-1
	 * mapping table says field SCTE35_protocol_version should be mapped into the SCTE35
	 * reconstructed table. I'm NOT going to do that, because the SCTE35 spec says the only valid
	 * value is zero. So, I'm going to ensure that any SCTE35 message we generate contains
	 * protocol_zero, regardless.
	 */
	klbs_write_bits(bs, si->protocol_version, 8);
	if (si->protocol_version != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_write_bits(bs, si->encrypted_packet, 1);
	if (si->encrypted_packet != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

	klbs_write_bits(bs, si->encryption_algorithm, 6);
	if (si->encryption_algorithm != 0) {
		klbs_free(bs);
		return -KLSCTE35_ERR_INVAL;
	}

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
		klbs_free(bs);
		return -KLSCTE35_ERR_NOTSUPPORTED;
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
		/* Nothing to do */
	} else
	if (si->splice_command_type == SCTE35_COMMAND_TYPE__PRIVATE) {
		klbs_write_bits(bs, si->private_command.identifier, 32);
		for (int i = 0; i < si->private_command.private_length; i++) {
			klbs_write_bits(bs, si->private_command.private_byte[i], 8);
		}
	} else {
		klbs_free(bs);
		return -KLSCTE35_ERR_NOTSUPPORTED;
	}

	int posb = klbs_get_byte_count(bs);
	if (si->splice_command_length != 0xfff) {
		/* If we deserialized a packet which had the reserved value 0xfff,
		   pass that through in packets we generate for consistency.  See
		   Sec 9.6 description of "splice_command_length" */
		si->splice_command_length = posb - posa;
	}

	/* Patch in the command length */
	bs->buf[11] |= ((si->splice_command_length >> 8) & 0x0f);
	bs->buf[12]  =  (si->splice_command_length       & 0xff);

	/* Generate the descriptor payload */
	si->descriptor_loop_length = 0;
	for (int i = 0; i < si->descriptor_loop_count; i++) {
		switch (si->descriptors[i]->identifier) {
		case 0x43554549:
			switch(si->descriptors[i]->splice_descriptor_tag) {
			case SCTE35_AVAIL_DESCRIPTOR:
				ret = scte35_append_avail(si, si->descriptors[i]);
				break;
			case SCTE35_DTMF_DESCRIPTOR:
				ret = scte35_append_dtmf(si, si->descriptors[i]);
				break;
			case SCTE35_SEGMENTATION_DESCRIPTOR:
				ret = scte35_append_segmentation(si, si->descriptors[i]);
				break;
			case SCTE35_TIME_DESCRIPTOR:
				ret = scte35_append_time(si, si->descriptors[i]);
				break;
			default:
				/* SCTE identifer, but unknown descriptor tag, so just
				   pass it through */
				ret = scte35_append_descriptor(si, si->descriptors[i]);
				break;
			}
			break;
		default:
			/* If it's not one of the known types, it's a unknown/proprietary
			   descriptor */
			ret = scte35_append_descriptor(si, si->descriptors[i]);
			break;
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
		return -KLSCTE35_ERR_NOMEM;

	sd->splice_descriptor_tag = tag;
	*desc = sd;

	return 0;
}
