/*
 * Copyright (c) 2025 Kernel Labs Inc. All Rights Reserved
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

#include "libklscte35/scte35.h"
#include "base64.h"
#include <json-c/json.h>
#include <stdio.h>

static int json_generate_splice_insert(const struct scte35_splice_insert_s *si, json_object *obj)
{
        json_object *splice = json_object_new_object();
	if (splice == NULL)
		return -1;

	json_object_object_add(obj, "splice_insert", splice);

	json_object_object_add(splice, "splice_event_id", json_object_new_int64(si->splice_event_id));
	json_object_object_add(splice, "splice_event_cancel_indicator",
			       json_object_new_boolean(si->splice_event_cancel_indicator));
	json_object_object_add(splice, "splice_event_cancel_indicator",
			       json_object_new_boolean(si->splice_event_cancel_indicator));

	if (si->splice_event_cancel_indicator == 0) {
		json_object_object_add(splice, "out_of_network_indicator",
				       json_object_new_boolean(si->out_of_network_indicator));
		json_object_object_add(splice, "program_splice_flag",
				       json_object_new_boolean(si->program_splice_flag));
		json_object_object_add(splice, "duration_flag",
				       json_object_new_boolean(si->duration_flag));
		json_object_object_add(splice, "splice_immediate_flag",
				       json_object_new_boolean(si->splice_immediate_flag));
		if (si->program_splice_flag == 1 && si->splice_immediate_flag == 0) {
			/* Splice Time */
			json_object * stime = json_object_new_object();
			json_object_object_add(splice, "splice_time", stime);
			json_object_object_add(stime, "time_specified_flag",
					       json_object_new_boolean(si->splice_time.time_specified_flag));
			if (si->splice_time.time_specified_flag == 1) {
				json_object_object_add(stime, "pts_time",
						       json_object_new_int64(si->splice_time.pts_time));
			}
		}
		if (si->program_splice_flag == 0) {
			/* Component mode, not supported */
		}
		if (si->duration_flag == 1) {
			/* break_duration */
			json_object * duration = json_object_new_object();
			json_object_object_add(splice, "break_duration", duration);
			json_object_object_add(duration, "auto_return",
					       json_object_new_boolean(si->duration.auto_return));
			json_object_object_add(duration, "duration",
					       json_object_new_int64(si->duration.duration));		
			
		}
		json_object_object_add(splice, "unique_program_id", json_object_new_int64(si->unique_program_id));
		json_object_object_add(splice, "avail_num", json_object_new_int64(si->avail_num));
		json_object_object_add(splice, "avails_expected", json_object_new_int64(si->avails_expected));
	}

	return 0;
}

static int json_generate_splice_null(const struct scte35_splice_null_s *si, json_object *obj)
{
	/* Splice NULL requests have no actual properties to fill out */
        json_object *splice = json_object_new_object();
	if (splice == NULL)
		return -1;

	json_object_object_add(obj, "splice_null", splice);
	return 0;
}

static int json_generate_time_signal(const struct scte35_splice_time_s *si, json_object *obj)
{
        json_object *splice = json_object_new_object();
	if (splice == NULL)
		return -1;

	json_object_object_add(obj, "time_signal", splice);

	json_object * stime = json_object_new_object();
	json_object_object_add(splice, "splice_time", stime);
	json_object_object_add(stime, "time_specified_flag",
			       json_object_new_boolean(si->time_specified_flag));
	if (si->time_specified_flag == 1) {
		json_object_object_add(stime, "pts_time",
				       json_object_new_int64(si->pts_time));
	}

	return 0;
}

static int json_generate_private(const struct scte35_splice_private_s *si,
				    json_object *obj)
{
        json_object *splice = json_object_new_object();
	uint8_t *base64_out;
	size_t base64_outlen;

	if (splice == NULL)
		return -1;

	json_object_object_add(obj, "private_command", splice);

	json_object_object_add(splice, "identifier", json_object_new_int64(si->identifier));

	base64_out = klscte35_base64_encode((uint8_t *)si->private_byte, si->private_length, &base64_outlen);
	if (base64_out) {
		json_object_object_add(splice, "private_bytes" ,json_object_new_string((char *)base64_out));
		free(base64_out);
	}

	return 0;
}

static int json_generate_bandwidth_reservation(json_object *obj)
{
	/* Bandwidth reservation requests have no actual properties to fill out */
        json_object *splice = json_object_new_object();
	if (splice == NULL)
		return -1;

	json_object_object_add(obj, "bandwidth_reservation", splice);
	return 0;
}

static int json_append_private_splice(struct splice_descriptor *sd, json_object *obj)
{
	uint8_t *base64_out;
	size_t base64_outlen;
        json_object *desc = json_object_new_object();
	if (desc == NULL)
		return -1;

        json_object_array_add(obj, desc);

	json_object_object_add(desc, "descriptor_type" , json_object_new_string("private_splice_descriptor"));
	json_object_object_add(desc, "splice_descriptor_tag",
			       json_object_new_int64(sd->splice_descriptor_tag));
	json_object_object_add(desc, "identifier",
			       json_object_new_int64(sd->identifier));

	base64_out = klscte35_base64_encode((uint8_t *)sd->extra_data.descriptor_data,
					    sd->extra_data.descriptor_data_length, &base64_outlen);
	if (base64_out) {
		json_object_object_add(desc, "private_bytes" ,json_object_new_string((char *)base64_out));
		free(base64_out);
	}

	return 0;
}

static int json_append_avail(struct splice_descriptor *sd, json_object *obj)
{
        json_object *desc = json_object_new_object();
	if (desc == NULL)
		return -1;

        json_object_array_add(obj, desc);

	json_object_object_add(desc, "descriptor_type" , json_object_new_string("avail_descriptor"));
	json_object_object_add(desc, "splice_descriptor_tag",
			       json_object_new_int64(sd->splice_descriptor_tag));
	json_object_object_add(desc, "identifier",
			       json_object_new_int64(0x43554549));

	json_object_object_add(desc, "provider_avail_id",
			       json_object_new_int64(sd->avail_data.provider_avail_id));

	return 0;
}

static int json_append_dtmf(struct splice_descriptor *sd, json_object *obj)
{
	char buf[64] = "";
        json_object *desc = json_object_new_object();
	if (desc == NULL)
		return -1;

        json_object_array_add(obj, desc);

	/* These values never change, per the spec */
	json_object_object_add(desc, "descriptor_type" , json_object_new_string("dtmf_descriptor"));
	json_object_object_add(desc, "splice_descriptor_tag",
			       json_object_new_int64(sd->splice_descriptor_tag));
	json_object_object_add(desc, "identifier",
			       json_object_new_int64(0x43554549));
	json_object_object_add(desc, "preroll",
			       json_object_new_int64(sd->dtmf_data.preroll));
	json_object_object_add(desc, "dtmf_count",
			       json_object_new_int64(sd->dtmf_data.dtmf_count));

	for (int i = 0; i < sd->dtmf_data.dtmf_count; i++) {
		buf[i] = sd->dtmf_data.dtmf_char[i];
	}
	json_object_object_add(desc, "DTMF_char", json_object_new_string(buf));

	return 0;
}


static int json_append_segmentation(struct splice_descriptor *sd, json_object *obj)
{
        json_object *desc = json_object_new_object();
	if (desc == NULL)
		return -1;

        json_object_array_add(obj, desc);

	json_object_object_add(desc, "descriptor_type" , json_object_new_string("segmentation_descriptor"));
	json_object_object_add(desc, "splice_descriptor_tag",
			       json_object_new_int64(sd->splice_descriptor_tag));
	json_object_object_add(desc, "identifier",
			       json_object_new_int64(0x43554549));

	json_object_object_add(desc, "segmentation_event_id",
			       json_object_new_int64(sd->seg_data.event_id));
	json_object_object_add(desc, "segmentation_event_cancel_indicator",
			       json_object_new_boolean(sd->seg_data.event_cancel_indicator));
	if (sd->seg_data.event_cancel_indicator == 0) {
		json_object_object_add(desc, "program_segmentation_flag",
				       json_object_new_boolean(sd->seg_data.program_segmentation_flag));
		json_object_object_add(desc, "segmentation_duration_flag",
				       json_object_new_boolean(sd->seg_data.segmentation_duration_flag));
		json_object_object_add(desc, "delivery_not_restricted_flag",
				       json_object_new_boolean(sd->seg_data.delivery_not_restricted_flag));
		if (sd->seg_data.delivery_not_restricted_flag == 0) {
			json_object_object_add(desc, "web_delivery_allowed_flag",
					       json_object_new_boolean(sd->seg_data.web_delivery_allowed_flag));
			json_object_object_add(desc, "no_regional_blackout_flag",
					       json_object_new_boolean(sd->seg_data.no_regional_blackout_flag));
			json_object_object_add(desc, "archive_allowed_flag",
					       json_object_new_boolean(sd->seg_data.archive_allowed_flag));
			json_object_object_add(desc, "device_restrictions",
					       json_object_new_int64(sd->seg_data.device_restrictions));
		}
		if (sd->seg_data.program_segmentation_flag == 0) {
			/* Component mode not supported */
		}
		if (sd->seg_data.segmentation_duration_flag == 1) {
			json_object_object_add(desc, "segmentation_duration",
                                               json_object_new_int64(sd->seg_data.segmentation_duration));
		}
		json_object_object_add(desc, "segmentation_upid_type",
				       json_object_new_int64(sd->seg_data.upid_type));
		/* FIXME: segmentation upid bytes */

		json_object_object_add(desc, "segmentation_type_id",
				       json_object_new_int64(sd->seg_data.type_id));
		json_object_object_add(desc, "segment_num",
				       json_object_new_int64(sd->seg_data.segment_num));
		json_object_object_add(desc, "segments_expected",
				       json_object_new_int64(sd->seg_data.segments_expected));
		
	}

	return 0;
}

static int json_append_time(struct splice_descriptor *sd, json_object *obj)
{
        json_object *desc = json_object_new_object();
	if (desc == NULL)
		return -1;

        json_object_array_add(obj, desc);

	json_object_object_add(desc, "descriptor_type" , json_object_new_string("time_descriptor"));
	json_object_object_add(desc, "splice_descriptor_tag",
			       json_object_new_int64(sd->splice_descriptor_tag));

	json_object_object_add(desc, "identifier", json_object_new_int64(0x43554549));

	json_object_object_add(desc, "TAI_seconds", json_object_new_int64(sd->time_data.TAI_seconds));
	json_object_object_add(desc, "TAI_ns", json_object_new_int64(sd->time_data.TAI_ns));
	json_object_object_add(desc, "UTC_offset", json_object_new_int64(sd->time_data.UTC_offset));

	return 0;
}

int scte35_create_json_message(struct scte35_splice_info_section_s *s, char **buf, uint16_t *byteCount, int compressed)
{
	int ret = -1;

        json_object * jobj = json_object_new_object();
	if (jobj == NULL)
		return -1;

	json_object_object_add(jobj, "table_id", json_object_new_int64(s->table_id));
	json_object_object_add(jobj, "section_syntax_indicator", json_object_new_boolean(s->section_syntax_indicator));
	json_object_object_add(jobj, "private_indicator", json_object_new_boolean(s->private_indicator));
	json_object_object_add(jobj, "section_length", json_object_new_int64(s->section_length)); 
	json_object_object_add(jobj, "protocol_version", json_object_new_int64(s->protocol_version)); 
	json_object_object_add(jobj, "encrypted_packet", json_object_new_boolean(s->encrypted_packet));
	json_object_object_add(jobj, "encryption_algorithm", json_object_new_int64(s->encryption_algorithm));
	json_object_object_add(jobj, "pts_adjustment", json_object_new_int64(s->pts_adjustment));
	json_object_object_add(jobj, "cw_index", json_object_new_int64(s->cw_index));
	json_object_object_add(jobj, "tier", json_object_new_int64(s->tier));
	json_object_object_add(jobj, "splice_command_length", json_object_new_int64(s->splice_command_length));
	json_object_object_add(jobj, "splice_command_type", json_object_new_int64(s->splice_command_type));


	switch(s->splice_command_type) {
	case SCTE35_COMMAND_TYPE__SPLICE_INSERT:
		ret = json_generate_splice_insert(&s->splice_insert, jobj);
		break;
	case SCTE35_COMMAND_TYPE__SPLICE_NULL:
		ret = json_generate_splice_null(&s->splice_null, jobj);
		break;
	case SCTE35_COMMAND_TYPE__TIME_SIGNAL:
		ret = json_generate_time_signal(&s->time_signal, jobj);
		break;
	case SCTE35_COMMAND_TYPE__PRIVATE:
		ret = json_generate_private(&s->private_command, jobj);
		break;
	case SCTE35_COMMAND_TYPE__BW_RESERVATION:
		ret = json_generate_bandwidth_reservation(jobj);
		break;
	default:
		fprintf(stderr, "%s: Unsupported command type %d\n", __func__,
			s->splice_command_type);
		return -1;
	}

	if (s->descriptor_loop_count > 0) {
		json_object *desc_array = json_object_new_array();
		for (int i = 0; i < s->descriptor_loop_count; i++) {
			struct splice_descriptor *sd = s->descriptors[i];
			switch(sd->splice_descriptor_tag) {
			case SCTE35_AVAIL_DESCRIPTOR:
				json_append_avail(sd, desc_array);
				break;
			case SCTE35_DTMF_DESCRIPTOR:
				json_append_dtmf(sd, desc_array);
				break;
			case SCTE35_SEGMENTATION_DESCRIPTOR:
				json_append_segmentation(sd, desc_array);
				break;
			case SCTE35_TIME_DESCRIPTOR:
				json_append_time(sd, desc_array);
				break;
			default:
				/* Any SCTE-35 descriptor we don't recognize should be pushed
				   out as a "Private Splice Descriptor" */
				json_append_private_splice(sd, desc_array);
				break;
			}
		}
		json_object_object_add(jobj, "descriptors", desc_array);
	}

	if (compressed) {
		*buf = strdup(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));
	} else {
		*buf = strdup(json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY));
	}
	*byteCount=strlen(*buf);
	json_object_put(jobj);

	return ret;
}
