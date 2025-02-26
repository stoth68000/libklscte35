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

int scte35_create_base64_message(struct scte35_splice_info_section_s *s, char **buf, uint32_t *byteCount)
{
	int ret;
	uint8_t tmp[256];
	size_t len;

	ret = scte35_splice_info_section_packTo(s, tmp, sizeof(tmp));
	if (ret < 0)
		return ret;

	*buf = (char *) klscte35_base64_encode(tmp, ret, &len);
	*byteCount = len;

	return 0;
}
