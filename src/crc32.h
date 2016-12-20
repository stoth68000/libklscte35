/**
 * @file	crc32.h
 * @author	Steven Toth <stoth@kernellabs.com>
 * @copyright	Copyright (c) 2016 Kernel Labs Inc. All Rights Reserved.
 * @brief	Validate and generate CRC32 checksums.\n
 */

#ifndef CRC32_H
#define CRC32_H

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	Takes the entire table from tableid to last crcbyte. Length should be the total numbers 
 *		of bytes form the table id up to and including the last CRC byte.
 * @param[in]	unsigned char *buf - Brief description goes here.
 * @param[in]	int len - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int iso13818_checkCRC32(unsigned char *buf, int len);

/**
 * @brief	TODO - Brief description goes here.
 * @param[in]	unsigned char *buf - Brief description goes here.
 * @param[in]	int len - Brief description goes here.
 * @param[in]	unsigned int *crc32 - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int iso13818_getCRC32(unsigned char *buf, int len, unsigned int *crc32);

#ifdef __cplusplus
};
#endif
#endif /* CRC32_H */
