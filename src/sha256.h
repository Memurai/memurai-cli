/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA256 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include "Win32_Interop/Win32_Portability.h"
#include "Win32_Interop/win32_types_hiredis.h"

#include <stddef.h>
#include <stdint.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;   // 8-bit byte
#define WORD uint32_t   // 32-bit word     WIN_PORT_FIX: define instead of typedef because windows already typedefs WORD as unsigned short

typedef struct {
	BYTE data[64];
	WORD datalen;
	PORT_ULONGLONG bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#undef WORD     // WIN_PORT_FIX: undef WORD so actual uses of windows WORD are not affected

#endif   // SHA256_H
