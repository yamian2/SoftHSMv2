/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SymCryptUtil.h

 SymCrypt convenience helpers shared by the SymCrypt crypto classes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTUTIL_H
#define _SOFTHSM_V2_SYMCRYPTUTIL_H

#include "config.h"
#include "ByteString.h"
#include <symcrypt.h>

namespace SymUtil
{
	// Return the exact number of significant bits in a big-endian (MSB first)
	// magnitude stored in a ByteString (leading zero bytes/bits are ignored).
	UINT32 bitLength(const ByteString& value);

	// Convert a big-endian magnitude (e.g. an RSA public exponent) into a
	// UINT64. Returns false if the value does not fit in 64 bits.
	bool toUInt64(const ByteString& value, UINT64& result);

	// Log a SymCrypt error together with the operation that produced it.
	void logError(const char* operation, SYMCRYPT_ERROR scError);
}

#endif // !_SOFTHSM_V2_SYMCRYPTUTIL_H
