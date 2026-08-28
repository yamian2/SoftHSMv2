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
 SymCryptUtil.cpp

 SymCrypt convenience helpers shared by the SymCrypt crypto classes
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptUtil.h"

namespace SymUtil
{

UINT32 bitLength(const ByteString& value)
{
	size_t len = value.size();
	const unsigned char* bytes = value.const_byte_str();

	// Skip leading zero bytes
	size_t i = 0;
	while (i < len && bytes[i] == 0)
	{
		i++;
	}

	if (i == len)
	{
		// All zero
		return 0;
	}

	// Count the bits in the most significant non-zero byte
	UINT32 bits = (UINT32)((len - i - 1) * 8);
	unsigned char top = bytes[i];
	while (top != 0)
	{
		bits++;
		top >>= 1;
	}

	return bits;
}

bool toUInt64(const ByteString& value, UINT64& result)
{
	size_t len = value.size();
	const unsigned char* bytes = value.const_byte_str();

	// Skip leading zero bytes
	size_t i = 0;
	while (i < len && bytes[i] == 0)
	{
		i++;
	}

	if ((len - i) > 8)
	{
		return false;
	}

	UINT64 v = 0;
	for (; i < len; i++)
	{
		v = (v << 8) | bytes[i];
	}

	result = v;
	return true;
}

void logError(const char* operation, SYMCRYPT_ERROR scError)
{
	ERROR_MSG("%s failed (SymCrypt error 0x%08X)", operation, (unsigned int)scError);
}

}
