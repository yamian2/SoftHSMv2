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
 SymCryptDES.cpp

 SymCrypt (3)DES implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptDES.h"
#include "odd.h"

PCSYMCRYPT_BLOCKCIPHER SymCryptDES::getBlockCipher() const
{
	return SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_3DES);
}

bool SymCryptDES::isValidKeyLength(unsigned long bitLen) const
{
	if (
#ifndef WITH_FIPS
	    (bitLen == 56) ||
#endif
	    (bitLen == 112) ||
	    (bitLen == 168))
	{
		return true;
	}

	return false;
}

bool SymCryptDES::expandKey(const ByteString& keyBits, SymMode::Type /*mode*/)
{
	// SymCrypt3DesExpandKey accepts 8-byte (single), 16-byte (2-key) or
	// 24-byte (3-key) key material and ignores the parity bits.
	if (SymCrypt3DesExpandKey(&m_desKey, keyBits.const_byte_str(), keyBits.size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCrypt3DesExpandKey failed");
		return false;
	}

	return true;
}

PCVOID SymCryptDES::getExpandedKey() const
{
	return (PCVOID) &m_desKey;
}

PCSYMCRYPT_GCM_EXPANDED_KEY SymCryptDES::getGcmExpandedKey() const
{
	// DES does not support GCM
	return NULL;
}

size_t SymCryptDES::getBlockSize() const
{
	// The block size is 64 bits
	return 64 >> 3;
}

bool SymCryptDES::wrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("DES does not support key wrapping");
	return false;
}

bool SymCryptDES::unwrapKey(const SymmetricKey* /*key*/, const SymWrap::Type /*mode*/, const ByteString& /*in*/, ByteString& /*out*/)
{
	ERROR_MSG("DES does not support key unwrapping");
	return false;
}

bool SymCryptDES::generateKey(SymmetricKey& key, RNG* rng /* = NULL */)
{
	if (rng == NULL)
	{
		return false;
	}

	if (key.getBitLen() == 0)
	{
		return false;
	}

	ByteString keyBits;

	// don't count parity bit
	if (!rng->generateRandom(keyBits, key.getBitLen() / 7))
	{
		return false;
	}

	// fix the odd parity
	for (size_t i = 0; i < keyBits.size(); i++)
	{
		keyBits[i] = odd_parity[keyBits[i]];
	}

	return key.setKeyBits(keyBits);
}
