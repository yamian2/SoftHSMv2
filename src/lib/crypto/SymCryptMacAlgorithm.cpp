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
 SymCryptMacAlgorithm.cpp

 SymCrypt MAC algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptMacAlgorithm.h"
#include <string.h>

/*****************************************************************************
 Generic SymCrypt MAC (HMAC variants and AES-CMAC)
 *****************************************************************************/

SymCryptMacAlgorithm::SymCryptMacAlgorithm()
{
	initialised = false;
	memset(&expandedKey, 0, sizeof(expandedKey));
	memset(&state, 0, sizeof(state));
}

bool SymCryptMacAlgorithm::doInit(const SymmetricKey* key)
{
	PCSYMCRYPT_MAC pMac = getMacDefinition();
	if (pMac == NULL)
	{
		ERROR_MSG("No SymCrypt MAC definition available");
		return false;
	}

	ByteString keyBits = key->getKeyBits();

	if (pMac->expandKeyFunc(&expandedKey, keyBits.const_byte_str(), keyBits.size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCrypt MAC key expansion failed");
		return false;
	}

	pMac->initFunc(&state, &expandedKey);
	initialised = true;

	return true;
}

// Signing functions
bool SymCryptMacAlgorithm::signInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	if (!doInit(key))
	{
		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptMacAlgorithm::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (dataToSign.size() == 0) return true;

	getMacDefinition()->appendFunc(&state, dataToSign.const_byte_str(), dataToSign.size());

	return true;
}

bool SymCryptMacAlgorithm::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	PCSYMCRYPT_MAC pMac = getMacDefinition();

	signature.resize(pMac->resultSize);
	pMac->resultFunc(&state, &signature[0]);

	initialised = false;

	return true;
}

// Verification functions
bool SymCryptMacAlgorithm::verifyInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	if (!doInit(key))
	{
		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptMacAlgorithm::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (originalData.size() == 0) return true;

	getMacDefinition()->appendFunc(&state, originalData.const_byte_str(), originalData.size());

	return true;
}

bool SymCryptMacAlgorithm::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	PCSYMCRYPT_MAC pMac = getMacDefinition();

	ByteString macResult;
	macResult.resize(pMac->resultSize);
	pMac->resultFunc(&state, &macResult[0]);

	initialised = false;

	return macResult == signature;
}

size_t SymCryptMacAlgorithm::getMacSize() const
{
	return getMacDefinition()->resultSize;
}

// Concrete HMAC and AES-CMAC definitions
PCSYMCRYPT_MAC SymCryptHMACMD5::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_MD5);
}

PCSYMCRYPT_MAC SymCryptHMACSHA1::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA1);
}

PCSYMCRYPT_MAC SymCryptHMACSHA224::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA224);
}

PCSYMCRYPT_MAC SymCryptHMACSHA256::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA256);
}

PCSYMCRYPT_MAC SymCryptHMACSHA384::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA384);
}

PCSYMCRYPT_MAC SymCryptHMACSHA512::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_HMAC_SHA512);
}

PCSYMCRYPT_MAC SymCryptCMACAES::getMacDefinition() const
{
	return SymCryptGetMacAlgorithm(SYMCRYPT_MAC_ID_AES_CMAC);
}

/*****************************************************************************
 (3)DES CMAC (NIST SP 800-38B)
 *****************************************************************************/

// Shift a block left by one bit, returning the bit shifted out of the MSB
static unsigned char leftShiftOneBit(const unsigned char* in, unsigned char* out, size_t len)
{
	unsigned char overflow = 0;

	for (size_t i = len; i > 0; i--)
	{
		out[i - 1] = (unsigned char)((in[i - 1] << 1) | overflow);
		overflow = (in[i - 1] & 0x80) ? 1 : 0;
	}

	return overflow;
}

SymCryptCMACDES::SymCryptCMACDES()
{
	initialised = false;
	blockLen = 0;
	memset(&desKey, 0, sizeof(desKey));
	memset(k1, 0, sizeof(k1));
	memset(k2, 0, sizeof(k2));
	memset(chaining, 0, sizeof(chaining));
	memset(block, 0, sizeof(block));
}

void SymCryptCMACDES::processBlock(const unsigned char* in)
{
	unsigned char tmp[DES_BLOCK];

	for (size_t i = 0; i < DES_BLOCK; i++)
	{
		tmp[i] = (unsigned char)(chaining[i] ^ in[i]);
	}

	SymCrypt3DesEncrypt(&desKey, tmp, chaining);
}

bool SymCryptCMACDES::doInit(const SymmetricKey* key)
{
	ByteString keyBits = key->getKeyBits();

	// SymCrypt3DesExpandKey accepts 8/16/24 byte key material and ignores parity
	if (SymCrypt3DesExpandKey(&desKey, keyBits.const_byte_str(), keyBits.size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCrypt3DesExpandKey failed");
		return false;
	}

	// Derive the CMAC subkeys K1 and K2 (NIST SP 800-38B).
	// For a 64-bit block cipher the constant Rb is 0x1B.
	unsigned char zero[DES_BLOCK];
	unsigned char l[DES_BLOCK];
	memset(zero, 0, sizeof(zero));
	SymCrypt3DesEncrypt(&desKey, zero, l);

	if (leftShiftOneBit(l, k1, DES_BLOCK))
	{
		k1[DES_BLOCK - 1] ^= 0x1B;
	}

	if (leftShiftOneBit(k1, k2, DES_BLOCK))
	{
		k2[DES_BLOCK - 1] ^= 0x1B;
	}

	memset(chaining, 0, sizeof(chaining));
	blockLen = 0;
	initialised = true;

	return true;
}

void SymCryptCMACDES::cmacAppend(const ByteString& data)
{
	const unsigned char* pb = data.const_byte_str();
	size_t n = data.size();
	size_t pos = 0;

	// Process full blocks while strictly more than one block of data remains,
	// so that between 1 and DES_BLOCK bytes are always left buffered for the
	// final (K1/K2) processing step.
	while (blockLen + (n - pos) > DES_BLOCK)
	{
		size_t need = DES_BLOCK - blockLen;
		memcpy(block + blockLen, pb + pos, need);
		pos += need;
		blockLen = DES_BLOCK;

		processBlock(block);
		blockLen = 0;
	}

	if (n > pos)
	{
		memcpy(block + blockLen, pb + pos, n - pos);
		blockLen += (n - pos);
	}
}

void SymCryptCMACDES::cmacResult(ByteString& mac)
{
	unsigned char last[DES_BLOCK];

	if (blockLen == DES_BLOCK)
	{
		// Complete final block: XOR with K1
		for (size_t i = 0; i < DES_BLOCK; i++)
		{
			last[i] = (unsigned char)(block[i] ^ k1[i]);
		}
	}
	else
	{
		// Incomplete final block: pad with 10* and XOR with K2
		unsigned char padded[DES_BLOCK];
		memset(padded, 0, sizeof(padded));
		memcpy(padded, block, blockLen);
		padded[blockLen] = 0x80;

		for (size_t i = 0; i < DES_BLOCK; i++)
		{
			last[i] = (unsigned char)(padded[i] ^ k2[i]);
		}
	}

	processBlock(last);

	mac.resize(DES_BLOCK);
	memcpy(&mac[0], chaining, DES_BLOCK);

	initialised = false;
}

// Signing functions
bool SymCryptCMACDES::signInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::signInit(key))
	{
		return false;
	}

	if (!doInit(key))
	{
		ByteString dummy;
		MacAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptCMACDES::signUpdate(const ByteString& dataToSign)
{
	if (!MacAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (dataToSign.size() == 0) return true;

	cmacAppend(dataToSign);

	return true;
}

bool SymCryptCMACDES::signFinal(ByteString& signature)
{
	if (!MacAlgorithm::signFinal(signature))
	{
		return false;
	}

	cmacResult(signature);

	return true;
}

// Verification functions
bool SymCryptCMACDES::verifyInit(const SymmetricKey* key)
{
	if (!MacAlgorithm::verifyInit(key))
	{
		return false;
	}

	if (!doInit(key))
	{
		ByteString dummy;
		MacAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptCMACDES::verifyUpdate(const ByteString& originalData)
{
	if (!MacAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (originalData.size() == 0) return true;

	cmacAppend(originalData);

	return true;
}

bool SymCryptCMACDES::verifyFinal(ByteString& signature)
{
	if (!MacAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString macResult;
	cmacResult(macResult);

	return macResult == signature;
}

size_t SymCryptCMACDES::getMacSize() const
{
	return DES_BLOCK;
}
