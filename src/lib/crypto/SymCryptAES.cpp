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
 SymCryptAES.cpp

 SymCrypt AES implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptAES.h"
#include <string.h>

// The RFC 3394 default initial value
static const unsigned char AES_KEYWRAP_IV[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

// Constructor
SymCryptAES::SymCryptAES()
{
	m_gcmKeyValid = false;
}

// Single block AES helpers for the key wrap routines
static inline void aesEcbEncryptBlock(const SYMCRYPT_AES_EXPANDED_KEY* kek, const unsigned char* in, unsigned char* out)
{
	SymCryptEcbEncrypt(SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_AES), (PCVOID) kek, (PCBYTE) in, (PBYTE) out, SYMCRYPT_AES_BLOCK_SIZE);
}

static inline void aesEcbDecryptBlock(const SYMCRYPT_AES_EXPANDED_KEY* kek, const unsigned char* in, unsigned char* out)
{
	SymCryptEcbDecrypt(SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_AES), (PCVOID) kek, (PCBYTE) in, (PBYTE) out, SYMCRYPT_AES_BLOCK_SIZE);
}

PCSYMCRYPT_BLOCKCIPHER SymCryptAES::getBlockCipher() const
{
	return SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_AES);
}

bool SymCryptAES::isValidKeyLength(unsigned long bitLen) const
{
	return (bitLen == 128) || (bitLen == 192) || (bitLen == 256);
}

bool SymCryptAES::expandKey(const ByteString& keyBits, SymMode::Type mode)
{
	m_gcmKeyValid = false;

	if (SymCryptAesExpandKey(&m_aesKey, keyBits.const_byte_str(), keyBits.size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptAesExpandKey failed");
		return false;
	}

	if (mode == SymMode::GCM)
	{
		if (SymCryptGcmExpandKey(&m_gcmKey, SymCryptGetBlockCipher(SYMCRYPT_BLOCKCIPHER_ID_AES), keyBits.const_byte_str(), keyBits.size()) != SYMCRYPT_NO_ERROR)
		{
			ERROR_MSG("SymCryptGcmExpandKey failed");
			return false;
		}
		m_gcmKeyValid = true;
	}

	return true;
}

PCVOID SymCryptAES::getExpandedKey() const
{
	return (PCVOID) &m_aesKey;
}

PCSYMCRYPT_GCM_EXPANDED_KEY SymCryptAES::getGcmExpandedKey() const
{
	return m_gcmKeyValid ? (PCSYMCRYPT_GCM_EXPANDED_KEY) &m_gcmKey : NULL;
}

size_t SymCryptAES::getBlockSize() const
{
	// The block size is 128 bits
	return 128 >> 3;
}

// RFC 3394 key wrap. The chaining value A is initialised to *iv (either the
// default 0xA6A6... IV or an RFC 5649 AIV).
bool SymCryptAES::rfc3394Wrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const unsigned char* iv, const ByteString& in, ByteString& out) const
{
	size_t n = in.size() / 8;
	if ((n < 1) || ((in.size() % 8) != 0))
	{
		return false;
	}

	unsigned char A[8];
	memcpy(A, iv, 8);

	ByteString R = in;
	unsigned char* Rp = &R[0];
	unsigned char B[16];

	for (unsigned int j = 0; j < 6; j++)
	{
		for (size_t i = 1; i <= n; i++)
		{
			memcpy(B, A, 8);
			memcpy(B + 8, Rp + (i - 1) * 8, 8);
			aesEcbEncryptBlock(kek, B, B);

			memcpy(A, B, 8);
			unsigned long long t = (unsigned long long) n * j + i;
			for (int k = 0; k < 8; k++)
			{
				A[7 - k] ^= (unsigned char) ((t >> (8 * k)) & 0xff);
			}

			memcpy(Rp + (i - 1) * 8, B + 8, 8);
		}
	}

	out.wipe();
	out.resize(8);
	memcpy(&out[0], A, 8);
	out += R;

	return true;
}

// RFC 3394 key unwrap. The recovered chaining value is written to outIv (8 bytes)
// for the caller to validate; the recovered data blocks are written to out.
bool SymCryptAES::rfc3394Unwrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, unsigned char* outIv, ByteString& out) const
{
	if ((in.size() < 16) || ((in.size() % 8) != 0))
	{
		return false;
	}

	size_t n = (in.size() / 8) - 1;

	unsigned char A[8];
	memcpy(A, in.const_byte_str(), 8);

	ByteString R = in.substr(8);
	unsigned char* Rp = &R[0];
	unsigned char B[16];

	for (int j = 5; j >= 0; j--)
	{
		for (size_t i = n; i >= 1; i--)
		{
			unsigned long long t = (unsigned long long) n * (unsigned int) j + i;
			for (int k = 0; k < 8; k++)
			{
				A[7 - k] ^= (unsigned char) ((t >> (8 * k)) & 0xff);
			}

			memcpy(B, A, 8);
			memcpy(B + 8, Rp + (i - 1) * 8, 8);
			aesEcbDecryptBlock(kek, B, B);

			memcpy(A, B, 8);
			memcpy(Rp + (i - 1) * 8, B + 8, 8);
		}
	}

	memcpy(outIv, A, 8);
	out = R;

	return true;
}

bool SymCryptAES::rfc5649Wrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, ByteString& out) const
{
	size_t mli = in.size();

	// Pad the plaintext with zeros to a multiple of 8 bytes (at least one block)
	size_t padded = ((mli + 7) / 8) * 8;
	if (padded == 0)
	{
		padded = 8;
	}

	ByteString P = in;
	if (padded > mli)
	{
		ByteString pad;
		pad.resize(padded - mli);
		memset(&pad[0], 0, padded - mli);
		P += pad;
	}

	// AIV = 0xA65959A6 || MLI (32-bit big-endian message length indicator)
	unsigned char aiv[8];
	aiv[0] = 0xA6;
	aiv[1] = 0x59;
	aiv[2] = 0x59;
	aiv[3] = 0xA6;
	aiv[4] = (unsigned char) ((mli >> 24) & 0xff);
	aiv[5] = (unsigned char) ((mli >> 16) & 0xff);
	aiv[6] = (unsigned char) ((mli >> 8) & 0xff);
	aiv[7] = (unsigned char) (mli & 0xff);

	if (padded == 8)
	{
		// Single block: out = AES-ECB-Encrypt(AIV || P)
		unsigned char B[16];
		memcpy(B, aiv, 8);
		memcpy(B + 8, P.const_byte_str(), 8);

		out.wipe();
		out.resize(16);
		aesEcbEncryptBlock(kek, B, &out[0]);

		return true;
	}

	return rfc3394Wrap(kek, aiv, P, out);
}

bool SymCryptAES::rfc5649Unwrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, ByteString& out) const
{
	unsigned char aiv[8];
	ByteString R;

	if (in.size() == 16)
	{
		// Single block: decrypt directly to AIV || padded plaintext
		unsigned char P[16];
		aesEcbDecryptBlock(kek, in.const_byte_str(), P);
		memcpy(aiv, P, 8);
		R.resize(8);
		memcpy(&R[0], P + 8, 8);
	}
	else
	{
		if (!rfc3394Unwrap(kek, in, aiv, R))
		{
			return false;
		}
	}

	// Validate the AIV prefix
	if ((aiv[0] != 0xA6) || (aiv[1] != 0x59) || (aiv[2] != 0x59) || (aiv[3] != 0xA6))
	{
		ERROR_MSG("Invalid RFC 5649 AIV");
		return false;
	}

	size_t mli = ((size_t) aiv[4] << 24) | ((size_t) aiv[5] << 16) | ((size_t) aiv[6] << 8) | (size_t) aiv[7];

	// The message length must fit in the padded data with 0..7 padding bytes
	if ((mli > R.size()) || (mli + 8 <= R.size()) || (mli == 0))
	{
		ERROR_MSG("Invalid RFC 5649 message length indicator");
		return false;
	}

	// The padding bytes must all be zero
	for (size_t i = mli; i < R.size(); i++)
	{
		if (R.const_byte_str()[i] != 0)
		{
			ERROR_MSG("Invalid RFC 5649 padding");
			return false;
		}
	}

	out = R.substr(0, mli);

	return true;
}

bool SymCryptAES::wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	if (key == NULL)
	{
		return false;
	}

	if (!isValidKeyLength(key->getBitLen()))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());
		return false;
	}

	SYMCRYPT_AES_EXPANDED_KEY kek;
	if (SymCryptAesExpandKey(&kek, key->getKeyBits().const_byte_str(), key->getKeyBits().size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptAesExpandKey failed");
		return false;
	}

	if (mode == SymWrap::AES_KEYWRAP)
	{
		if ((in.size() < 16) || ((in.size() % 8) != 0))
		{
			ERROR_MSG("key data to wrap must be at least 16 bytes and 8-byte aligned");
			return false;
		}
		return rfc3394Wrap(&kek, AES_KEYWRAP_IV, in, out);
	}
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		if (in.size() == 0)
		{
			ERROR_MSG("no key data to wrap");
			return false;
		}
		return rfc5649Wrap(&kek, in, out);
	}

	ERROR_MSG("unknown AES key wrap mode %i", mode);
	return false;
}

bool SymCryptAES::unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out)
{
	if (key == NULL)
	{
		return false;
	}

	if (!isValidKeyLength(key->getBitLen()))
	{
		ERROR_MSG("Invalid AES key length (%d bits)", key->getBitLen());
		return false;
	}

	SYMCRYPT_AES_EXPANDED_KEY kek;
	if (SymCryptAesExpandKey(&kek, key->getKeyBits().const_byte_str(), key->getKeyBits().size()) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptAesExpandKey failed");
		return false;
	}

	if (mode == SymWrap::AES_KEYWRAP)
	{
		if ((in.size() < 24) || ((in.size() % 8) != 0))
		{
			ERROR_MSG("key data to unwrap must be at least 24 bytes and 8-byte aligned");
			return false;
		}

		unsigned char A[8];
		ByteString R;
		if (!rfc3394Unwrap(&kek, in, A, R))
		{
			return false;
		}

		// Verify the integrity check value
		for (int k = 0; k < 8; k++)
		{
			if (A[k] != 0xA6)
			{
				ERROR_MSG("AES key unwrap integrity check failed");
				return false;
			}
		}

		out = R;
		return true;
	}
	else if (mode == SymWrap::AES_KEYWRAP_PAD)
	{
		if ((in.size() < 16) || ((in.size() % 8) != 0))
		{
			ERROR_MSG("key data to unwrap must be at least 16 bytes and 8-byte aligned");
			return false;
		}
		return rfc5649Unwrap(&kek, in, out);
	}

	ERROR_MSG("unknown AES key wrap mode %i", mode);
	return false;
}
