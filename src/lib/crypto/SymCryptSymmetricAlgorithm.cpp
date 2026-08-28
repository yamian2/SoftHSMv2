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
 SymCryptSymmetricAlgorithm.cpp

 SymCrypt symmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptSymmetricAlgorithm.h"
#include <string.h>

// Constructor
SymCryptSymmetricAlgorithm::SymCryptSymmetricAlgorithm()
{
	m_ofbOffset = 0;
	m_maxBytesLimited = false;
	m_maxBytes = 0;
	m_processedBytes = 0;
}

// Destructor
SymCryptSymmetricAlgorithm::~SymCryptSymmetricAlgorithm()
{
	cleanup();
}

void SymCryptSymmetricAlgorithm::cleanup()
{
	m_iv.wipe();
	m_buffer.wipe();
	m_aad.wipe();
	m_ofbKeystream.wipe();
	m_ofbOffset = 0;
	m_maxBytesLimited = false;
	m_maxBytes = 0;
	m_processedBytes = 0;
}

void SymCryptSymmetricAlgorithm::ecbEncryptBlock(const unsigned char* in, unsigned char* out) const
{
	SymCryptEcbEncrypt(getBlockCipher(), getExpandedKey(), (PCBYTE) in, (PBYTE) out, getBlockSize());
}

void SymCryptSymmetricAlgorithm::computeCounterMax(const ByteString& iv, size_t counterBits)
{
	m_maxBytesLimited = false;
	m_maxBytes = 0;
	m_processedBytes = 0;

	// counterBits == 0 means no limit; for very large counters we treat the space
	// as effectively unlimited to avoid 64-bit overflow.
	if (counterBits == 0 || counterBits >= 64)
	{
		return;
	}

	// Determine the current value of the low counterBits of the IV (big-endian)
	size_t n = iv.size();
	size_t take = (n < 8) ? n : 8;
	unsigned long long v = 0;
	for (size_t i = 0; i < take; i++)
	{
		v = (v << 8) | iv.const_byte_str()[n - take + i];
	}

	unsigned long long mask = (1ULL << counterBits) - 1;
	v &= mask;

	unsigned long long total = (1ULL << counterBits);
	unsigned long long remaining = total - v;

	m_maxBytes = remaining * getBlockSize();
	m_maxBytesLimited = true;
}

bool SymCryptSymmetricAlgorithm::cipherInit(const SymmetricKey* key, SymMode::Type mode, const ByteString& IV, bool /*padding*/, size_t counterBits, const ByteString& aad, size_t tagBytes, bool /*encrypt*/)
{
	// Reset any lingering state
	cleanup();

	size_t block = getBlockSize();

	// Validate the key length
	if (!isValidKeyLength(key->getBitLen()))
	{
		ERROR_MSG("Invalid key length (%d bits)", key->getBitLen());
		return false;
	}

	// Set up the IV / nonce
	if (mode == SymMode::GCM)
	{
		// SymCrypt only supports 96-bit (12-byte) GCM nonces
		if (IV.size() != 12)
		{
			ERROR_MSG("SymCrypt AES-GCM only supports 12-byte (96-bit) nonces (got %d bytes)", IV.size());
			return false;
		}

		m_iv = IV;
	}
	else if (mode == SymMode::ECB)
	{
		// ECB does not use an IV
		m_iv.wipe(block);
	}
	else
	{
		if ((IV.size() > 0) && (IV.size() != block))
		{
			ERROR_MSG("Invalid IV size (%d bytes, expected %d bytes)", IV.size(), block);
			return false;
		}

		if (IV.size() > 0)
		{
			m_iv = IV;
		}
		else
		{
			m_iv.wipe(block);
		}
	}

	// Expand the key material into the subclass storage
	if (!expandKey(key->getKeyBits(), mode))
	{
		ERROR_MSG("Failed to expand the symmetric key");
		return false;
	}

	if (mode == SymMode::GCM)
	{
		if (getGcmExpandedKey() == NULL)
		{
			ERROR_MSG("GCM mode is not supported by this cipher");
			return false;
		}

		// SymCrypt only supports tag sizes of 12..16 bytes
		if ((tagBytes < 12) || (tagBytes > 16))
		{
			ERROR_MSG("SymCrypt AES-GCM only supports tag sizes of 12 to 16 bytes (got %d)", tagBytes);
			return false;
		}

		m_aad = aad;
	}

	// Initialise the OFB keystream buffer
	m_ofbKeystream.wipe(block);
	m_ofbOffset = 0;

	// Initialise CTR maximum bytes tracking
	computeCounterMax(m_iv, counterBits);

	m_buffer.wipe();

	return true;
}

// Block cipher mode (CBC/ECB) streaming
bool SymCryptSymmetricAlgorithm::blockModeUpdate(const ByteString& data, ByteString& out, bool encrypt)
{
	size_t block = getBlockSize();

	m_buffer += data;
	out.wipe();

	size_t avail = m_buffer.size();
	size_t process;

	if (encrypt)
	{
		// Emit all complete blocks; padding is applied to the tail in Final
		process = (avail / block) * block;
	}
	else if (currentPaddingMode)
	{
		// Retain at least one full block so padding can be stripped in Final
		if (avail <= block)
			process = 0;
		else
			process = ((avail - 1) / block) * block;
	}
	else
	{
		process = (avail / block) * block;
	}

	if (process == 0)
	{
		return true;
	}

	out.resize(process);

	PCSYMCRYPT_BLOCKCIPHER bc = getBlockCipher();
	PCVOID expKey = getExpandedKey();

	if (currentCipherMode == SymMode::CBC)
	{
		if (encrypt)
			SymCryptCbcEncrypt(bc, expKey, &m_iv[0], m_buffer.const_byte_str(), &out[0], process);
		else
			SymCryptCbcDecrypt(bc, expKey, &m_iv[0], m_buffer.const_byte_str(), &out[0], process);
	}
	else // ECB
	{
		if (encrypt)
			SymCryptEcbEncrypt(bc, expKey, m_buffer.const_byte_str(), &out[0], process);
		else
			SymCryptEcbDecrypt(bc, expKey, m_buffer.const_byte_str(), &out[0], process);
	}

	m_buffer = m_buffer.substr(process);

	return true;
}

bool SymCryptSymmetricAlgorithm::blockModeFinal(ByteString& out, bool encrypt)
{
	size_t block = getBlockSize();
	out.wipe();

	PCSYMCRYPT_BLOCKCIPHER bc = getBlockCipher();
	PCVOID expKey = getExpandedKey();

	if (encrypt)
	{
		size_t rem = m_buffer.size();

		if (currentPaddingMode)
		{
			// PKCS#7 padding: always add between 1 and block bytes
			size_t padLen = block - (rem % block);

			ByteString padded = m_buffer;
			ByteString pad;
			pad.resize(padLen);
			for (size_t i = 0; i < padLen; i++)
			{
				pad[i] = (unsigned char) padLen;
			}
			padded += pad;

			out.resize(padded.size());
			if (currentCipherMode == SymMode::CBC)
				SymCryptCbcEncrypt(bc, expKey, &m_iv[0], padded.const_byte_str(), &out[0], padded.size());
			else
				SymCryptEcbEncrypt(bc, expKey, padded.const_byte_str(), &out[0], padded.size());
		}
		else if (rem != 0)
		{
			ERROR_MSG("Data length is not a multiple of the block size");
			return false;
		}
	}
	else // decrypt
	{
		size_t rem = m_buffer.size();

		if (currentPaddingMode)
		{
			if (rem != block)
			{
				ERROR_MSG("Invalid encrypted data length for padded decryption");
				return false;
			}

			ByteString dec;
			dec.resize(block);
			if (currentCipherMode == SymMode::CBC)
				SymCryptCbcDecrypt(bc, expKey, &m_iv[0], m_buffer.const_byte_str(), &dec[0], block);
			else
				SymCryptEcbDecrypt(bc, expKey, m_buffer.const_byte_str(), &dec[0], block);

			// Strip and validate PKCS#7 padding
			unsigned char padLen = dec[block - 1];
			if ((padLen == 0) || (padLen > block))
			{
				ERROR_MSG("Invalid PKCS#7 padding");
				return false;
			}
			for (size_t i = 0; i < padLen; i++)
			{
				if (dec[block - 1 - i] != padLen)
				{
					ERROR_MSG("Invalid PKCS#7 padding");
					return false;
				}
			}

			out = dec.substr(0, block - padLen);
		}
		else if (rem != 0)
		{
			ERROR_MSG("Encrypted data length is not a multiple of the block size");
			return false;
		}
	}

	m_buffer.wipe();

	return true;
}

// CTR mode streaming
bool SymCryptSymmetricAlgorithm::ctrUpdate(const ByteString& data, ByteString& out)
{
	size_t block = getBlockSize();

	m_buffer += data;
	out.wipe();

	size_t process = (m_buffer.size() / block) * block;
	if (process == 0)
	{
		return true;
	}

	out.resize(process);
	SymCryptCtrMsb64(getBlockCipher(), getExpandedKey(), &m_iv[0], m_buffer.const_byte_str(), &out[0], process);

	m_buffer = m_buffer.substr(process);
	m_processedBytes += process;

	return true;
}

bool SymCryptSymmetricAlgorithm::ctrFinal(ByteString& out)
{
	out.wipe();

	size_t rem = m_buffer.size();
	if (rem == 0)
	{
		return true;
	}

	size_t block = getBlockSize();

	ByteString inb;
	inb.resize(block);
	memset(&inb[0], 0, block);
	memcpy(&inb[0], m_buffer.const_byte_str(), rem);

	ByteString outb;
	outb.resize(block);
	SymCryptCtrMsb64(getBlockCipher(), getExpandedKey(), &m_iv[0], inb.const_byte_str(), &outb[0], block);

	out = outb.substr(0, rem);
	m_processedBytes += rem;
	m_buffer.wipe();

	return true;
}

// CFB mode streaming (full block feedback)
bool SymCryptSymmetricAlgorithm::cfbUpdate(const ByteString& data, ByteString& out, bool encrypt)
{
	size_t block = getBlockSize();

	m_buffer += data;
	out.wipe();

	size_t process = (m_buffer.size() / block) * block;
	if (process == 0)
	{
		return true;
	}

	out.resize(process);
	if (encrypt)
		SymCryptCfbEncrypt(getBlockCipher(), block, getExpandedKey(), &m_iv[0], m_buffer.const_byte_str(), &out[0], process);
	else
		SymCryptCfbDecrypt(getBlockCipher(), block, getExpandedKey(), &m_iv[0], m_buffer.const_byte_str(), &out[0], process);

	m_buffer = m_buffer.substr(process);

	return true;
}

bool SymCryptSymmetricAlgorithm::cfbFinal(ByteString& out, bool encrypt)
{
	out.wipe();

	size_t rem = m_buffer.size();
	if (rem == 0)
	{
		return true;
	}

	size_t block = getBlockSize();

	// The keystream for the trailing partial block is E(chaining value)
	ByteString ks;
	ks.resize(block);
	ecbEncryptBlock(&m_iv[0], &ks[0]);

	out.resize(rem);
	const unsigned char* in = m_buffer.const_byte_str();
	for (size_t i = 0; i < rem; i++)
	{
		out[i] = in[i] ^ ks[i];
	}

	(void) encrypt; // encrypt and decrypt use the same keystream for the tail
	m_buffer.wipe();

	return true;
}

// OFB mode streaming (implemented manually on top of ECB)
bool SymCryptSymmetricAlgorithm::ofbUpdate(const ByteString& data, ByteString& out)
{
	size_t block = getBlockSize();
	size_t len = data.size();

	out.resize(len);
	if (len == 0)
	{
		return true;
	}

	const unsigned char* in = data.const_byte_str();

	for (size_t i = 0; i < len; i++)
	{
		if (m_ofbOffset == 0 || m_ofbOffset == block)
		{
			// Generate the next keystream block O = E(feedback); the feedback for
			// the following block becomes O.
			ecbEncryptBlock(&m_iv[0], &m_ofbKeystream[0]);
			memcpy(&m_iv[0], m_ofbKeystream.const_byte_str(), block);
			m_ofbOffset = 0;
		}

		out[i] = in[i] ^ m_ofbKeystream[m_ofbOffset];
		m_ofbOffset++;
	}

	return true;
}

// Encryption functions
bool SymCryptSymmetricAlgorithm::encryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& aad /* = ByteString() */, size_t tagBytes /* = 0 */)
{
	if (!SymmetricAlgorithm::encryptInit(key, mode, IV, padding, counterBits, aad, tagBytes))
	{
		return false;
	}

	if (!cipherInit(key, mode, IV, padding, counterBits, aad, tagBytes, true))
	{
		ByteString dummy;
		SymmetricAlgorithm::encryptFinal(dummy);
		cleanup();
		return false;
	}

	return true;
}

bool SymCryptSymmetricAlgorithm::encryptUpdate(const ByteString& data, ByteString& encryptedData)
{
	if (!SymmetricAlgorithm::encryptUpdate(data, encryptedData))
	{
		cleanup();
		return false;
	}

	switch (currentCipherMode)
	{
		case SymMode::CBC:
		case SymMode::ECB:
			return blockModeUpdate(data, encryptedData, true);
		case SymMode::CTR:
			return ctrUpdate(data, encryptedData);
		case SymMode::CFB:
			return cfbUpdate(data, encryptedData, true);
		case SymMode::OFB:
			return ofbUpdate(data, encryptedData);
		case SymMode::GCM:
			m_buffer += data;
			encryptedData.wipe();
			return true;
		default:
			break;
	}

	ERROR_MSG("Invalid cipher mode %i", currentCipherMode);
	cleanup();
	return false;
}

bool SymCryptSymmetricAlgorithm::encryptFinal(ByteString& encryptedData)
{
	SymMode::Type mode = currentCipherMode;
	size_t tagBytes = currentTagBytes;

	encryptedData.wipe();

	bool ok = true;
	switch (mode)
	{
		case SymMode::CBC:
		case SymMode::ECB:
			ok = blockModeFinal(encryptedData, true);
			break;
		case SymMode::CTR:
			ok = ctrFinal(encryptedData);
			break;
		case SymMode::CFB:
			ok = cfbFinal(encryptedData, true);
			break;
		case SymMode::OFB:
			// No pending data for OFB
			break;
		case SymMode::GCM:
		{
			PCSYMCRYPT_GCM_EXPANDED_KEY gcmKey = getGcmExpandedKey();
			if (gcmKey == NULL)
			{
				ok = false;
				break;
			}

			size_t ptLen = m_buffer.size();
			ByteString ct;
			ct.resize(ptLen);
			ByteString tag;
			tag.resize(tagBytes);

			SymCryptGcmEncrypt(gcmKey,
				m_iv.const_byte_str(), m_iv.size(),
				m_aad.size() ? m_aad.const_byte_str() : NULL, m_aad.size(),
				ptLen ? m_buffer.const_byte_str() : NULL, ptLen ? &ct[0] : NULL, ptLen,
				&tag[0], tagBytes);

			encryptedData = ct;
			encryptedData += tag;
			break;
		}
		default:
			ok = false;
			break;
	}

	ByteString dummy;
	SymmetricAlgorithm::encryptFinal(dummy);
	cleanup();

	return ok;
}

// Decryption functions
bool SymCryptSymmetricAlgorithm::decryptInit(const SymmetricKey* key, const SymMode::Type mode /* = SymMode::CBC */, const ByteString& IV /* = ByteString() */, bool padding /* = true */, size_t counterBits /* = 0 */, const ByteString& aad /* = ByteString() */, size_t tagBytes /* = 0 */)
{
	if (!SymmetricAlgorithm::decryptInit(key, mode, IV, padding, counterBits, aad, tagBytes))
	{
		return false;
	}

	if (!cipherInit(key, mode, IV, padding, counterBits, aad, tagBytes, false))
	{
		ByteString dummy;
		SymmetricAlgorithm::decryptFinal(dummy);
		cleanup();
		return false;
	}

	return true;
}

bool SymCryptSymmetricAlgorithm::decryptUpdate(const ByteString& encryptedData, ByteString& data)
{
	// The base class accumulates the AEAD buffer for GCM mode
	if (!SymmetricAlgorithm::decryptUpdate(encryptedData, data))
	{
		cleanup();
		return false;
	}

	switch (currentCipherMode)
	{
		case SymMode::CBC:
		case SymMode::ECB:
			return blockModeUpdate(encryptedData, data, false);
		case SymMode::CTR:
			return ctrUpdate(encryptedData, data);
		case SymMode::CFB:
			return cfbUpdate(encryptedData, data, false);
		case SymMode::OFB:
			return ofbUpdate(encryptedData, data);
		case SymMode::GCM:
			// AEAD ciphers do not return plaintext until Final is called
			data.wipe();
			return true;
		default:
			break;
	}

	ERROR_MSG("Invalid cipher mode %i", currentCipherMode);
	cleanup();
	return false;
}

bool SymCryptSymmetricAlgorithm::decryptFinal(ByteString& data)
{
	SymMode::Type mode = currentCipherMode;
	size_t tagBytes = currentTagBytes;
	ByteString aeadBuffer = currentAEADBuffer;

	data.wipe();

	bool ok = true;
	switch (mode)
	{
		case SymMode::CBC:
		case SymMode::ECB:
			ok = blockModeFinal(data, false);
			break;
		case SymMode::CTR:
			ok = ctrFinal(data);
			break;
		case SymMode::CFB:
			ok = cfbFinal(data, false);
			break;
		case SymMode::OFB:
			// No pending data for OFB
			break;
		case SymMode::GCM:
		{
			PCSYMCRYPT_GCM_EXPANDED_KEY gcmKey = getGcmExpandedKey();
			if (gcmKey == NULL)
			{
				ok = false;
				break;
			}

			if (aeadBuffer.size() < tagBytes)
			{
				ERROR_MSG("Tag bytes (%d) does not fit in AEAD buffer (%d)", tagBytes, aeadBuffer.size());
				ok = false;
				break;
			}

			size_t ctLen = aeadBuffer.size() - tagBytes;
			ByteString ct = aeadBuffer.substr(0, ctLen);
			ByteString tag = aeadBuffer.substr(ctLen, tagBytes);

			ByteString pt;
			pt.resize(ctLen);

			SYMCRYPT_ERROR scError = SymCryptGcmDecrypt(gcmKey,
				m_iv.const_byte_str(), m_iv.size(),
				m_aad.size() ? m_aad.const_byte_str() : NULL, m_aad.size(),
				ctLen ? ct.const_byte_str() : NULL, ctLen ? &pt[0] : NULL, ctLen,
				tag.const_byte_str(), tagBytes);

			if (scError != SYMCRYPT_NO_ERROR)
			{
				ERROR_MSG("GCM authentication failed (0x%x)", scError);
				ok = false;
				break;
			}

			data = pt;
			break;
		}
		default:
			ok = false;
			break;
	}

	ByteString dummy;
	SymmetricAlgorithm::decryptFinal(dummy);
	cleanup();

	return ok;
}

// Check if more bytes of data can be encrypted
bool SymCryptSymmetricAlgorithm::checkMaximumBytes(unsigned long bytes)
{
	if (!m_maxBytesLimited)
	{
		return true;
	}

	return (m_processedBytes + bytes) <= m_maxBytes;
}
