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
 SymCryptSymmetricAlgorithm.h

 SymCrypt symmetric algorithm implementation

 This base class drives all of the block cipher modes of operation (CBC, ECB,
 CTR, CFB, OFB and GCM) on top of the generic SymCrypt block cipher API. The
 concrete AES and (3)DES subclasses only need to provide key expansion and the
 SymCrypt block cipher description table.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTSYMMETRICALGORITHM_H
#define _SOFTHSM_V2_SYMCRYPTSYMMETRICALGORITHM_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "SymmetricAlgorithm.h"
#include <symcrypt.h>

class SymCryptSymmetricAlgorithm : public SymmetricAlgorithm
{
public:
	// Constructor
	SymCryptSymmetricAlgorithm();

	// Destructor
	virtual ~SymCryptSymmetricAlgorithm();

	// Encryption functions
	virtual bool encryptInit(const SymmetricKey* key, const SymMode::Type mode = SymMode::CBC, const ByteString& IV = ByteString(), bool padding = true, size_t counterBits = 0, const ByteString& aad = ByteString(), size_t tagBytes = 0);
	virtual bool encryptUpdate(const ByteString& data, ByteString& encryptedData);
	virtual bool encryptFinal(ByteString& encryptedData);

	// Decryption functions
	virtual bool decryptInit(const SymmetricKey* key, const SymMode::Type mode = SymMode::CBC, const ByteString& IV = ByteString(), bool padding = true, size_t counterBits = 0, const ByteString& aad = ByteString(), size_t tagBytes = 0);
	virtual bool decryptUpdate(const ByteString& encryptedData, ByteString& data);
	virtual bool decryptFinal(ByteString& data);

	// Return the block size
	virtual size_t getBlockSize() const = 0;

	// Check if more bytes of data can be encrypted
	virtual bool checkMaximumBytes(unsigned long bytes);

protected:
	// Provided by the concrete cipher subclasses

	// Return the SymCrypt block cipher description table
	virtual PCSYMCRYPT_BLOCKCIPHER getBlockCipher() const = 0;

	// Validate the key length (in bits) for this cipher
	virtual bool isValidKeyLength(unsigned long bitLen) const = 0;

	// Expand the given raw key material into the subclass storage. When mode is
	// GCM the subclass must also prepare a GCM expanded key.
	virtual bool expandKey(const ByteString& keyBits, SymMode::Type mode) = 0;

	// Pointer to the expanded block cipher key (used for CBC/ECB/CTR/CFB/OFB)
	virtual PCVOID getExpandedKey() const = 0;

	// Pointer to the expanded GCM key, or NULL if this cipher does not support GCM
	virtual PCSYMCRYPT_GCM_EXPANDED_KEY getGcmExpandedKey() const = 0;

	// Encrypt a single block using ECB (helper for OFB/CFB tail handling)
	void ecbEncryptBlock(const unsigned char* in, unsigned char* out) const;

private:
	bool cipherInit(const SymmetricKey* key, SymMode::Type mode, const ByteString& IV, bool padding, size_t counterBits, const ByteString& aad, size_t tagBytes, bool encrypt);
	bool blockModeUpdate(const ByteString& data, ByteString& out, bool encrypt);
	bool blockModeFinal(ByteString& out, bool encrypt);
	bool ctrUpdate(const ByteString& data, ByteString& out);
	bool ctrFinal(ByteString& out);
	bool cfbUpdate(const ByteString& data, ByteString& out, bool encrypt);
	bool cfbFinal(ByteString& out, bool encrypt);
	bool ofbUpdate(const ByteString& data, ByteString& out);
	void computeCounterMax(const ByteString& iv, size_t counterBits);
	void cleanup();

	// The chaining value / counter block (block size), or the nonce for GCM
	ByteString m_iv;

	// Pending input that has not yet been processed
	ByteString m_buffer;

	// The associated authentication data for GCM
	ByteString m_aad;

	// Keystream state for OFB streaming
	ByteString m_ofbKeystream;
	size_t     m_ofbOffset;

	// CTR maximum bytes tracking
	bool               m_maxBytesLimited;
	unsigned long long m_maxBytes;
	unsigned long long m_processedBytes;
};

#endif // !_SOFTHSM_V2_SYMCRYPTSYMMETRICALGORITHM_H
