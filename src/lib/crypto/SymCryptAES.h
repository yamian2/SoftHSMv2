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
 SymCryptAES.h

 SymCrypt AES implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTAES_H
#define _SOFTHSM_V2_SYMCRYPTAES_H

#include <string>
#include "config.h"
#include "SymmetricKey.h"
#include "SymCryptSymmetricAlgorithm.h"
#include <symcrypt.h>

class SymCryptAES : public SymCryptSymmetricAlgorithm
{
public:
	// Constructor
	SymCryptAES();

	// Destructor
	virtual ~SymCryptAES() { }

	// Wrap/Unwrap keys
	virtual bool wrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);
	virtual bool unwrapKey(const SymmetricKey* key, const SymWrap::Type mode, const ByteString& in, ByteString& out);

	// Return the block size
	virtual size_t getBlockSize() const;

protected:
	virtual PCSYMCRYPT_BLOCKCIPHER getBlockCipher() const;
	virtual bool isValidKeyLength(unsigned long bitLen) const;
	virtual bool expandKey(const ByteString& keyBits, SymMode::Type mode);
	virtual PCVOID getExpandedKey() const;
	virtual PCSYMCRYPT_GCM_EXPANDED_KEY getGcmExpandedKey() const;

private:
	// RFC 3394 / RFC 5649 key wrapping primitives
	bool rfc3394Wrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const unsigned char* iv, const ByteString& in, ByteString& out) const;
	bool rfc3394Unwrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, unsigned char* outIv, ByteString& out) const;
	bool rfc5649Wrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, ByteString& out) const;
	bool rfc5649Unwrap(const SYMCRYPT_AES_EXPANDED_KEY* kek, const ByteString& in, ByteString& out) const;

	SYMCRYPT_AES_EXPANDED_KEY m_aesKey;
	SYMCRYPT_GCM_EXPANDED_KEY m_gcmKey;
	bool                      m_gcmKeyValid;
};

#endif // !_SOFTHSM_V2_SYMCRYPTAES_H
