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
 SymCryptHashAlgorithm.h

 Base class for SymCrypt hash algorithm classes. SymCrypt exposes a generic
 hash object interface (PCSYMCRYPT_HASH) very similar to OpenSSL's EVP_MD, so
 a single base class parameterised by the hash object handles every digest.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTHASHALGORITHM_H
#define _SOFTHSM_V2_SYMCRYPTHASHALGORITHM_H

#include "config.h"
#include "HashAlgorithm.h"
#include <symcrypt.h>

class SymCryptHashAlgorithm : public HashAlgorithm
{
public:
	// Base constructor
	SymCryptHashAlgorithm() : HashAlgorithm() { }

	// Hashing functions
	virtual bool hashInit();
	virtual bool hashUpdate(const ByteString& data);
	virtual bool hashFinal(ByteString& hashedData);

	virtual int getHashSize() = 0;

protected:
	// Return the SymCrypt hash object for this digest
	virtual PCSYMCRYPT_HASH getHash() const = 0;

private:
	// The current hashing state. This union is large enough to hold the state
	// of any of the digests SoftHSM supports (SHA-224 shares the SHA-256 state
	// and SHA-384 shares the SHA-512 state).
	union
	{
		SYMCRYPT_MD5_STATE    md5;
		SYMCRYPT_SHA1_STATE   sha1;
		SYMCRYPT_SHA256_STATE sha256;
		SYMCRYPT_SHA512_STATE sha512;
	} curCTX;
};

#endif // !_SOFTHSM_V2_SYMCRYPTHASHALGORITHM_H
