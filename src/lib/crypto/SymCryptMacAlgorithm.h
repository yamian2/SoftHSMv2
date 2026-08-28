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
 SymCryptMacAlgorithm.h

 SymCrypt MAC algorithm implementation

 The generic SymCryptMacAlgorithm base class drives all of the SymCrypt MAC
 algorithms that expose a SYMCRYPT_MAC vtable (all HMAC variants and AES-CMAC).
 The concrete subclasses only need to return the SymCrypt algorithm definition.

 SymCrypt does not ship a CMAC based on (3)DES, so SymCryptCMACDES implements
 the CMAC construction (NIST SP 800-38B) on top of the SymCrypt (3)DES block
 cipher primitive.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMACALGORITHM_H
#define _SOFTHSM_V2_SYMCRYPTMACALGORITHM_H

#include "config.h"
#include "MacAlgorithm.h"
#include <symcrypt.h>

class SymCryptMacAlgorithm : public MacAlgorithm
{
public:
	// Constructor
	SymCryptMacAlgorithm();

	// Destructor
	virtual ~SymCryptMacAlgorithm() { }

	// Signing functions
	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	// Return the MAC size
	virtual size_t getMacSize() const;

protected:
	// Return the SymCrypt MAC algorithm definition
	virtual PCSYMCRYPT_MAC getMacDefinition() const = 0;

private:
	// Expand the key and initialise the MAC state
	bool doInit(const SymmetricKey* key);

	// The SymCrypt MAC state and expanded key
	SYMCRYPT_MAC_EXPANDED_KEY expandedKey;
	SYMCRYPT_MAC_STATE state;

	// Whether the MAC state has been initialised
	bool initialised;
};

class SymCryptHMACMD5 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptHMACSHA1 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptHMACSHA224 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptHMACSHA256 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptHMACSHA384 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptHMACSHA512 : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

class SymCryptCMACAES : public SymCryptMacAlgorithm
{
protected:
	virtual PCSYMCRYPT_MAC getMacDefinition() const;
};

// (3)DES CMAC (NIST SP 800-38B) built on the SymCrypt (3)DES block cipher,
// since SymCrypt does not provide a native (3)DES CMAC.
class SymCryptCMACDES : public MacAlgorithm
{
public:
	// Constructor
	SymCryptCMACDES();

	// Destructor
	virtual ~SymCryptCMACDES() { }

	// Signing functions
	virtual bool signInit(const SymmetricKey* key);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verifyInit(const SymmetricKey* key);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(ByteString& signature);

	// Return the MAC size
	virtual size_t getMacSize() const;

private:
	// The (3)DES block size in bytes
	static const size_t DES_BLOCK = 8;

	// Expand the key, derive the CMAC subkeys and reset the state
	bool doInit(const SymmetricKey* key);

	// Feed data into the running CMAC computation
	void cmacAppend(const ByteString& data);

	// Finalise the CMAC computation into the provided buffer
	void cmacResult(ByteString& mac);

	// Encrypt a single block in-place through the CBC-MAC chaining value
	void processBlock(const unsigned char* in);

	// The SymCrypt (3)DES expanded key
	SYMCRYPT_3DES_EXPANDED_KEY desKey;

	// The CMAC subkeys
	unsigned char k1[DES_BLOCK];
	unsigned char k2[DES_BLOCK];

	// The CBC-MAC chaining value
	unsigned char chaining[DES_BLOCK];

	// The buffer holding pending (not yet processed) input bytes
	unsigned char block[DES_BLOCK];
	size_t blockLen;

	// Whether the state has been initialised
	bool initialised;
};

#endif // !_SOFTHSM_V2_SYMCRYPTMACALGORITHM_H
