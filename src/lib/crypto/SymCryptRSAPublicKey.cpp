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
 SymCryptRSAPublicKey.cpp

 SymCrypt RSA public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptRSAPublicKey.h"
#include "SymCryptUtil.h"
#include <string.h>

// Constructors
SymCryptRSAPublicKey::SymCryptRSAPublicKey()
{
	rsa = NULL;
}

// Destructor
SymCryptRSAPublicKey::~SymCryptRSAPublicKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptRSAPublicKey::type = "SymCrypt RSA Public Key";

// Check if the key is of the given type
bool SymCryptRSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the RSA public key components
void SymCryptRSAPublicKey::setN(const ByteString& inN)
{
	RSAPublicKey::setN(inN);

	freeSymCryptKey();
}

void SymCryptRSAPublicKey::setE(const ByteString& inE)
{
	RSAPublicKey::setE(inE);

	freeSymCryptKey();
}

// Release the cached SymCrypt key
void SymCryptRSAPublicKey::freeSymCryptKey()
{
	if (rsa != NULL)
	{
		SymCryptRsakeyFree(rsa);
		rsa = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_RSAKEY SymCryptRSAPublicKey::getSymCryptKey()
{
	if (rsa == NULL)
	{
		createSymCryptKey();
	}

	return rsa;
}

// Build the SymCrypt representation from the stored components
void SymCryptRSAPublicKey::createSymCryptKey()
{
	if (rsa != NULL)
	{
		return;
	}

	if (n.size() == 0 || e.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt RSA public key: missing modulus or exponent");
		return;
	}

	UINT64 pubExp = 0;
	if (!SymUtil::toUInt64(e, pubExp))
	{
		ERROR_MSG("RSA public exponent does not fit in 64 bits");
		return;
	}

	SYMCRYPT_RSA_PARAMS params;
	params.version = 1;
	params.nBitsOfModulus = SymUtil::bitLength(n);
	params.nPrimes = 0;
	params.nPubExp = 1;

	PSYMCRYPT_RSAKEY key = SymCryptRsakeyAllocate(&params, 0);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt RSA public key");
		return;
	}

	SYMCRYPT_ERROR scError = SymCryptRsakeySetValue(
		n.const_byte_str(), n.size(),
		&pubExp, 1,
		NULL, NULL, 0,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCryptRsakeySetValue (public)", scError);
		SymCryptRsakeyFree(key);
		return;
	}

	rsa = key;
}
