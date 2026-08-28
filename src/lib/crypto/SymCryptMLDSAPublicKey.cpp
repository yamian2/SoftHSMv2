/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAPublicKey.cpp

 SymCrypt ML-DSA public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "SymCryptMLDSAPublicKey.h"
#include "SymCryptMLDSAUtil.h"
#include "MLDSAParameters.h"
#include <string.h>

// Constructors
SymCryptMLDSAPublicKey::SymCryptMLDSAPublicKey()
{
	mldsakey = NULL;
}

// Destructor
SymCryptMLDSAPublicKey::~SymCryptMLDSAPublicKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptMLDSAPublicKey::type = "SymCrypt ML-DSA Public Key";

// Check if the key is of the given type
bool SymCryptMLDSAPublicKey::isOfType(const char* inType)
{
	return !strcmp(SymCryptMLDSAPublicKey::type, inType) || MLDSAPublicKey::isOfType(inType);
}

void SymCryptMLDSAPublicKey::setValue(const ByteString& inValue)
{
	MLDSAPublicKey::setValue(inValue);

	freeSymCryptKey();
}

// Release the cached SymCrypt object
void SymCryptMLDSAPublicKey::freeSymCryptKey()
{
	if (mldsakey != NULL)
	{
		SymCryptMlDsakeyFree(mldsakey);
		mldsakey = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_MLDSAKEY SymCryptMLDSAPublicKey::getSymCryptKey()
{
	if (mldsakey == NULL)
	{
		createSymCryptKey();
	}

	return mldsakey;
}

// Build the SymCrypt key representation from the stored components
void SymCryptMLDSAPublicKey::createSymCryptKey()
{
	if (mldsakey != NULL)
	{
		return;
	}

	if (value.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt ML-DSA public key: missing value");
		return;
	}

	SYMCRYPT_MLDSA_PARAMS params;
	if (!SymMLDSA::paramsFromParameterSet(getParameterSet(), params))
	{
		ERROR_MSG("Unknown ML-DSA parameter set (public key length: %zu)", (size_t)value.size());
		return;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(params);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-DSA key");
		return;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeySetValue(
		value.const_byte_str(), value.size(),
		SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsakeySetValue (public) failed (0x%08X)", (unsigned)scError);
		SymCryptMlDsakeyFree(key);
		return;
	}

	mldsakey = key;
}

#endif // WITH_ML_DSA
