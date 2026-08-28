/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMPublicKey.cpp

 SymCrypt ML-KEM public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "SymCryptMLKEMPublicKey.h"
#include "SymCryptMLKEMUtil.h"
#include "MLKEMParameters.h"
#include <string.h>

// Constructors
SymCryptMLKEMPublicKey::SymCryptMLKEMPublicKey()
{
	mlkemkey = NULL;
}

// Destructor
SymCryptMLKEMPublicKey::~SymCryptMLKEMPublicKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptMLKEMPublicKey::type = "SymCrypt ML-KEM Public Key";

// Check if the key is of the given type
bool SymCryptMLKEMPublicKey::isOfType(const char* inType)
{
	return !strcmp(SymCryptMLKEMPublicKey::type, inType) || MLKEMPublicKey::isOfType(inType);
}

void SymCryptMLKEMPublicKey::setValue(const ByteString& inValue)
{
	MLKEMPublicKey::setValue(inValue);

	freeSymCryptKey();
}

// Release the cached SymCrypt object
void SymCryptMLKEMPublicKey::freeSymCryptKey()
{
	if (mlkemkey != NULL)
	{
		SymCryptMlKemkeyFree(mlkemkey);
		mlkemkey = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_MLKEMKEY SymCryptMLKEMPublicKey::getSymCryptKey()
{
	if (mlkemkey == NULL)
	{
		createSymCryptKey();
	}

	return mlkemkey;
}

// Build the SymCrypt key representation from the stored components
void SymCryptMLKEMPublicKey::createSymCryptKey()
{
	if (mlkemkey != NULL)
	{
		return;
	}

	if (value.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt ML-KEM public key: missing value");
		return;
	}

	SYMCRYPT_MLKEM_PARAMS params;
	if (!SymMLKEM::paramsFromParameterSet(getParameterSet(), params))
	{
		ERROR_MSG("Unknown ML-KEM parameter set (public key length: %zu)", (size_t)value.size());
		return;
	}

	PSYMCRYPT_MLKEMKEY key = SymCryptMlKemkeyAllocate(params);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-KEM key");
		return;
	}

	SYMCRYPT_ERROR scError = SymCryptMlKemkeySetValue(
		value.const_byte_str(), value.size(),
		SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlKemkeySetValue (encapsulation key) failed (0x%08X)", (unsigned)scError);
		SymCryptMlKemkeyFree(key);
		return;
	}

	mlkemkey = key;
}

#endif // WITH_ML_KEM
