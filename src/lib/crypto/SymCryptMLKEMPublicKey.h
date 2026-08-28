/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMPublicKey.h

 SymCrypt ML-KEM public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLKEMPUBLICKEY_H
#define _SOFTHSM_V2_SYMCRYPTMLKEMPUBLICKEY_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMPublicKey.h"
#include <symcrypt.h>

class SymCryptMLKEMPublicKey : public MLKEMPublicKey
{
public:
	// Constructors
	SymCryptMLKEMPublicKey();

	// Destructor
	virtual ~SymCryptMLKEMPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the ML-KEM public key components
	virtual void setValue(const ByteString& value);

	// Retrieve the SymCrypt representation of the key (built lazily, owned by
	// this object). Returns NULL on failure.
	PSYMCRYPT_MLKEMKEY getSymCryptKey();

private:
	// The internal SymCrypt representation
	mutable PSYMCRYPT_MLKEMKEY mlkemkey;

	// Release the cached SymCrypt object
	void freeSymCryptKey();

	// Build the SymCrypt key representation from the stored components
	void createSymCryptKey();
};

#endif // WITH_ML_KEM
#endif // !_SOFTHSM_V2_SYMCRYPTMLKEMPUBLICKEY_H
