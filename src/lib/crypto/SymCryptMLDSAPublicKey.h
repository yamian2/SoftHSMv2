/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAPublicKey.h

 SymCrypt ML-DSA public key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLDSAPUBLICKEY_H
#define _SOFTHSM_V2_SYMCRYPTMLDSAPUBLICKEY_H

#include "config.h"
#ifdef WITH_ML_DSA
#include "MLDSAPublicKey.h"
#include <symcrypt.h>

class SymCryptMLDSAPublicKey : public MLDSAPublicKey
{
public:
	// Constructors
	SymCryptMLDSAPublicKey();

	// Destructor
	virtual ~SymCryptMLDSAPublicKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the ML-DSA public key components
	virtual void setValue(const ByteString& value);

	// Retrieve the SymCrypt representation of the key (built lazily, owned by
	// this object). Returns NULL on failure.
	PSYMCRYPT_MLDSAKEY getSymCryptKey();

private:
	// The internal SymCrypt representation
	mutable PSYMCRYPT_MLDSAKEY mldsakey;

	// Release the cached SymCrypt object
	void freeSymCryptKey();

	// Build the SymCrypt key representation from the stored components
	void createSymCryptKey();
};

#endif // WITH_ML_DSA
#endif // !_SOFTHSM_V2_SYMCRYPTMLDSAPUBLICKEY_H
