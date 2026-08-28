/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMPrivateKey.h

 SymCrypt ML-KEM private key class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLKEMPRIVATEKEY_H
#define _SOFTHSM_V2_SYMCRYPTMLKEMPRIVATEKEY_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMPrivateKey.h"
#include <symcrypt.h>

class SymCryptMLKEMPrivateKey : public MLKEMPrivateKey
{
public:
	// Constructors
	SymCryptMLKEMPrivateKey();

	// Destructor
	virtual ~SymCryptMLKEMPrivateKey();

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Setters for the ML-KEM private key components
	virtual void setValue(const ByteString& value);
	virtual void setSeed(const ByteString& seed);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

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
#endif // !_SOFTHSM_V2_SYMCRYPTMLKEMPRIVATEKEY_H
