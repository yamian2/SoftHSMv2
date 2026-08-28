/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAKeyPair.h

 SymCrypt composite ML-DSA key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAKEYPAIR_H
#define _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAKEYPAIR_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "AsymmetricKeyPair.h"
#include "SymCryptCompositeMLDSAPublicKey.h"
#include "SymCryptCompositeMLDSAPrivateKey.h"

class SymCryptCompositeMLDSAKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(SymCryptCompositeMLDSAPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(SymCryptCompositeMLDSAPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	SymCryptCompositeMLDSAPublicKey pubKey;
	SymCryptCompositeMLDSAPrivateKey privKey;
};

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAKEYPAIR_H
