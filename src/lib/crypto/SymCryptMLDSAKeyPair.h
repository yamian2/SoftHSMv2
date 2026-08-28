/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAKeyPair.h

 SymCrypt ML-DSA key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLDSAKEYPAIR_H
#define _SOFTHSM_V2_SYMCRYPTMLDSAKEYPAIR_H

#include "config.h"
#ifdef WITH_ML_DSA
#include "AsymmetricKeyPair.h"
#include "SymCryptMLDSAPublicKey.h"
#include "SymCryptMLDSAPrivateKey.h"

class SymCryptMLDSAKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(SymCryptMLDSAPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(SymCryptMLDSAPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	SymCryptMLDSAPublicKey pubKey;

	// The private key
	SymCryptMLDSAPrivateKey privKey;
};

#endif // WITH_ML_DSA
#endif // !_SOFTHSM_V2_SYMCRYPTMLDSAKEYPAIR_H
