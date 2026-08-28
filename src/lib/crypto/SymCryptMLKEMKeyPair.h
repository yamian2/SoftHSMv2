/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMKeyPair.h

 SymCrypt ML-KEM key-pair class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLKEMKEYPAIR_H
#define _SOFTHSM_V2_SYMCRYPTMLKEMKEYPAIR_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "AsymmetricKeyPair.h"
#include "SymCryptMLKEMPublicKey.h"
#include "SymCryptMLKEMPrivateKey.h"

class SymCryptMLKEMKeyPair : public AsymmetricKeyPair
{
public:
	// Set the public key
	void setPublicKey(SymCryptMLKEMPublicKey& publicKey);

	// Set the private key
	void setPrivateKey(SymCryptMLKEMPrivateKey& privateKey);

	// Return the public key
	virtual PublicKey* getPublicKey();
	virtual const PublicKey* getConstPublicKey() const;

	// Return the private key
	virtual PrivateKey* getPrivateKey();
	virtual const PrivateKey* getConstPrivateKey() const;

private:
	// The public key
	SymCryptMLKEMPublicKey pubKey;

	// The private key
	SymCryptMLKEMPrivateKey privKey;
};

#endif // WITH_ML_KEM
#endif // !_SOFTHSM_V2_SYMCRYPTMLKEMKEYPAIR_H
