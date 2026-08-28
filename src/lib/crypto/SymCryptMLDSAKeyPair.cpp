/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAKeyPair.cpp

 SymCrypt ML-DSA key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "SymCryptMLDSAKeyPair.h"

// Set the public key
void SymCryptMLDSAKeyPair::setPublicKey(SymCryptMLDSAPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
}

// Set the private key
void SymCryptMLDSAKeyPair::setPrivateKey(SymCryptMLDSAPrivateKey& privateKey)
{
	privKey.setValue(privateKey.getValue());
	privKey.setSeed(privateKey.getSeed());
}

// Return the public key
PublicKey* SymCryptMLDSAKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* SymCryptMLDSAKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* SymCryptMLDSAKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* SymCryptMLDSAKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif // WITH_ML_DSA
