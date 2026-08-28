/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAKeyPair.cpp

 SymCrypt composite ML-DSA key-pair class
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "log.h"
#include "SymCryptCompositeMLDSAKeyPair.h"

// Set the public key
void SymCryptCompositeMLDSAKeyPair::setPublicKey(SymCryptCompositeMLDSAPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
	pubKey.setAlgorithm(publicKey.getAlgorithm());
}

// Set the private key
void SymCryptCompositeMLDSAKeyPair::setPrivateKey(SymCryptCompositeMLDSAPrivateKey& privateKey)
{
	privKey.setValue(privateKey.getValue());
	privKey.setAlgorithm(privateKey.getAlgorithm());
}

// Return the public key
PublicKey* SymCryptCompositeMLDSAKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* SymCryptCompositeMLDSAKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* SymCryptCompositeMLDSAKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* SymCryptCompositeMLDSAKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif // WITH_ML_DSA && WITH_ECC
