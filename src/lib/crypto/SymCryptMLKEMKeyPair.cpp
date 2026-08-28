/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMKeyPair.cpp

 SymCrypt ML-KEM key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "SymCryptMLKEMKeyPair.h"

// Set the public key
void SymCryptMLKEMKeyPair::setPublicKey(SymCryptMLKEMPublicKey& publicKey)
{
	pubKey.setValue(publicKey.getValue());
}

// Set the private key
void SymCryptMLKEMKeyPair::setPrivateKey(SymCryptMLKEMPrivateKey& privateKey)
{
	privKey.setValue(privateKey.getValue());
	privKey.setSeed(privateKey.getSeed());
}

// Return the public key
PublicKey* SymCryptMLKEMKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* SymCryptMLKEMKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* SymCryptMLKEMKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* SymCryptMLKEMKeyPair::getConstPrivateKey() const
{
	return &privKey;
}

#endif // WITH_ML_KEM
