/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEM.h

 SymCrypt ML-KEM asymmetric algorithm implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLKEM_H
#define _SOFTHSM_V2_SYMCRYPTMLKEM_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "AsymmetricAlgorithm.h"

class SymCryptMLKEM : public AsymmetricAlgorithm
{
public:
	// Destructor
	virtual ~SymCryptMLKEM() { }

	// Signing functions (not supported by ML-KEM)
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);

	// Encryption functions (not supported by ML-KEM)
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);

	// Decryption functions (not supported by ML-KEM)
	virtual bool checkEncryptedDataSize(PrivateKey* privateKey, const ByteString& encryptedData, int* errorCode);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);

	// Encapsulate/Decapsulate keys
	virtual bool encapsulate(PublicKey* publicKey, ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type mechanism);
	virtual bool decapsulate(PrivateKey* privateKey, const ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type mechanism);

	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();

	// Key factory
	virtual bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng = NULL);
	virtual bool reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData);
	virtual bool reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData);
	virtual bool reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData);
	virtual bool reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();
	virtual AsymmetricParameters* newParameters();
};

#endif // WITH_ML_KEM
#endif // !_SOFTHSM_V2_SYMCRYPTMLKEM_H
