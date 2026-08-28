/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSA.h

 SymCrypt composite ML-DSA asymmetric algorithm implementation. Composition is
 performed externally: a fresh ML-DSA key and a fresh ECDSA key are generated
 and combined per draft-ietf-lamps-pq-composite-sigs, transparently to the
 caller. SymCrypt provides the ML-DSA and ECDSA primitives.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSA_H
#define _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSA_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "AsymmetricAlgorithm.h"

class SymCryptCompositeMLDSA : public AsymmetricAlgorithm
{
public:
	SymCryptCompositeMLDSA() : message(), mechanismParameters(NULL) { }

	// Destructor
	virtual ~SymCryptCompositeMLDSA();

	// Signing functions
	virtual bool sign(PrivateKey* privateKey, const ByteString& dataToSign, ByteString& signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	// Verification functions
	virtual bool verify(PublicKey* publicKey, const ByteString& originalData, const ByteString& signature, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const MechanismParam* mechanismParam = NULL);
	virtual bool verifyUpdate(const ByteString& originalData);
	virtual bool verifyFinal(const ByteString& signature);

	// Encryption functions
	virtual bool encrypt(PublicKey* publicKey, const ByteString& data, ByteString& encryptedData, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);

	// Decryption functions
	virtual bool checkEncryptedDataSize(PrivateKey* privateKey, const ByteString& encryptedData, int* errorCode);
	virtual bool decrypt(PrivateKey* privateKey, const ByteString& encryptedData, ByteString& data, const AsymMech::Type padding,
		 const MechanismParam* mechanismParam = NULL);
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

private:
	ByteString message;
	const MechanismParam* mechanismParameters;
};

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSA_H
