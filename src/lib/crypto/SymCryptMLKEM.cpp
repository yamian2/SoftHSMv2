/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEM.cpp

 SymCrypt ML-KEM asymmetric algorithm implementation

 Notes:
 - ML-KEM is a key-encapsulation mechanism; it supports neither signing nor
   encryption. Only encapsulate/decapsulate and key management are implemented.
 - The agreed (shared) secret is always 32 bytes for every ML-KEM parameter set.
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "SymCryptMLKEM.h"
#include "CryptoFactory.h"
#include "MLKEMParameters.h"
#include "SymCryptMLKEMKeyPair.h"
#include "SymCryptMLKEMPublicKey.h"
#include "SymCryptMLKEMPrivateKey.h"
#include "SymCryptMLKEMUtil.h"
#include "AESKey.h"
#include <symcrypt.h>
#include <string.h>

// The agreed secret is 32 bytes for all ML-KEM parameter sets (FIPS 203)
static const size_t ML_KEM_SHARED_SECRET_SIZE = 32;

// Signing functions (not supported by ML-KEM)
bool SymCryptMLKEM::sign(PrivateKey* /*privateKey*/, const ByteString& /*dataToSign*/,
						 ByteString& /*signature*/, const AsymMech::Type /*mechanism*/,
						 const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-KEM does not support signing");

	return false;
}

bool SymCryptMLKEM::verify(PublicKey* /*publicKey*/, const ByteString& /*originalData*/,
						   const ByteString& /*signature*/, const AsymMech::Type /*mechanism*/,
						   const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-KEM does not support verifying");

	return false;
}

// Encryption functions (not supported by ML-KEM)
bool SymCryptMLKEM::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
							ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
							const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-KEM does not support encryption");

	return false;
}

// Decryption functions (not supported by ML-KEM)
bool SymCryptMLKEM::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
							ByteString& /*data*/, const AsymMech::Type /*padding*/,
							const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-KEM does not support decryption");

	return false;
}

bool SymCryptMLKEM::checkEncryptedDataSize(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, int* /*errorCode*/)
{
	ERROR_MSG("ML-KEM does not support encryption");

	return false;
}

// Encapsulate a freshly generated shared secret against the recipient public key
bool SymCryptMLKEM::encapsulate(PublicKey* publicKey, ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type /*mechanism*/)
{
	if (publicKey == NULL || secretKey == NULL || !publicKey->isOfType(SymCryptMLKEMPublicKey::type))
	{
		ERROR_MSG("Invalid ML-KEM public key input");
		return false;
	}

	SymCryptMLKEMPublicKey* pk = (SymCryptMLKEMPublicKey*)publicKey;

	unsigned long ctLen = pk->getOutputLength();
	if (ctLen == 0)
	{
		ERROR_MSG("Could not determine the ML-KEM ciphertext length");
		return false;
	}

	PSYMCRYPT_MLKEMKEY key = pk->getSymCryptKey();
	if (key == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt public key");
		return false;
	}

	ByteString secretKeyValue;
	secretKeyValue.resize(ML_KEM_SHARED_SECRET_SIZE);
	cipherText.resize(ctLen);

	SYMCRYPT_ERROR scError = SymCryptMlKemEncapsulate(
		key,
		&secretKeyValue[0], ML_KEM_SHARED_SECRET_SIZE,
		&cipherText[0], ctLen);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlKemEncapsulate failed (0x%08X)", (unsigned)scError);
		return false;
	}

	if (keyType == CKK_AES)
	{
		*secretKey = new AESKey(ML_KEM_SHARED_SECRET_SIZE * 8);
	}
	else
	{
		*secretKey = new SymmetricKey(ML_KEM_SHARED_SECRET_SIZE * 8);
	}

	if (!(*secretKey)->setKeyBits(secretKeyValue))
	{
		delete *secretKey;
		*secretKey = NULL;
		return false;
	}

	return true;
}

// Decapsulate the shared secret from a ciphertext using the recipient private key
bool SymCryptMLKEM::decapsulate(PrivateKey* privateKey, const ByteString& cipherText, SymmetricKey** secretKey, CK_KEY_TYPE keyType, const AsymMech::Type /*mechanism*/)
{
	if (privateKey == NULL || secretKey == NULL || !privateKey->isOfType(SymCryptMLKEMPrivateKey::type))
	{
		ERROR_MSG("Invalid ML-KEM private key input");
		return false;
	}

	SymCryptMLKEMPrivateKey* pk = (SymCryptMLKEMPrivateKey*)privateKey;

	unsigned long ctLen = pk->getOutputLength();
	if (ctLen == 0)
	{
		ERROR_MSG("Could not determine the ML-KEM ciphertext length");
		return false;
	}
	if (cipherText.size() != ctLen)
	{
		ERROR_MSG("Invalid ML-KEM ciphertext length");
		return false;
	}

	PSYMCRYPT_MLKEMKEY key = pk->getSymCryptKey();
	if (key == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt private key");
		return false;
	}

	ByteString secretKeyValue;
	secretKeyValue.resize(ML_KEM_SHARED_SECRET_SIZE);

	SYMCRYPT_ERROR scError = SymCryptMlKemDecapsulate(
		key,
		cipherText.const_byte_str(), cipherText.size(),
		&secretKeyValue[0], ML_KEM_SHARED_SECRET_SIZE);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlKemDecapsulate failed (0x%08X)", (unsigned)scError);
		return false;
	}

	if (keyType == CKK_AES)
	{
		*secretKey = new AESKey(ML_KEM_SHARED_SECRET_SIZE * 8);
	}
	else
	{
		*secretKey = new SymmetricKey(ML_KEM_SHARED_SECRET_SIZE * 8);
	}

	if (!(*secretKey)->setKeyBits(secretKeyValue))
	{
		delete *secretKey;
		*secretKey = NULL;
		return false;
	}

	return true;
}

unsigned long SymCryptMLKEM::getMinKeySize()
{
	return MLKEMParameters::ML_KEM_512_PRIV_LENGTH;
}

unsigned long SymCryptMLKEM::getMaxKeySize()
{
	return MLKEMParameters::ML_KEM_1024_PRIV_LENGTH;
}

// Key factory
bool SymCryptMLKEM::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* inParameters, RNG* /*rng = NULL*/)
{
	// Check parameters
	if ((ppKeyPair == NULL) || (inParameters == NULL))
	{
		return false;
	}

	if (!inParameters->areOfType(MLKEMParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-KEM key generation");
		return false;
	}

	MLKEMParameters* params = (MLKEMParameters*)inParameters;

	SYMCRYPT_MLKEM_PARAMS scParams;
	if (!SymMLKEM::paramsFromParameterSet(params->getParameterSet(), scParams))
	{
		ERROR_MSG("Unknown ML-KEM parameter set (%lu)", params->getParameterSet());
		return false;
	}

	PSYMCRYPT_MLKEMKEY key = SymCryptMlKemkeyAllocate(scParams);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-KEM key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlKemkeyGenerate(key, 0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlKemkeyGenerate failed (0x%08X)", (unsigned)scError);
		SymCryptMlKemkeyFree(key);
		return false;
	}

	// Determine the sizes of the exportable formats
	SIZE_T cbPub = 0, cbPriv = 0;
	if (SymCryptMlKemSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, &cbPub) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlKemSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &cbPriv) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not determine ML-KEM key format sizes");
		SymCryptMlKemkeyFree(key);
		return false;
	}

	ByteString pubBS, privBS, seedBS;
	pubBS.resize(cbPub);
	privBS.resize(cbPriv);
	seedBS.resize(SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE);

	if (SymCryptMlKemkeyGetValue(key, &pubBS[0], cbPub, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, 0) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlKemkeyGetValue(key, &privBS[0], cbPriv, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, 0) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlKemkeyGetValue(key, &seedBS[0], SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, 0) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not export ML-KEM key material");
		SymCryptMlKemkeyFree(key);
		return false;
	}

	SymCryptMlKemkeyFree(key);

	// Create an asymmetric key-pair object to return
	SymCryptMLKEMKeyPair* kp = new SymCryptMLKEMKeyPair();

	((SymCryptMLKEMPublicKey*)kp->getPublicKey())->setValue(pubBS);
	((SymCryptMLKEMPrivateKey*)kp->getPrivateKey())->setValue(privBS);
	((SymCryptMLKEMPrivateKey*)kp->getPrivateKey())->setSeed(seedBS);

	*ppKeyPair = kp;

	return true;
}

bool SymCryptMLKEM::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	SymCryptMLKEMKeyPair* kp = new SymCryptMLKEMKeyPair();

	bool rv = true;

	if (!((MLKEMPublicKey*)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((MLKEMPrivateKey*)kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;
		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool SymCryptMLKEM::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptMLKEMPublicKey* pub = new SymCryptMLKEMPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool SymCryptMLKEM::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptMLKEMPrivateKey* priv = new SymCryptMLKEMPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* SymCryptMLKEM::newPublicKey()
{
	return (PublicKey*)new SymCryptMLKEMPublicKey();
}

PrivateKey* SymCryptMLKEM::newPrivateKey()
{
	return (PrivateKey*)new SymCryptMLKEMPrivateKey();
}

AsymmetricParameters* SymCryptMLKEM::newParameters()
{
	return (AsymmetricParameters*)new MLKEMParameters();
}

bool SymCryptMLKEM::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLKEMParameters* params = new MLKEMParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}

#endif // WITH_ML_KEM
