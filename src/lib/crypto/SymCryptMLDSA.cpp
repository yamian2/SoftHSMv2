/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSA.cpp

 SymCrypt ML-DSA asymmetric algorithm implementation

 Notes:
 - Only "pure" ML-DSA (mechanism AsymMech::MLDSA) is implemented.
 - SymCrypt's ML-DSA signing is hedged (randomised) only; it exposes no
   deterministic signing option. A DETERMINISTIC_REQUIRED request is therefore
   rejected explicitly rather than silently producing a hedged signature.
 - Verification is independent of the hedge type; the hedge type is ignored on
   the verify path and only the optional context string is honoured.
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "SymCryptMLDSA.h"
#include "CryptoFactory.h"
#include "MLDSAParameters.h"
#include "MLDSAMechanismParam.h"
#include "SymCryptMLDSAKeyPair.h"
#include "SymCryptMLDSAPublicKey.h"
#include "SymCryptMLDSAPrivateKey.h"
#include "SymCryptMLDSAUtil.h"
#include <symcrypt.h>
#include <string.h>

// Destructor
SymCryptMLDSA::~SymCryptMLDSA()
{
	delete mechanismParameters;
	mechanismParameters = NULL;
}

// Signing functions
bool SymCryptMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
						 ByteString& signature, const AsymMech::Type mechanism,
						 const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (privateKey == NULL)
	{
		ERROR_MSG("No private key supplied");
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(SymCryptMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	if (mechanismParam != NULL && !mechanismParam->isOfType(MLDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");
		return false;
	}

	// Resolve the optional context string and the hedge requirement
	ByteString context;
	const MLDSAMechanismParam* mldsaParam = dynamic_cast<const MLDSAMechanismParam*>(mechanismParam);
	if (mldsaParam != NULL)
	{
		if (mldsaParam->additionalContext.size() > SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH)
		{
			ERROR_MSG("Invalid parameters, context length > %d", SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH);
			return false;
		}
		context = mldsaParam->additionalContext;

		if (mldsaParam->hedgeType == Hedge::Type::DETERMINISTIC_REQUIRED)
		{
			ERROR_MSG("SymCrypt does not support deterministic ML-DSA signing");
			return false;
		}
	}

	SymCryptMLDSAPrivateKey* pk = (SymCryptMLDSAPrivateKey*)privateKey;

	PSYMCRYPT_MLDSAKEY key = pk->getSymCryptKey();
	if (key == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt private key");
		return false;
	}

	unsigned long sigLen = pk->getOutputLength();
	if (sigLen == 0)
	{
		ERROR_MSG("Could not determine the ML-DSA signature length");
		return false;
	}

	signature.resize(sigLen);

	SYMCRYPT_ERROR scError = SymCryptMlDsaSign(
		key,
		dataToSign.const_byte_str(), dataToSign.size(),
		context.size() ? context.const_byte_str() : NULL, context.size(),
		0,
		&signature[0], sigLen);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsaSign failed (0x%08X)", (unsigned)scError);
		return false;
	}

	return true;
}

bool SymCryptMLDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
							 const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(SymCryptMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	if (mechanismParam != NULL && !mechanismParam->isOfType(MLDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	delete mechanismParameters;
	mechanismParameters = (mechanismParam != NULL) ? mechanismParam->clone() : NULL;

	return true;
}

bool SymCryptMLDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	message += dataToSign;

	return true;
}

bool SymCryptMLDSA::signFinal(ByteString& signature)
{
	bool rv = SymCryptMLDSA::sign(currentPrivateKey, message, signature, currentMechanism, mechanismParameters);

	delete mechanismParameters;
	mechanismParameters = NULL;

	message.resize(0);

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	return rv;
}

// Verification functions
bool SymCryptMLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
						   const ByteString& signature, const AsymMech::Type mechanism,
						   const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (publicKey == NULL)
	{
		ERROR_MSG("No public key supplied");
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(SymCryptMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	if (mechanismParam != NULL && !mechanismParam->isOfType(MLDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");
		return false;
	}

	SymCryptMLDSAPublicKey* pk = (SymCryptMLDSAPublicKey*)publicKey;

	unsigned long sigLen = pk->getOutputLength();
	if (sigLen == 0)
	{
		ERROR_MSG("Could not determine the ML-DSA signature length");
		return false;
	}
	if (signature.size() != sigLen)
	{
		ERROR_MSG("Invalid signature length");
		return false;
	}

	// Resolve the optional context string (the hedge type is irrelevant to verify)
	ByteString context;
	const MLDSAMechanismParam* mldsaParam = dynamic_cast<const MLDSAMechanismParam*>(mechanismParam);
	if (mldsaParam != NULL)
	{
		if (mldsaParam->additionalContext.size() > SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH)
		{
			ERROR_MSG("Invalid parameters, context length > %d", SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH);
			return false;
		}
		context = mldsaParam->additionalContext;
	}

	PSYMCRYPT_MLDSAKEY key = pk->getSymCryptKey();
	if (key == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt public key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsaVerify(
		key,
		originalData.const_byte_str(), originalData.size(),
		context.size() ? context.const_byte_str() : NULL, context.size(),
		signature.const_byte_str(), signature.size(),
		0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		return false;
	}

	return true;
}

bool SymCryptMLDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
							   const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(SymCryptMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	if (mechanismParam != NULL && !mechanismParam->isOfType(MLDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	delete mechanismParameters;
	mechanismParameters = (mechanismParam != NULL) ? mechanismParam->clone() : NULL;

	return true;
}

bool SymCryptMLDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	message += originalData;

	return true;
}

bool SymCryptMLDSA::verifyFinal(const ByteString& signature)
{
	bool rv = SymCryptMLDSA::verify(currentPublicKey, message, signature, currentMechanism, mechanismParameters);

	delete mechanismParameters;
	mechanismParameters = NULL;

	message.resize(0);

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	return rv;
}

// Encryption functions
bool SymCryptMLDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
							ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
							const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-DSA does not support encryption");

	return false;
}

// Decryption functions
bool SymCryptMLDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
							ByteString& /*data*/, const AsymMech::Type /*padding*/,
							const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ML-DSA does not support decryption");

	return false;
}

bool SymCryptMLDSA::checkEncryptedDataSize(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, int* /*errorCode*/)
{
	ERROR_MSG("ML-DSA does not support encryption");

	return false;
}

unsigned long SymCryptMLDSA::getMinKeySize()
{
	return MLDSAParameters::ML_DSA_44_PUB_LENGTH;
}

unsigned long SymCryptMLDSA::getMaxKeySize()
{
	return MLDSAParameters::ML_DSA_87_PUB_LENGTH;
}

// Key factory
bool SymCryptMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* inParameters, RNG* /*rng = NULL*/)
{
	// Check parameters
	if ((ppKeyPair == NULL) || (inParameters == NULL))
	{
		return false;
	}

	if (!inParameters->areOfType(MLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ML-DSA key generation");
		return false;
	}

	MLDSAParameters* params = (MLDSAParameters*)inParameters;

	SYMCRYPT_MLDSA_PARAMS scParams;
	if (!SymMLDSA::paramsFromParameterSet(params->getParameterSet(), scParams))
	{
		ERROR_MSG("Unknown ML-DSA parameter set (%lu)", params->getParameterSet());
		return false;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(scParams);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-DSA key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeyGenerate(key, 0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsakeyGenerate failed (0x%08X)", (unsigned)scError);
		SymCryptMlDsakeyFree(key);
		return false;
	}

	// Determine the sizes of the exportable formats
	SIZE_T cbPub = 0, cbPriv = 0, cbSeed = 0;
	if (SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPub) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPriv) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &cbSeed) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not determine ML-DSA key format sizes");
		SymCryptMlDsakeyFree(key);
		return false;
	}

	ByteString pubBS, privBS, seedBS;
	pubBS.resize(cbPub);
	privBS.resize(cbPriv);
	seedBS.resize(cbSeed);

	if (SymCryptMlDsakeyGetValue(key, &pubBS[0], cbPub, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, 0) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsakeyGetValue(key, &privBS[0], cbPriv, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, 0) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsakeyGetValue(key, &seedBS[0], cbSeed, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, 0) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not export ML-DSA key material");
		SymCryptMlDsakeyFree(key);
		return false;
	}

	SymCryptMlDsakeyFree(key);

	// Create an asymmetric key-pair object to return
	SymCryptMLDSAKeyPair* kp = new SymCryptMLDSAKeyPair();

	((SymCryptMLDSAPublicKey*)kp->getPublicKey())->setValue(pubBS);
	((SymCryptMLDSAPrivateKey*)kp->getPrivateKey())->setValue(privBS);
	((SymCryptMLDSAPrivateKey*)kp->getPrivateKey())->setSeed(seedBS);

	*ppKeyPair = kp;

	return true;
}

bool SymCryptMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	SymCryptMLDSAKeyPair* kp = new SymCryptMLDSAKeyPair();

	bool rv = true;

	if (!((MLDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((MLDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv))
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

bool SymCryptMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptMLDSAPublicKey* pub = new SymCryptMLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool SymCryptMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptMLDSAPrivateKey* priv = new SymCryptMLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* SymCryptMLDSA::newPublicKey()
{
	return (PublicKey*)new SymCryptMLDSAPublicKey();
}

PrivateKey* SymCryptMLDSA::newPrivateKey()
{
	return (PrivateKey*)new SymCryptMLDSAPrivateKey();
}

AsymmetricParameters* SymCryptMLDSA::newParameters()
{
	return (AsymmetricParameters*)new MLDSAParameters();
}

bool SymCryptMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	MLDSAParameters* params = new MLDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}

#endif // WITH_ML_DSA
