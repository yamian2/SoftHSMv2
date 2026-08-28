/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSA.cpp

 SymCrypt composite ML-DSA asymmetric algorithm implementation.

 A composite key is a pair of an ML-DSA key and an ECDSA key over one of the
 NIST curves. Key generation, signing and verification follow
 draft-ietf-lamps-pq-composite-sigs: both component operations run over the
 same message representative M' and the component outputs are concatenated.
 SymCrypt provides both the ML-DSA and ECDSA primitives.
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "log.h"
#include "SymCryptCompositeMLDSA.h"
#include "SymCryptCompositeMLDSAKeyPair.h"
#include "SymCryptCompositeMLDSAPublicKey.h"
#include "SymCryptCompositeMLDSAPrivateKey.h"
#include "CompositeMLDSAParameters.h"
#include "CompositeMLDSAUtil.h"
#include "MLDSAMechanismParam.h"
#include "SymCryptMLDSAUtil.h"
#include "SymCryptECPublicKey.h"
#include "SymCryptECPrivateKey.h"
#include "SymCryptECDSA.h"
#include "ECParameters.h"
#include "DerUtil.h"
#include <symcrypt.h>
#include <string.h>

// Map the ECDSA component hash to the corresponding ECDSA mechanism.
static bool ecdsaMechForHash(HashAlgo::Type hash, AsymMech::Type& mech)
{
	switch (hash)
	{
		case HashAlgo::SHA256: mech = AsymMech::ECDSA_SHA256; return true;
		case HashAlgo::SHA384: mech = AsymMech::ECDSA_SHA384; return true;
		case HashAlgo::SHA512: mech = AsymMech::ECDSA_SHA512; return true;
		default: return false;
	}
}

// Resolve the optional context string from a mechanism parameter.
static bool resolveContext(const MechanismParam* mechanismParam, ByteString& context)
{
	context.wipe();

	if (mechanismParam == NULL)
	{
		return true;
	}

	if (!mechanismParam->isOfType(MLDSAMechanismParam::type))
	{
		ERROR_MSG("Invalid mechanism parameter type supplied");
		return false;
	}

	const MLDSAMechanismParam* p = dynamic_cast<const MLDSAMechanismParam*>(mechanismParam);
	if (p != NULL)
	{
		if (p->additionalContext.size() > 255)
		{
			ERROR_MSG("Composite ML-DSA context too long");
			return false;
		}
		context = p->additionalContext;
	}

	return true;
}

// Sign the message representative with the ML-DSA component (context = Label).
static bool signMLDSAComponent(const CompositeMLDSA::Metadata& meta, const ByteString& seed,
			       const ByteString& mPrime, ByteString& sig)
{
	SYMCRYPT_MLDSA_PARAMS scParams;
	if (!SymMLDSA::paramsFromParameterSet(meta.mldsaParameterSet, scParams))
	{
		return false;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(scParams);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-DSA key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeySetValue(
		seed.const_byte_str(), seed.size(),
		SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsakeySetValue (seed) failed (0x%08X)", (unsigned)scError);
		SymCryptMlDsakeyFree(key);
		return false;
	}

	sig.resize(meta.mldsaSigLen);
	size_t labelLen = strlen(meta.label);

	scError = SymCryptMlDsaSign(
		key,
		mPrime.const_byte_str(), mPrime.size(),
		(PCBYTE)meta.label, labelLen,
		0,
		&sig[0], meta.mldsaSigLen);

	SymCryptMlDsakeyFree(key);

	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Composite ML-DSA component sign failed (0x%08X)", (unsigned)scError);
		return false;
	}

	return true;
}

// Verify the ML-DSA component signature (context = Label).
static bool verifyMLDSAComponent(const CompositeMLDSA::Metadata& meta, const ByteString& mldsaPub,
				 const ByteString& mPrime, const ByteString& sig)
{
	SYMCRYPT_MLDSA_PARAMS scParams;
	if (!SymMLDSA::paramsFromParameterSet(meta.mldsaParameterSet, scParams))
	{
		return false;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(scParams);
	if (key == NULL)
	{
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeySetValue(
		mldsaPub.const_byte_str(), mldsaPub.size(),
		SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymCryptMlDsakeyFree(key);
		return false;
	}

	size_t labelLen = strlen(meta.label);

	scError = SymCryptMlDsaVerify(
		key,
		mPrime.const_byte_str(), mPrime.size(),
		(PCBYTE)meta.label, labelLen,
		sig.const_byte_str(), sig.size(),
		0);

	SymCryptMlDsakeyFree(key);

	return scError == SYMCRYPT_NO_ERROR;
}

// Sign the message representative with the ECDSA component (DER Ecdsa-Sig-Value).
static bool signECDSAComponent(const CompositeMLDSA::Metadata& meta, const ByteString& tradSK,
			       const ByteString& mPrime, ByteString& derSig)
{
	ByteString d;
	if (!CompositeMLDSA::decodeEcPrivateKey(tradSK, d))
	{
		ERROR_MSG("Could not decode composite ECDSA private key");
		return false;
	}

	AsymMech::Type ecMech;
	if (!ecdsaMechForHash(meta.ecdsaHash, ecMech))
	{
		return false;
	}

	SymCryptECPrivateKey ecPriv;
	ecPriv.setEC(meta.curveOID);
	ecPriv.setD(d);

	SymCryptECDSA ecdsa;
	ByteString raw;
	if (!ecdsa.sign(&ecPriv, mPrime, raw, ecMech))
	{
		return false;
	}

	derSig = CompositeMLDSA::ecdsaRawToDer(raw, meta.ecFieldLen);

	return derSig.size() != 0;
}

// Verify the ECDSA component signature (DER Ecdsa-Sig-Value).
static bool verifyECDSAComponent(const CompositeMLDSA::Metadata& meta, const ByteString& tradPub,
				 const ByteString& mPrime, const ByteString& derSig)
{
	ByteString raw;
	if (!CompositeMLDSA::ecdsaDerToRaw(derSig, meta.ecFieldLen, raw))
	{
		return false;
	}

	AsymMech::Type ecMech;
	if (!ecdsaMechForHash(meta.ecdsaHash, ecMech))
	{
		return false;
	}

	SymCryptECPublicKey ecPub;
	ecPub.setEC(meta.curveOID);
	ecPub.setQ(DERUTIL::raw2Octet(tradPub));

	SymCryptECDSA ecdsa;

	return ecdsa.verify(&ecPub, mPrime, raw, ecMech);
}

// --- SymCryptCompositeMLDSA -----------------------------------------------

// Destructor
SymCryptCompositeMLDSA::~SymCryptCompositeMLDSA()
{
	delete mechanismParameters;
	mechanismParameters = NULL;
}

// Signing functions
bool SymCryptCompositeMLDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
				  ByteString& signature, const AsymMech::Type mechanism,
				  const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::COMPOSITE_MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (privateKey == NULL || !privateKey->isOfType(SymCryptCompositeMLDSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptCompositeMLDSAPrivateKey* pk = (SymCryptCompositeMLDSAPrivateKey*)privateKey;

	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(pk->getAlgorithm(), meta))
	{
		ERROR_MSG("Unknown composite ML-DSA algorithm (%lu)", pk->getAlgorithm());
		return false;
	}

	ByteString context;
	if (!resolveContext(mechanismParam, context))
	{
		return false;
	}

	// Split the composite private key: mldsaSeed || tradSK
	const ByteString& value = pk->getValue();
	SYMCRYPT_MLDSA_PARAMS scParams;
	SIZE_T cbSeed = 0;
	if (!SymMLDSA::paramsFromParameterSet(meta.mldsaParameterSet, scParams) ||
	    SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &cbSeed) != SYMCRYPT_NO_ERROR)
	{
		return false;
	}
	if (value.size() <= cbSeed)
	{
		ERROR_MSG("Malformed composite private key");
		return false;
	}

	ByteString seed = value.substr(0, cbSeed);
	ByteString tradSK = value.substr(cbSeed);

	// Build the message representative M'
	ByteString mPrime;
	if (!CompositeMLDSA::buildMessageRepresentative(meta, context, dataToSign, mPrime))
	{
		return false;
	}

	// Component signatures
	ByteString mldsaSig;
	if (!signMLDSAComponent(meta, seed, mPrime, mldsaSig))
	{
		return false;
	}

	ByteString ecdsaSig;
	if (!signECDSAComponent(meta, tradSK, mPrime, ecdsaSig))
	{
		return false;
	}

	// Composite signature = mldsaSig || ecdsaSig(DER)
	signature.wipe();
	signature += mldsaSig;
	signature += ecdsaSig;

	return true;
}

bool SymCryptCompositeMLDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
				      const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	if (!privateKey->isOfType(SymCryptCompositeMLDSAPrivateKey::type))
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

bool SymCryptCompositeMLDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	message += dataToSign;

	return true;
}

bool SymCryptCompositeMLDSA::signFinal(ByteString& signature)
{
	bool rv = SymCryptCompositeMLDSA::sign(currentPrivateKey, message, signature, currentMechanism, mechanismParameters);

	delete mechanismParameters;
	mechanismParameters = NULL;

	message.wipe();

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	return rv;
}

// Verification functions
bool SymCryptCompositeMLDSA::verify(PublicKey* publicKey, const ByteString& originalData,
				    const ByteString& signature, const AsymMech::Type mechanism,
				    const MechanismParam* mechanismParam)
{
	if (mechanism != AsymMech::COMPOSITE_MLDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (publicKey == NULL || !publicKey->isOfType(SymCryptCompositeMLDSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptCompositeMLDSAPublicKey* pk = (SymCryptCompositeMLDSAPublicKey*)publicKey;

	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(pk->getAlgorithm(), meta))
	{
		ERROR_MSG("Unknown composite ML-DSA algorithm (%lu)", pk->getAlgorithm());
		return false;
	}

	ByteString context;
	if (!resolveContext(mechanismParam, context))
	{
		return false;
	}

	// Split the composite public key: mldsaPK || tradPK
	const ByteString& value = pk->getValue();
	if (value.size() <= meta.mldsaPubLen)
	{
		ERROR_MSG("Malformed composite public key");
		return false;
	}
	ByteString mldsaPub = value.substr(0, meta.mldsaPubLen);
	ByteString tradPub = value.substr(meta.mldsaPubLen);

	// Split the composite signature: mldsaSig || ecdsaSig(DER)
	if (signature.size() <= meta.mldsaSigLen)
	{
		ERROR_MSG("Malformed composite signature");
		return false;
	}
	ByteString mldsaSig = signature.substr(0, meta.mldsaSigLen);
	ByteString ecdsaSig = signature.substr(meta.mldsaSigLen);

	// Build the message representative M'
	ByteString mPrime;
	if (!CompositeMLDSA::buildMessageRepresentative(meta, context, originalData, mPrime))
	{
		return false;
	}

	// Both components must verify
	if (!verifyMLDSAComponent(meta, mldsaPub, mPrime, mldsaSig))
	{
		return false;
	}

	if (!verifyECDSAComponent(meta, tradPub, mPrime, ecdsaSig))
	{
		return false;
	}

	return true;
}

bool SymCryptCompositeMLDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
					const MechanismParam* mechanismParam)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	if (!publicKey->isOfType(SymCryptCompositeMLDSAPublicKey::type))
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

bool SymCryptCompositeMLDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	message += originalData;

	return true;
}

bool SymCryptCompositeMLDSA::verifyFinal(const ByteString& signature)
{
	bool rv = SymCryptCompositeMLDSA::verify(currentPublicKey, message, signature, currentMechanism, mechanismParameters);

	delete mechanismParameters;
	mechanismParameters = NULL;

	message.wipe();

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	return rv;
}

// Encryption functions
bool SymCryptCompositeMLDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
				     ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
				     const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Composite ML-DSA does not support encryption");

	return false;
}

// Decryption functions
bool SymCryptCompositeMLDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
				     ByteString& /*data*/, const AsymMech::Type /*padding*/,
				     const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("Composite ML-DSA does not support decryption");

	return false;
}

bool SymCryptCompositeMLDSA::checkEncryptedDataSize(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/, int* /*errorCode*/)
{
	ERROR_MSG("Composite ML-DSA does not support encryption");

	return false;
}

unsigned long SymCryptCompositeMLDSA::getMinKeySize()
{
	return MLDSAParameters::ML_DSA_44_PUB_LENGTH;
}

unsigned long SymCryptCompositeMLDSA::getMaxKeySize()
{
	return MLDSAParameters::ML_DSA_87_PUB_LENGTH;
}

// Key factory
bool SymCryptCompositeMLDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* inParameters, RNG* /*rng = NULL*/)
{
	if ((ppKeyPair == NULL) || (inParameters == NULL))
	{
		return false;
	}

	if (!inParameters->areOfType(CompositeMLDSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for composite ML-DSA key generation");
		return false;
	}

	CompositeMLDSAParameters* params = (CompositeMLDSAParameters*)inParameters;

	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(params->getAlgorithm(), meta))
	{
		ERROR_MSG("Unknown composite ML-DSA algorithm (%lu)", params->getAlgorithm());
		return false;
	}

	// ---- ML-DSA component key generation ----
	SYMCRYPT_MLDSA_PARAMS scParams;
	if (!SymMLDSA::paramsFromParameterSet(meta.mldsaParameterSet, scParams))
	{
		return false;
	}

	PSYMCRYPT_MLDSAKEY mldsaKey = SymCryptMlDsakeyAllocate(scParams);
	if (mldsaKey == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-DSA key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeyGenerate(mldsaKey, 0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsakeyGenerate failed (0x%08X)", (unsigned)scError);
		SymCryptMlDsakeyFree(mldsaKey);
		return false;
	}

	SIZE_T cbPub = 0, cbSeed = 0;
	if (SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPub) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsaSizeofKeyFormatFromParams(scParams, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, &cbSeed) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not determine ML-DSA key format sizes");
		SymCryptMlDsakeyFree(mldsaKey);
		return false;
	}

	ByteString mldsaPub, mldsaSeed;
	mldsaPub.resize(cbPub);
	mldsaSeed.resize(cbSeed);

	if (SymCryptMlDsakeyGetValue(mldsaKey, &mldsaPub[0], cbPub, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, 0) != SYMCRYPT_NO_ERROR ||
	    SymCryptMlDsakeyGetValue(mldsaKey, &mldsaSeed[0], cbSeed, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED, 0) != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Could not export ML-DSA key material");
		SymCryptMlDsakeyFree(mldsaKey);
		return false;
	}

	SymCryptMlDsakeyFree(mldsaKey);

	// ---- ECDSA component key generation (reuse SymCryptECDSA) ----
	ECParameters ecParams;
	ecParams.setEC(meta.curveOID);

	SymCryptECDSA ecdsa;
	AsymmetricKeyPair* ecKeyPair = NULL;
	if (!ecdsa.generateKeyPair(&ecKeyPair, &ecParams))
	{
		ERROR_MSG("Composite ML-DSA: ECDSA component key generation failed");
		return false;
	}

	ByteString ecD = ((ECPrivateKey*)ecKeyPair->getPrivateKey())->getD();
	ByteString ecQ = ((ECPublicKey*)ecKeyPair->getPublicKey())->getQ();

	// tradPK is the raw uncompressed point 0x04 || X || Y
	ByteString tradPub = DERUTIL::octet2Raw(ecQ);
	// tradSK is an RFC 5915 ECPrivateKey
	ByteString tradSK = CompositeMLDSA::encodeEcPrivateKey(ecD, meta.curveOID);

	ecdsa.recycleKeyPair(ecKeyPair);

	if (tradPub.size() == 0 || tradSK.size() == 0)
	{
		ERROR_MSG("Composite ML-DSA: failed to encode ECDSA component");
		return false;
	}

	// ---- Assemble the composite key material ----
	ByteString compositePub;
	compositePub += mldsaPub;
	compositePub += tradPub;

	ByteString compositePriv;
	compositePriv += mldsaSeed;
	compositePriv += tradSK;

	SymCryptCompositeMLDSAKeyPair* kp = new SymCryptCompositeMLDSAKeyPair();

	((SymCryptCompositeMLDSAPublicKey*)kp->getPublicKey())->setValue(compositePub);
	((SymCryptCompositeMLDSAPublicKey*)kp->getPublicKey())->setAlgorithm(meta.algorithm);
	((SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey())->setValue(compositePriv);
	((SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey())->setAlgorithm(meta.algorithm);

	*ppKeyPair = kp;

	return true;
}

bool SymCryptCompositeMLDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	SymCryptCompositeMLDSAKeyPair* kp = new SymCryptCompositeMLDSAKeyPair();

	bool rv = true;

	if (!((SymCryptCompositeMLDSAPublicKey*)kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey())->deserialise(dPriv))
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

bool SymCryptCompositeMLDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptCompositeMLDSAPublicKey* pub = new SymCryptCompositeMLDSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool SymCryptCompositeMLDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptCompositeMLDSAPrivateKey* priv = new SymCryptCompositeMLDSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* SymCryptCompositeMLDSA::newPublicKey()
{
	return (PublicKey*)new SymCryptCompositeMLDSAPublicKey();
}

PrivateKey* SymCryptCompositeMLDSA::newPrivateKey()
{
	return (PrivateKey*)new SymCryptCompositeMLDSAPrivateKey();
}

AsymmetricParameters* SymCryptCompositeMLDSA::newParameters()
{
	return (AsymmetricParameters*)new CompositeMLDSAParameters();
}

bool SymCryptCompositeMLDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	CompositeMLDSAParameters* params = new CompositeMLDSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}

#endif // WITH_ML_DSA && WITH_ECC
