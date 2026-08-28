/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SymCryptECDSA.cpp

 SymCrypt ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "SymCryptECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "SymCryptECKeyPair.h"
#include "SymCryptECUtil.h"
#include "DerUtil.h"
#include <symcrypt.h>
#include <string.h>

// Map an ECDSA mechanism to the corresponding pre-hash algorithm. Returns true
// on success; sets hash to HashAlgo::Unknown for the raw AsymMech::ECDSA case.
static bool mechToHash(const AsymMech::Type mechanism, HashAlgo::Type& hash)
{
	hash = HashAlgo::Unknown;

	switch (mechanism)
	{
		case AsymMech::ECDSA:
			hash = HashAlgo::Unknown;
			return true;
		case AsymMech::ECDSA_SHA1:
			hash = HashAlgo::SHA1;
			return true;
		case AsymMech::ECDSA_SHA224:
			hash = HashAlgo::SHA224;
			return true;
		case AsymMech::ECDSA_SHA256:
			hash = HashAlgo::SHA256;
			return true;
		case AsymMech::ECDSA_SHA384:
			hash = HashAlgo::SHA384;
			return true;
		case AsymMech::ECDSA_SHA512:
			hash = HashAlgo::SHA512;
			return true;
		default:
			return false;
	}
}

// Constructor
SymCryptECDSA::SymCryptECDSA()
{
	pCurrentHash = NULL;
}

// Destructor
SymCryptECDSA::~SymCryptECDSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}
}

// Signing functions
bool SymCryptECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
			 ByteString& signature, const AsymMech::Type mechanism,
			 const MechanismParam* /* mechanismParam */)
{
	HashAlgo::Type hash = HashAlgo::Unknown;

	if (!mechToHash(mechanism, hash))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(SymCryptECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptECPrivateKey* pk = (SymCryptECPrivateKey*) privateKey;
	PSYMCRYPT_ECKEY eckey = pk->getSymCryptKey();
	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt private key");
		return false;
	}

	// Pre-hash the data if necessary
	ByteString prepDataToSign;
	if (hash == HashAlgo::Unknown)
	{
		prepDataToSign = dataToSign;
	}
	else
	{
		HashAlgorithm* digest = CryptoFactory::i()->getHashAlgorithm(hash);
		if (digest == NULL) return false;

		if (!digest->hashInit()
				|| !digest->hashUpdate(dataToSign)
				|| !digest->hashFinal(prepDataToSign))
		{
			CryptoFactory::i()->recycleHashAlgorithm(digest);
			return false;
		}
		CryptoFactory::i()->recycleHashAlgorithm(digest);
	}

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);

	SYMCRYPT_ERROR scError = SymCryptEcDsaSign(
		eckey,
		prepDataToSign.const_byte_str(), prepDataToSign.size(),
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		0,
		&signature[0], signature.size());
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("ECDSA sign failed (0x%08X)", (unsigned)scError);
		return false;
	}

	return true;
}

bool SymCryptECDSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			     const MechanismParam* mechanismParam /* = NULL */)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(SymCryptECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	if (mechanism == AsymMech::ECDSA || !mechToHash(mechanism, hash))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptECDSA::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptECDSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	SymCryptECPrivateKey* pk = (SymCryptECPrivateKey*) currentPrivateKey;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bResult)
	{
		return false;
	}

	PSYMCRYPT_ECKEY eckey = pk->getSymCryptKey();
	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt private key");
		return false;
	}

	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);

	SYMCRYPT_ERROR scError = SymCryptEcDsaSign(
		eckey,
		hash.const_byte_str(), hash.size(),
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		0,
		&signature[0], signature.size());
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("ECDSA sign failed (0x%08X)", (unsigned)scError);
		return false;
	}

	return true;
}

// Verification functions
bool SymCryptECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
			   const ByteString& signature, const AsymMech::Type mechanism,
			   const MechanismParam* /* mechanismParam */)
{
	HashAlgo::Type hash = HashAlgo::Unknown;

	if (!mechToHash(mechanism, hash))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(SymCryptECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptECPublicKey* pk = (SymCryptECPublicKey*) publicKey;
	PSYMCRYPT_ECKEY eckey = pk->getSymCryptKey();
	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt public key");
		return false;
	}

	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	// Pre-hash the data if necessary
	ByteString prepData;
	if (hash == HashAlgo::Unknown)
	{
		prepData = originalData;
	}
	else
	{
		HashAlgorithm* digest = CryptoFactory::i()->getHashAlgorithm(hash);
		if (digest == NULL) return false;

		if (!digest->hashInit()
				|| !digest->hashUpdate(originalData)
				|| !digest->hashFinal(prepData))
		{
			CryptoFactory::i()->recycleHashAlgorithm(digest);
			return false;
		}
		CryptoFactory::i()->recycleHashAlgorithm(digest);
	}

	SYMCRYPT_ERROR scError = SymCryptEcDsaVerify(
		eckey,
		prepData.const_byte_str(), prepData.size(),
		signature.const_byte_str(), signature.size(),
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		0);

	return (scError == SYMCRYPT_NO_ERROR);
}

bool SymCryptECDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			       const MechanismParam* mechanismParam /* = NULL */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	// Check if the public key is the right type
	if (!publicKey->isOfType(SymCryptECPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	HashAlgo::Type hash = HashAlgo::Unknown;

	if (mechanism == AsymMech::ECDSA || !mechToHash(mechanism, hash))
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash);

	if (pCurrentHash == NULL || !pCurrentHash->hashInit())
	{
		if (pCurrentHash != NULL)
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
		}

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptECDSA::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData))
	{
		return false;
	}

	if (!pCurrentHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;

		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);

		return false;
	}

	return true;
}

bool SymCryptECDSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	SymCryptECPublicKey* pk = (SymCryptECPublicKey*) currentPublicKey;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString hash;

	bool bResult = pCurrentHash->hashFinal(hash);

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (!bResult)
	{
		return false;
	}

	PSYMCRYPT_ECKEY eckey = pk->getSymCryptKey();
	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the SymCrypt public key");
		return false;
	}

	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptEcDsaVerify(
		eckey,
		hash.const_byte_str(), hash.size(),
		signature.const_byte_str(), signature.size(),
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		0);

	return (scError == SYMCRYPT_NO_ERROR);
}

// Encryption functions
bool SymCryptECDSA::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			    ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/ )
{
	ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool SymCryptECDSA::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			    ByteString& /*data*/, const AsymMech::Type /*padding*/, const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
bool SymCryptECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");
		return false;
	}

	ECParameters* params = (ECParameters*) parameters;

	PSYMCRYPT_ECURVE curve = SymEC::curveFromParams(params->getEC());
	if (curve == NULL)
	{
		return false;
	}

	PSYMCRYPT_ECKEY eckey = SymCryptEckeyAllocate(curve);
	if (eckey == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt EC key");
		SymCryptEcurveFree(curve);
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, eckey);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("ECDSA key generation failed (0x%08X)", (unsigned)scError);
		SymCryptEckeyFree(eckey);
		SymCryptEcurveFree(curve);
		return false;
	}

	// Extract the generated key material
	SIZE_T cbPrivateKey = SymCryptEckeySizeofPrivateKey(eckey);
	SIZE_T cbPublicKey = SymCryptEckeySizeofPublicKey(eckey, SYMCRYPT_ECPOINT_FORMAT_XY);

	ByteString privBuf, pubBuf;
	privBuf.resize(cbPrivateKey);
	pubBuf.resize(cbPublicKey);

	scError = SymCryptEckeyGetValue(
		eckey,
		&privBuf[0], cbPrivateKey,
		&pubBuf[0], cbPublicKey,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		SYMCRYPT_ECPOINT_FORMAT_XY,
		0);

	SymCryptEckeyFree(eckey);
	SymCryptEcurveFree(curve);

	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("Failed to extract generated EC key (0x%08X)", (unsigned)scError);
		return false;
	}

	// Build the SoftHSM public point: DER OCTET STRING wrapping 0x04 || X || Y
	ByteString uncompressed;
	uncompressed += (unsigned char)0x04;
	uncompressed += pubBuf;
	ByteString q = DERUTIL::raw2Octet(uncompressed);

	// Create an asymmetric key-pair object to return
	SymCryptECKeyPair* kp = new SymCryptECKeyPair();

	((ECPublicKey*) kp->getPublicKey())->setEC(params->getEC());
	((ECPublicKey*) kp->getPublicKey())->setQ(q);
	((ECPrivateKey*) kp->getPrivateKey())->setEC(params->getEC());
	((ECPrivateKey*) kp->getPrivateKey())->setD(privBuf);

	*ppKeyPair = kp;

	return true;
}

unsigned long SymCryptECDSA::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long SymCryptECDSA::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool SymCryptECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	SymCryptECKeyPair* kp = new SymCryptECKeyPair();

	bool rv = true;

	if (!((ECPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((ECPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool SymCryptECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptECPublicKey* pub = new SymCryptECPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool SymCryptECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptECPrivateKey* priv = new SymCryptECPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* SymCryptECDSA::newPublicKey()
{
	return (PublicKey*) new SymCryptECPublicKey();
}

PrivateKey* SymCryptECDSA::newPrivateKey()
{
	return (PrivateKey*) new SymCryptECPrivateKey();
}

AsymmetricParameters* SymCryptECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool SymCryptECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ECParameters* params = new ECParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}

#endif // WITH_ECC
