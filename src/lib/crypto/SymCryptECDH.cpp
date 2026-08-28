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
 SymCryptECDH.cpp

 SymCrypt Diffie-Hellman on elliptic curves asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "SymCryptECDH.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "SymCryptECKeyPair.h"
#include "SymCryptECUtil.h"
#include "DerUtil.h"
#include "SymmetricKey.h"
#include <symcrypt.h>
#include <string.h>

// Signing functions
bool SymCryptECDH::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			    const MechanismParam* /* mechanismParam = NULL */)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool SymCryptECDH::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

bool SymCryptECDH::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support signing");

	return false;
}

// Verification functions
bool SymCryptECDH::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			      const MechanismParam* /* mechanismParam = NULL */)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool SymCryptECDH::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

bool SymCryptECDH::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDH does not support verifying");

	return false;
}

// Encryption functions
bool SymCryptECDH::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			   ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/,
			   const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ECDH does not support encryption");

	return false;
}

// Decryption functions
bool SymCryptECDH::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			   ByteString& /*data*/, const AsymMech::Type /*padding*/,
			   const MechanismParam* /*mechanismParam*/)
{
	ERROR_MSG("ECDH does not support decryption");

	return false;
}

// Key factory
bool SymCryptECDH::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDH key generation");
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
		ERROR_MSG("ECDH key generation failed (0x%08X)", (unsigned)scError);
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

bool SymCryptECDH::deriveKey(SymmetricKey **ppSymmetricKey, PublicKey* publicKey, PrivateKey* privateKey)
{
	// Check parameters
	if ((ppSymmetricKey == NULL) ||
	    (publicKey == NULL) ||
	    (privateKey == NULL))
	{
		return false;
	}

	// Check the key types
	if (!publicKey->isOfType(SymCryptECPublicKey::type) ||
	    !privateKey->isOfType(SymCryptECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptECPublicKey* pub = (SymCryptECPublicKey*) publicKey;
	SymCryptECPrivateKey* priv = (SymCryptECPrivateKey*) privateKey;

	PSYMCRYPT_ECKEY pubKey = pub->getSymCryptKey();
	PSYMCRYPT_ECKEY privKey = priv->getSymCryptKey();
	if (pubKey == NULL || privKey == NULL)
	{
		ERROR_MSG("Failed to get SymCrypt ECDH keys");
		return false;
	}

	// The agreed secret is the X-coordinate of the shared point, one field
	// element in size. For the supported NIST curves this equals the base
	// point order length.
	size_t size = priv->getOrderLength();
	if (size == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}

	ByteString secret;
	secret.resize(size);

	SYMCRYPT_ERROR scError = SymCryptEcDhSecretAgreement(
		privKey,
		pubKey,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		0,
		&secret[0], secret.size());
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("ECDH key derivation failed (0x%08X)", (unsigned)scError);
		return false;
	}

	*ppSymmetricKey = new SymmetricKey(secret.size() * 8);
	if (*ppSymmetricKey == NULL)
		return false;
	if (!(*ppSymmetricKey)->setKeyBits(secret))
	{
		delete *ppSymmetricKey;
		*ppSymmetricKey = NULL;
		return false;
	}

	return true;
}

unsigned long SymCryptECDH::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long SymCryptECDH::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool SymCryptECDH::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
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

bool SymCryptECDH::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
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

bool SymCryptECDH::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
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

PublicKey* SymCryptECDH::newPublicKey()
{
	return (PublicKey*) new SymCryptECPublicKey();
}

PrivateKey* SymCryptECDH::newPrivateKey()
{
	return (PrivateKey*) new SymCryptECPrivateKey();
}

AsymmetricParameters* SymCryptECDH::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool SymCryptECDH::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
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
