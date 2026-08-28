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
 SymCryptRSA.cpp

 SymCrypt RSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptRSA.h"
#include "SymCryptUtil.h"
#include "CryptoFactory.h"
#include "RSAParameters.h"
#include "RSAMechanismParam.h"
#include "SymCryptRSAKeyPair.h"
#include "SymCryptRSAPublicKey.h"
#include "SymCryptRSAPrivateKey.h"
#include "SymCryptImports.h"
#include <string.h>

// Map a fixed-hash PKCS #1 mechanism to its SymCrypt hash OID list
static bool pkcs1OidsForMech(AsymMech::Type mechanism, PCSYMCRYPT_OID& oids, SIZE_T& count)
{
	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			oids = SymImports::md5Oids();
			count = SYMCRYPT_MD5_OID_COUNT;
			return true;
		case AsymMech::RSA_SHA1_PKCS:
			oids = SymImports::sha1Oids();
			count = SYMCRYPT_SHA1_OID_COUNT;
			return true;
		case AsymMech::RSA_SHA224_PKCS:
			oids = SymImports::sha224Oids();
			count = SYMCRYPT_SHA224_OID_COUNT;
			return true;
		case AsymMech::RSA_SHA256_PKCS:
			oids = SymImports::sha256Oids();
			count = SYMCRYPT_SHA256_OID_COUNT;
			return true;
		case AsymMech::RSA_SHA384_PKCS:
			oids = SymImports::sha384Oids();
			count = SYMCRYPT_SHA384_OID_COUNT;
			return true;
		case AsymMech::RSA_SHA512_PKCS:
			oids = SymImports::sha512Oids();
			count = SYMCRYPT_SHA512_OID_COUNT;
			return true;
		default:
			return false;
	}
}

// Map a fixed-hash PSS mechanism to its SymCrypt hash algorithm
static PCSYMCRYPT_HASH pssHashForMech(AsymMech::Type mechanism)
{
	switch (mechanism)
	{
		case AsymMech::RSA_SHA1_PKCS_PSS:
			return SymImports::sha1();
		case AsymMech::RSA_SHA224_PKCS_PSS:
			return SymImports::sha224();
		case AsymMech::RSA_SHA256_PKCS_PSS:
			return SymImports::sha256();
		case AsymMech::RSA_SHA384_PKCS_PSS:
			return SymImports::sha384();
		case AsymMech::RSA_SHA512_PKCS_PSS:
			return SymImports::sha512();
		default:
			return NULL;
	}
}

// Map a hash algorithm identifier to a SymCrypt hash algorithm (and its length)
static PCSYMCRYPT_HASH symHashForAlgo(HashAlgo::Type hashAlg, size_t& hashLen)
{
	switch (hashAlg)
	{
		case HashAlgo::SHA1:
			hashLen = 20;
			return SymImports::sha1();
		case HashAlgo::SHA224:
			hashLen = 28;
			return SymImports::sha224();
		case HashAlgo::SHA256:
			hashLen = 32;
			return SymImports::sha256();
		case HashAlgo::SHA384:
			hashLen = 48;
			return SymImports::sha384();
		case HashAlgo::SHA512:
			hashLen = 64;
			return SymImports::sha512();
		default:
			hashLen = 0;
			return NULL;
	}
}

// Verify a PKCS #1 v1.5 signature that carries no ASN.1 DigestInfo (i.e. the
// message representative is padded directly). SymCrypt's PKCS1 verify only
// accepts the OPTIONAL_HASH_OID flag and always expects a DigestInfo, so a
// NO_ASN1 signature (CKM_RSA_PKCS with a caller-supplied block, or the SSL
// MD5+SHA1 mechanism) has to be verified with a textbook RSA public operation
// followed by a constant-structure comparison against the expected padding.
static bool pkcs1RawVerify(PSYMCRYPT_RSAKEY rsa, const ByteString& data, const ByteString& signature)
{
	SIZE_T modLen = SymCryptRsakeySizeofModulus(rsa);

	// The signature must be exactly the modulus size and the data must leave
	// room for the minimum PKCS #1 padding (00 01 || >=8 * FF || 00).
	if (signature.size() != modLen)
		return false;
	if (data.size() + 11 > modLen)
		return false;

	// Recover the message representative: EM = signature^e mod n
	ByteString em;
	em.resize(modLen);
	SYMCRYPT_ERROR scError = SymCryptRsaRawEncrypt(
		rsa,
		signature.const_byte_str(), signature.size(),
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
		em.byte_str(), modLen);
	if (scError != SYMCRYPT_NO_ERROR)
		return false;

	// Build the expected block: 00 01 FF..FF 00 || data
	ByteString expected;
	expected.resize(modLen);
	unsigned char* p = expected.byte_str();
	size_t psLen = modLen - 3 - data.size();
	p[0] = 0x00;
	p[1] = 0x01;
	memset(p + 2, 0xFF, psLen);
	p[2 + psLen] = 0x00;
	if (data.size() > 0)
		memcpy(p + 3 + psLen, data.const_byte_str(), data.size());

	return (expected == em);
}

// Constructor
SymCryptRSA::SymCryptRSA()
{
	pCurrentHash = NULL;
	pSecondHash = NULL;
	sLen = 0;
}

// Destructor
SymCryptRSA::~SymCryptRSA()
{
	if (pCurrentHash != NULL)
	{
		delete pCurrentHash;
	}

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
	}
}

// Signing functions
bool SymCryptRSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		       ByteString& signature, const AsymMech::Type mechanism,
		       const MechanismParam* mechanismParam)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		// RSA PKCS #1 signing without hash computation; the caller supplies the
		// DigestInfo (or arbitrary data) which is PKCS #1 padded and signed.

		if (!privateKey->isOfType(SymCryptRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		SymCryptRSAPrivateKey* key = (SymCryptRSAPrivateKey*) privateKey;

		size_t allowedLen = key->getN().size() - 11;
		if (dataToSign.size() > allowedLen)
		{
			ERROR_MSG("Data to sign exceeds maximum for PKCS #1 signature");
			return false;
		}

		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt private key");
			return false;
		}

		SIZE_T sigLen = SymCryptRsakeySizeofModulus(rsa);
		signature.resize(sigLen);
		SIZE_T outLen = 0;

		SYMCRYPT_ERROR scError = SymCryptRsaPkcs1Sign(
			rsa,
			dataToSign.const_byte_str(), dataToSign.size(),
			NULL, 0,
			SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			signature.byte_str(), sigLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaPkcs1Sign (RSA_PKCS)", scError);
			return false;
		}
		signature.resize(outLen);
		return true;
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		if (mechanismParam == NULL || !mechanismParam->isOfType(RSAPssMechanismParam::type))
		{
			ERROR_MSG("Invalid RSA PSS mechanism parameter type supplied");
			return false;
		}
		const RSAPssMechanismParam* pssParam = dynamic_cast<const RSAPssMechanismParam*>(mechanismParam);

		if (!privateKey->isOfType(SymCryptRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		size_t allowedLen = 0;
		PCSYMCRYPT_HASH hash = symHashForAlgo(pssParam->hashAlg, allowedLen);
		if (hash == NULL)
		{
			ERROR_MSG("Invalid hash algorithm for RSA PSS");
			return false;
		}

		SymCryptRSAPrivateKey* key = (SymCryptRSAPrivateKey*) privateKey;

		if (dataToSign.size() != allowedLen)
		{
			ERROR_MSG("Data to sign does not match expected (%d) for RSA PSS", (int)allowedLen);
			return false;
		}

		size_t sParamLen = pssParam->sLen;
		if (sParamLen > ((privateKey->getBitLength() + 6) / 8 - 2 - allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sParamLen, privateKey->getBitLength());
			return false;
		}

		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt private key");
			return false;
		}

		SIZE_T sigLen = SymCryptRsakeySizeofModulus(rsa);
		signature.resize(sigLen);
		SIZE_T outLen = 0;

		SYMCRYPT_ERROR scError = SymCryptRsaPssSign(
			rsa,
			dataToSign.const_byte_str(), dataToSign.size(),
			hash, sParamLen, 0,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			signature.byte_str(), sigLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaPssSign", scError);
			return false;
		}
		signature.resize(outLen);
		return true;
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Raw RSA signing (private key operation)

		if (!privateKey->isOfType(SymCryptRSAPrivateKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		SymCryptRSAPrivateKey* key = (SymCryptRSAPrivateKey*) privateKey;

		if (dataToSign.size() != key->getN().size())
		{
			ERROR_MSG("Size of data to sign does not match the modulus size");
			return false;
		}

		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt private key");
			return false;
		}

		SIZE_T sigLen = SymCryptRsakeySizeofModulus(rsa);
		signature.resize(sigLen);

		SYMCRYPT_ERROR scError = SymCryptRsaRawDecrypt(
			rsa,
			dataToSign.const_byte_str(), dataToSign.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
			signature.byte_str(), sigLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaRawDecrypt (raw sign)", scError);
			return false;
		}
		return true;
	}
	else
	{
		// Call default implementation (hash-and-sign via signInit/Update/Final)
		return AsymmetricAlgorithm::sign(privateKey, dataToSign, signature, mechanism, mechanismParam);
	}
}

bool SymCryptRSA::signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
			   const MechanismParam* mechanismParam /*= NULL*/)
{
	if (!AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
	{
		return false;
	}

	if (!privateKey->isOfType(SymCryptRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);
		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;
	const RSAPssMechanismParam* pssParam = NULL;
	size_t allowedLen = 0;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
		case AsymMech::RSA_SHA224_PKCS_PSS:
		case AsymMech::RSA_SHA256_PKCS_PSS:
		case AsymMech::RSA_SHA384_PKCS_PSS:
		case AsymMech::RSA_SHA512_PKCS_PSS:
		{
			if ((mechanismParam == NULL) || (!mechanismParam->isOfType(RSAPssMechanismParam::type)))
			{
				ERROR_MSG("Invalid RSA PSS mechanism parameter type supplied");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			pssParam = dynamic_cast<const RSAPssMechanismParam*>(mechanismParam);
			switch (mechanism)
			{
				case AsymMech::RSA_SHA1_PKCS_PSS:
					hash1 = HashAlgo::SHA1; allowedLen = 20;
					if ((pssParam->hashAlg != HashAlgo::SHA1) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA1)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA224_PKCS_PSS:
					hash1 = HashAlgo::SHA224; allowedLen = 28;
					if ((pssParam->hashAlg != HashAlgo::SHA224) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA224)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA256_PKCS_PSS:
					hash1 = HashAlgo::SHA256; allowedLen = 32;
					if ((pssParam->hashAlg != HashAlgo::SHA256) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA256)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA384_PKCS_PSS:
					hash1 = HashAlgo::SHA384; allowedLen = 48;
					if ((pssParam->hashAlg != HashAlgo::SHA384) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA384)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA512_PKCS_PSS:
					hash1 = HashAlgo::SHA512; allowedLen = 64;
					if ((pssParam->hashAlg != HashAlgo::SHA512) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA512)) hash1 = HashAlgo::Unknown;
					break;
				default:
					break;
			}
			if (hash1 == HashAlgo::Unknown)
			{
				ERROR_MSG("Invalid RSA PSS mechanism parameters supplied");
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			sLen = pssParam->sLen;
			if (sLen > ((privateKey->getBitLength() + 6) / 8 - 2 - allowedLen))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, privateKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::signFinal(dummy);
				return false;
			}
			break;
		}
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);
			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);
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

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);
		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}
			ByteString dummy;
			AsymmetricAlgorithm::signFinal(dummy);
			return false;
		}
	}

	return true;
}

bool SymCryptRSA::signUpdate(const ByteString& dataToSign)
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

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(dataToSign))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;
		delete pSecondHash;
		pSecondHash = NULL;
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);
		return false;
	}

	return true;
}

bool SymCryptRSA::signFinal(ByteString& signature)
{
	// Save necessary state before calling super class signFinal
	PrivateKey* pk = currentPrivateKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::signFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	return signDigest(pk, digest, signature, mechanism);
}

bool SymCryptRSA::signDigest(PrivateKey* privateKey, const ByteString& digest,
			     ByteString& signature, const AsymMech::Type mechanism)
{
	SymCryptRSAPrivateKey* key = (SymCryptRSAPrivateKey*) privateKey;
	PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to get the SymCrypt private key");
		return false;
	}

	SIZE_T sigLen = SymCryptRsakeySizeofModulus(rsa);
	signature.resize(sigLen);
	SIZE_T outLen = 0;
	SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

	PCSYMCRYPT_OID oids = NULL;
	SIZE_T oidCount = 0;
	PCSYMCRYPT_HASH pssHash = pssHashForMech(mechanism);

	if (pkcs1OidsForMech(mechanism, oids, oidCount))
	{
		scError = SymCryptRsaPkcs1Sign(
			rsa,
			digest.const_byte_str(), digest.size(),
			oids, oidCount, 0,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			signature.byte_str(), sigLen, &outLen);
	}
	else if (pssHash != NULL)
	{
		scError = SymCryptRsaPssSign(
			rsa,
			digest.const_byte_str(), digest.size(),
			pssHash, sLen, 0,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			signature.byte_str(), sigLen, &outLen);
	}
	else if (mechanism == AsymMech::RSA_SSL)
	{
		scError = SymCryptRsaPkcs1Sign(
			rsa,
			digest.const_byte_str(), digest.size(),
			NULL, 0,
			SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			signature.byte_str(), sigLen, &outLen);
	}
	else
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCrypt RSA sign", scError);
		return false;
	}

	signature.resize(outLen);
	return true;
}

// Verification functions
bool SymCryptRSA::verify(PublicKey* publicKey, const ByteString& originalData,
			 const ByteString& signature, const AsymMech::Type mechanism,
			 const MechanismParam* mechanismParam)
{
	if (mechanism == AsymMech::RSA_PKCS)
	{
		if (!publicKey->isOfType(SymCryptRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		SymCryptRSAPublicKey* key = (SymCryptRSAPublicKey*) publicKey;
		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt public key");
			return false;
		}

		return pkcs1RawVerify(rsa, originalData, signature);
	}
	else if (mechanism == AsymMech::RSA_PKCS_PSS)
	{
		if (mechanismParam == NULL || !mechanismParam->isOfType(RSAPssMechanismParam::type))
		{
			ERROR_MSG("Invalid RSA PSS mechanism parameter type supplied");
			return false;
		}
		const RSAPssMechanismParam* pssParam = dynamic_cast<const RSAPssMechanismParam*>(mechanismParam);

		if (!publicKey->isOfType(SymCryptRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		size_t allowedLen = 0;
		PCSYMCRYPT_HASH hash = symHashForAlgo(pssParam->hashAlg, allowedLen);
		if (hash == NULL)
		{
			ERROR_MSG("Invalid hash algorithm for RSA PSS");
			return false;
		}

		SymCryptRSAPublicKey* key = (SymCryptRSAPublicKey*) publicKey;

		if (originalData.size() != allowedLen)
		{
			return false;
		}

		size_t sParamLen = pssParam->sLen;
		if (sParamLen > ((key->getBitLength() + 6) / 8 - 2 - allowedLen))
		{
			ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
				  (unsigned long)sParamLen, key->getBitLength());
			return false;
		}

		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt public key");
			return false;
		}

		SYMCRYPT_ERROR scError = SymCryptRsaPssVerify(
			rsa,
			originalData.const_byte_str(), originalData.size(),
			signature.const_byte_str(), signature.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			hash, sParamLen, 0);
		return (scError == SYMCRYPT_NO_ERROR);
	}
	else if (mechanism == AsymMech::RSA)
	{
		// Raw RSA verification: recover data from signature and compare

		if (!publicKey->isOfType(SymCryptRSAPublicKey::type))
		{
			ERROR_MSG("Invalid key type supplied");
			return false;
		}

		SymCryptRSAPublicKey* key = (SymCryptRSAPublicKey*) publicKey;
		PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
		if (rsa == NULL)
		{
			ERROR_MSG("Failed to get the SymCrypt public key");
			return false;
		}

		SIZE_T modLen = SymCryptRsakeySizeofModulus(rsa);
		ByteString recovered;
		recovered.resize(modLen);

		SYMCRYPT_ERROR scError = SymCryptRsaRawEncrypt(
			rsa,
			signature.const_byte_str(), signature.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
			recovered.byte_str(), modLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaRawEncrypt (raw verify)", scError);
			return false;
		}

		// Left-pad the original data to the modulus size for comparison
		ByteString padded = originalData;
		if (padded.size() < modLen)
		{
			ByteString tmp;
			tmp.resize(modLen - padded.size());
			padded = tmp + padded;
		}

		return (padded == recovered);
	}
	else
	{
		// Call the generic function (hash-and-verify via verifyInit/Update/Final)
		return AsymmetricAlgorithm::verify(publicKey, originalData, signature, mechanism, mechanismParam);
	}
}

bool SymCryptRSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			     const MechanismParam* mechanismParam /* = NULL */)
{
	if (!AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
	{
		return false;
	}

	if (!publicKey->isOfType(SymCryptRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);
		return false;
	}

	HashAlgo::Type hash1 = HashAlgo::Unknown;
	HashAlgo::Type hash2 = HashAlgo::Unknown;
	const RSAPssMechanismParam* pssParam = NULL;
	size_t allowedLen = 0;

	switch (mechanism)
	{
		case AsymMech::RSA_MD5_PKCS:
			hash1 = HashAlgo::MD5;
			break;
		case AsymMech::RSA_SHA1_PKCS:
			hash1 = HashAlgo::SHA1;
			break;
		case AsymMech::RSA_SHA224_PKCS:
			hash1 = HashAlgo::SHA224;
			break;
		case AsymMech::RSA_SHA256_PKCS:
			hash1 = HashAlgo::SHA256;
			break;
		case AsymMech::RSA_SHA384_PKCS:
			hash1 = HashAlgo::SHA384;
			break;
		case AsymMech::RSA_SHA512_PKCS:
			hash1 = HashAlgo::SHA512;
			break;
		case AsymMech::RSA_SHA1_PKCS_PSS:
		case AsymMech::RSA_SHA224_PKCS_PSS:
		case AsymMech::RSA_SHA256_PKCS_PSS:
		case AsymMech::RSA_SHA384_PKCS_PSS:
		case AsymMech::RSA_SHA512_PKCS_PSS:
		{
			if ((mechanismParam == NULL) || (!mechanismParam->isOfType(RSAPssMechanismParam::type)))
			{
				ERROR_MSG("Invalid RSA PSS mechanism parameter type supplied");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			pssParam = dynamic_cast<const RSAPssMechanismParam*>(mechanismParam);
			switch (mechanism)
			{
				case AsymMech::RSA_SHA1_PKCS_PSS:
					hash1 = HashAlgo::SHA1; allowedLen = 20;
					if ((pssParam->hashAlg != HashAlgo::SHA1) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA1)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA224_PKCS_PSS:
					hash1 = HashAlgo::SHA224; allowedLen = 28;
					if ((pssParam->hashAlg != HashAlgo::SHA224) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA224)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA256_PKCS_PSS:
					hash1 = HashAlgo::SHA256; allowedLen = 32;
					if ((pssParam->hashAlg != HashAlgo::SHA256) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA256)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA384_PKCS_PSS:
					hash1 = HashAlgo::SHA384; allowedLen = 48;
					if ((pssParam->hashAlg != HashAlgo::SHA384) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA384)) hash1 = HashAlgo::Unknown;
					break;
				case AsymMech::RSA_SHA512_PKCS_PSS:
					hash1 = HashAlgo::SHA512; allowedLen = 64;
					if ((pssParam->hashAlg != HashAlgo::SHA512) || (pssParam->mgfAlg != AsymRSAMGF::MGF1_SHA512)) hash1 = HashAlgo::Unknown;
					break;
				default:
					break;
			}
			if (hash1 == HashAlgo::Unknown)
			{
				ERROR_MSG("Invalid RSA PSS mechanism parameters supplied");
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			sLen = pssParam->sLen;
			if (sLen > ((publicKey->getBitLength() + 6) / 8 - 2 - allowedLen))
			{
				ERROR_MSG("sLen (%lu) is too large for current key size (%lu)",
					  (unsigned long)sLen, publicKey->getBitLength());
				ByteString dummy;
				AsymmetricAlgorithm::verifyFinal(dummy);
				return false;
			}
			break;
		}
		case AsymMech::RSA_SSL:
			hash1 = HashAlgo::MD5;
			hash2 = HashAlgo::SHA1;
			break;
		default:
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);
			return false;
	}

	pCurrentHash = CryptoFactory::i()->getHashAlgorithm(hash1);
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

	if (hash2 != HashAlgo::Unknown)
	{
		pSecondHash = CryptoFactory::i()->getHashAlgorithm(hash2);
		if (pSecondHash == NULL || !pSecondHash->hashInit())
		{
			delete pCurrentHash;
			pCurrentHash = NULL;
			if (pSecondHash != NULL)
			{
				delete pSecondHash;
				pSecondHash = NULL;
			}
			ByteString dummy;
			AsymmetricAlgorithm::verifyFinal(dummy);
			return false;
		}
	}

	return true;
}

bool SymCryptRSA::verifyUpdate(const ByteString& originalData)
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

	if ((pSecondHash != NULL) && !pSecondHash->hashUpdate(originalData))
	{
		delete pCurrentHash;
		pCurrentHash = NULL;
		delete pSecondHash;
		pSecondHash = NULL;
		ByteString dummy;
		AsymmetricAlgorithm::verifyFinal(dummy);
		return false;
	}

	return true;
}

bool SymCryptRSA::verifyFinal(const ByteString& signature)
{
	// Save necessary state before calling super class verifyFinal
	PublicKey* pk = currentPublicKey;
	AsymMech::Type mechanism = currentMechanism;

	if (!AsymmetricAlgorithm::verifyFinal(signature))
	{
		return false;
	}

	ByteString firstHash, secondHash;

	bool bFirstResult = pCurrentHash->hashFinal(firstHash);
	bool bSecondResult = (pSecondHash != NULL) ? pSecondHash->hashFinal(secondHash) : true;

	delete pCurrentHash;
	pCurrentHash = NULL;

	if (pSecondHash != NULL)
	{
		delete pSecondHash;
		pSecondHash = NULL;
	}

	if (!bFirstResult || !bSecondResult)
	{
		return false;
	}

	ByteString digest = firstHash + secondHash;

	return verifyDigest(pk, digest, signature, mechanism);
}

bool SymCryptRSA::verifyDigest(PublicKey* publicKey, const ByteString& digest,
			       const ByteString& signature, const AsymMech::Type mechanism)
{
	SymCryptRSAPublicKey* key = (SymCryptRSAPublicKey*) publicKey;
	PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to get the SymCrypt public key");
		return false;
	}

	PCSYMCRYPT_OID oids = NULL;
	SIZE_T oidCount = 0;
	PCSYMCRYPT_HASH pssHash = pssHashForMech(mechanism);
	SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;

	if (pkcs1OidsForMech(mechanism, oids, oidCount))
	{
		scError = SymCryptRsaPkcs1Verify(
			rsa,
			digest.const_byte_str(), digest.size(),
			signature.const_byte_str(), signature.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			oids, oidCount, 0);
	}
	else if (pssHash != NULL)
	{
		scError = SymCryptRsaPssVerify(
			rsa,
			digest.const_byte_str(), digest.size(),
			signature.const_byte_str(), signature.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			pssHash, sLen, 0);
	}
	else if (mechanism == AsymMech::RSA_SSL)
	{
		return pkcs1RawVerify(rsa, digest, signature);
	}
	else
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	return (scError == SYMCRYPT_NO_ERROR);
}

// Encryption functions
bool SymCryptRSA::encrypt(PublicKey* publicKey, const ByteString& data,
			  ByteString& encryptedData, const AsymMech::Type padding, const MechanismParam* mechanismParam)
{
	if (!publicKey->isOfType(SymCryptRSAPublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptRSAPublicKey* key = (SymCryptRSAPublicKey*) publicKey;
	PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to get the SymCrypt public key");
		return false;
	}

	SIZE_T modLen = SymCryptRsakeySizeofModulus(rsa);
	const RSAOaepMechanismParam* oaepParam = NULL;
	SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
	SIZE_T outLen = 0;

	if (padding == AsymMech::RSA_PKCS)
	{
		if (data.size() > (size_t)(modLen - 11))
		{
			ERROR_MSG("Too much data supplied for RSA PKCS #1 encryption");
			return false;
		}
		encryptedData.resize(modLen);
		scError = SymCryptRsaPkcs1Encrypt(
			rsa,
			data.const_byte_str(), data.size(), 0,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			encryptedData.byte_str(), modLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaPkcs1Encrypt", scError);
			return false;
		}
		encryptedData.resize(outLen);
		return true;
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		if (mechanismParam == NULL || !mechanismParam->isOfType(RSAOaepMechanismParam::type))
		{
			ERROR_MSG("Invalid RSA OAEP mechanism parameter type supplied");
			return false;
		}
		oaepParam = dynamic_cast<const RSAOaepMechanismParam*>(mechanismParam);
		size_t hashLen = 0;
		PCSYMCRYPT_HASH hash = symHashForAlgo(oaepParam->hashAlg, hashLen);
		if (hash == NULL)
		{
			ERROR_MSG("Invalid hash algorithm for RSA OAEP");
			return false;
		}
		if (data.size() + (2 * hashLen + 2) > (size_t)modLen)
		{
			ERROR_MSG("Too much data supplied for RSA OAEP encryption");
			return false;
		}
		encryptedData.resize(modLen);
		scError = SymCryptRsaOaepEncrypt(
			rsa,
			data.const_byte_str(), data.size(),
			hash,
			oaepParam->label.size() ? oaepParam->label.const_byte_str() : NULL,
			oaepParam->label.size(), 0,
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			encryptedData.byte_str(), modLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaOaepEncrypt", scError);
			return false;
		}
		encryptedData.resize(outLen);
		return true;
	}
	else if (padding == AsymMech::RSA)
	{
		if (data.size() != (size_t)modLen)
		{
			ERROR_MSG("Incorrect amount of input data supplied for raw RSA encryption");
			return false;
		}
		encryptedData.resize(modLen);
		scError = SymCryptRsaRawEncrypt(
			rsa,
			data.const_byte_str(), data.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
			encryptedData.byte_str(), modLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaRawEncrypt", scError);
			return false;
		}
		return true;
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);
		return false;
	}
}

// Decryption functions
bool SymCryptRSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
			  ByteString& data, const AsymMech::Type padding, const MechanismParam* mechanismParam)
{
	if (!privateKey->isOfType(SymCryptRSAPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");
		return false;
	}

	SymCryptRSAPrivateKey* key = (SymCryptRSAPrivateKey*) privateKey;
	PSYMCRYPT_RSAKEY rsa = key->getSymCryptKey();
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to get the SymCrypt private key");
		return false;
	}

	SIZE_T modLen = SymCryptRsakeySizeofModulus(rsa);
	if (encryptedData.size() != (size_t)modLen)
	{
		ERROR_MSG("Invalid amount of input data supplied for RSA decryption");
		return false;
	}

	const RSAOaepMechanismParam* oaepParam = NULL;
	SYMCRYPT_ERROR scError = SYMCRYPT_NO_ERROR;
	SIZE_T outLen = 0;

	if (padding == AsymMech::RSA_PKCS)
	{
		data.resize(modLen);
		scError = SymCryptRsaPkcs1Decrypt(
			rsa,
			encryptedData.const_byte_str(), encryptedData.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
			data.byte_str(), modLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaPkcs1Decrypt", scError);
			return false;
		}
		data.resize(outLen);
		return true;
	}
	else if (padding == AsymMech::RSA_PKCS_OAEP)
	{
		if (mechanismParam == NULL || !mechanismParam->isOfType(RSAOaepMechanismParam::type))
		{
			ERROR_MSG("Invalid RSA OAEP mechanism parameter type supplied");
			return false;
		}
		oaepParam = dynamic_cast<const RSAOaepMechanismParam*>(mechanismParam);
		size_t hashLen = 0;
		PCSYMCRYPT_HASH hash = symHashForAlgo(oaepParam->hashAlg, hashLen);
		if (hash == NULL)
		{
			ERROR_MSG("Invalid hash algorithm for RSA OAEP");
			return false;
		}
		data.resize(modLen);
		scError = SymCryptRsaOaepDecrypt(
			rsa,
			encryptedData.const_byte_str(), encryptedData.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
			hash,
			oaepParam->label.size() ? oaepParam->label.const_byte_str() : NULL,
			oaepParam->label.size(), 0,
			data.byte_str(), modLen, &outLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaOaepDecrypt", scError);
			return false;
		}
		data.resize(outLen);
		return true;
	}
	else if (padding == AsymMech::RSA)
	{
		data.resize(modLen);
		scError = SymCryptRsaRawDecrypt(
			rsa,
			encryptedData.const_byte_str(), encryptedData.size(),
			SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
			data.byte_str(), modLen);
		if (scError != SYMCRYPT_NO_ERROR)
		{
			SymUtil::logError("SymCryptRsaRawDecrypt", scError);
			return false;
		}
		return true;
	}
	else
	{
		ERROR_MSG("Invalid padding mechanism supplied (%i)", padding);
		return false;
	}
}

// Key factory
bool SymCryptRSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	if ((ppKeyPair == NULL) || (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(RSAParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for RSA key generation");
		return false;
	}

	RSAParameters* params = (RSAParameters*) parameters;

	if (params->getBitLength() < getMinKeySize() || params->getBitLength() > getMaxKeySize())
	{
		ERROR_MSG("This RSA key size (%lu) is not supported", params->getBitLength());
		return false;
	}

	if (params->getBitLength() < 1024)
	{
		WARNING_MSG("Using an RSA key size < 1024 bits is not recommended");
	}

	// Retrieve and validate the desired public exponent
	UINT64 pubExp = 0;
	if (!SymUtil::toUInt64(params->getE(), pubExp))
	{
		ERROR_MSG("RSA public exponent does not fit in 64 bits");
		return false;
	}
	if ((pubExp == 0) || (pubExp % 2 != 1))
	{
		ERROR_MSG("Invalid RSA public exponent");
		return false;
	}

	// Allocate and generate the key
	SYMCRYPT_RSA_PARAMS keyParams;
	keyParams.version = 1;
	keyParams.nBitsOfModulus = (UINT32) params->getBitLength();
	keyParams.nPrimes = 2;
	keyParams.nPubExp = 1;

	PSYMCRYPT_RSAKEY rsa = SymCryptRsakeyAllocate(&keyParams, 0);
	if (rsa == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt RSA key");
		return false;
	}

	SYMCRYPT_ERROR scError = SymCryptRsakeyGenerate(
		rsa, &pubExp, 1,
		SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCryptRsakeyGenerate", scError);
		SymCryptRsakeyFree(rsa);
		return false;
	}

	// Export all key components
	UINT32 modLen = SymCryptRsakeySizeofModulus(rsa);
	UINT32 pLen = SymCryptRsakeySizeofPrime(rsa, 0);
	UINT32 qLen = SymCryptRsakeySizeofPrime(rsa, 1);

	ByteString bN, bE, bP, bQ, bDP1, bDQ1, bPQ, bD;
	bN.resize(modLen);
	bP.resize(pLen);
	bQ.resize(qLen);

	UINT64 outPubExp = 0;
	PBYTE primes[2] = { bP.byte_str(), bQ.byte_str() };
	SIZE_T primeSizes[2] = { pLen, qLen };

	scError = SymCryptRsakeyGetValue(
		rsa,
		bN.byte_str(), modLen,
		&outPubExp, 1,
		primes, primeSizes, 2,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCryptRsakeyGetValue", scError);
		SymCryptRsakeyFree(rsa);
		return false;
	}

	// Export the CRT components (dp1, dq1, pq) and the private exponent d
	bDP1.resize(pLen);
	bDQ1.resize(qLen);
	bPQ.resize(pLen);
	bD.resize(modLen);

	PBYTE crtExps[2] = { bDP1.byte_str(), bDQ1.byte_str() };
	SIZE_T crtExpSizes[2] = { pLen, qLen };

	scError = SymCryptRsakeyGetCrtValue(
		rsa,
		crtExps, crtExpSizes, 2,
		bPQ.byte_str(), pLen,
		bD.byte_str(), modLen,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCryptRsakeyGetCrtValue", scError);
		SymCryptRsakeyFree(rsa);
		return false;
	}

	SymCryptRsakeyFree(rsa);

	// The public exponent is what was requested
	bE = params->getE();

	// Populate the key-pair object
	SymCryptRSAKeyPair* kp = new SymCryptRSAKeyPair();

	SymCryptRSAPublicKey* pub = (SymCryptRSAPublicKey*) kp->getPublicKey();
	pub->setN(bN);
	pub->setE(bE);

	SymCryptRSAPrivateKey* priv = (SymCryptRSAPrivateKey*) kp->getPrivateKey();
	priv->setP(bP);
	priv->setQ(bQ);
	priv->setDP1(bDP1);
	priv->setDQ1(bDQ1);
	priv->setPQ(bPQ);
	priv->setD(bD);
	priv->setN(bN);
	priv->setE(bE);

	*ppKeyPair = kp;

	return true;
}

unsigned long SymCryptRSA::getMinKeySize()
{
	return 512;
}

unsigned long SymCryptRSA::getMaxKeySize()
{
	// SymCrypt supports large moduli; use the same practical bound as OpenSSL
	return 16384;
}

bool SymCryptRSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	if ((ppKeyPair == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	SymCryptRSAKeyPair* kp = new SymCryptRSAKeyPair();

	bool rv = true;

	if (!((RSAPublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((RSAPrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
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

bool SymCryptRSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	if ((ppPublicKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptRSAPublicKey* pub = new SymCryptRSAPublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;
		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool SymCryptRSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	if ((ppPrivateKey == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SymCryptRSAPrivateKey* priv = new SymCryptRSAPrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;
		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* SymCryptRSA::newPublicKey()
{
	return (PublicKey*) new SymCryptRSAPublicKey();
}

PrivateKey* SymCryptRSA::newPrivateKey()
{
	return (PrivateKey*) new SymCryptRSAPrivateKey();
}

AsymmetricParameters* SymCryptRSA::newParameters()
{
	return (AsymmetricParameters*) new RSAParameters();
}

bool SymCryptRSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	RSAParameters* params = new RSAParameters();

	if (!params->deserialise(serialisedData))
	{
		delete params;
		return false;
	}

	*ppParams = params;

	return true;
}
