/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAPrivateKey.cpp

 SymCrypt ML-DSA private key class

 SymCrypt has no DER key (de)serialisation, so the PKCS#8 encode/decode used by
 SoftHSM for private key wrapping is implemented here with a small, self
 contained ASN.1 DER encoder/parser. The structure follows the IETF LAMPS
 ML-DSA key encoding (draft-ietf-lamps-dilithium-certificates): a PKCS#8
 PrivateKeyInfo whose privateKey OCTET STRING wraps a CHOICE that is either the
 32-byte seed ([0] IMPLICIT), the expanded FIPS 204 private key (OCTET STRING),
 or both (SEQUENCE).
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_DSA
#include "log.h"
#include "SymCryptMLDSAPrivateKey.h"
#include "SymCryptMLDSAUtil.h"
#include "MLDSAParameters.h"
#include <string.h>

// id-ml-dsa-44/65/87 OID contents (2.16.840.1.101.3.4.3.{17,18,19}), without the
// leading tag/length (i.e. the value of the OID TLV).
static const unsigned char mldsaOID44[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11 };
static const unsigned char mldsaOID65[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12 };
static const unsigned char mldsaOID87[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13 };

// --- Minimal DER helpers -------------------------------------------------

// Encode a DER length
static ByteString derLength(size_t len)
{
	ByteString out;
	if (len < 0x80)
	{
		out += (unsigned char)len;
	}
	else
	{
		unsigned char lenBytes[8];
		size_t nBytes = 0;
		size_t v = len;
		while (v > 0)
		{
			lenBytes[nBytes++] = (unsigned char)(v & 0xFF);
			v >>= 8;
		}
		out += (unsigned char)(0x80 | nBytes);
		for (size_t j = nBytes; j > 0; j--)
		{
			out += lenBytes[j - 1];
		}
	}
	return out;
}

// Encode a TLV given a tag and content
static ByteString derTLV(unsigned char tag, const ByteString& content)
{
	ByteString out;
	out += tag;
	out += derLength(content.size());
	out += content;
	return out;
}

// Encode a small non-negative integer as a DER INTEGER
static ByteString derSmallInteger(unsigned char value)
{
	ByteString content;
	content += value;
	return derTLV(0x02, content);
}

// A simple forward cursor DER parser
namespace {
struct DerCursor
{
	const unsigned char* p;
	size_t remaining;

	DerCursor(const ByteString& b) : p(b.const_byte_str()), remaining(b.size()) { }
	DerCursor(const unsigned char* buf, size_t len) : p(buf), remaining(len) { }

	// Read a TLV: on success sets tag, points content at the value and advances
	bool readTLV(unsigned char& tag, const unsigned char*& content, size_t& contentLen)
	{
		if (remaining < 2)
		{
			return false;
		}
		tag = p[0];
		size_t idx = 1;
		size_t len = 0;
		if ((p[idx] & 0x80) == 0)
		{
			len = p[idx];
			idx++;
		}
		else
		{
			size_t nBytes = p[idx] & 0x7F;
			idx++;
			if (nBytes == 0 || nBytes > 4 || (idx + nBytes) > remaining)
			{
				return false;
			}
			for (size_t j = 0; j < nBytes; j++)
			{
				len = (len << 8) | p[idx + j];
			}
			idx += nBytes;
		}
		if ((idx + len) > remaining)
		{
			return false;
		}
		content = p + idx;
		contentLen = len;
		p += idx + len;
		remaining -= idx + len;
		return true;
	}
};

// Map an ML-DSA parameter set to its OID value bytes
static bool oidForParameterSet(unsigned long parameterSet, const unsigned char*& oid, size_t& oidLen)
{
	switch (parameterSet)
	{
		case MLDSAParameters::ML_DSA_44_PARAMETER_SET:
			oid = mldsaOID44; oidLen = sizeof(mldsaOID44); return true;
		case MLDSAParameters::ML_DSA_65_PARAMETER_SET:
			oid = mldsaOID65; oidLen = sizeof(mldsaOID65); return true;
		case MLDSAParameters::ML_DSA_87_PARAMETER_SET:
			oid = mldsaOID87; oidLen = sizeof(mldsaOID87); return true;
		default:
			return false;
	}
}

// Map an OID value (as parsed from DER) to an ML-DSA parameter set
static unsigned long parameterSetForOID(const unsigned char* oid, size_t oidLen)
{
	if (oidLen == sizeof(mldsaOID44) && memcmp(oid, mldsaOID44, oidLen) == 0)
	{
		return MLDSAParameters::ML_DSA_44_PARAMETER_SET;
	}
	if (oidLen == sizeof(mldsaOID65) && memcmp(oid, mldsaOID65, oidLen) == 0)
	{
		return MLDSAParameters::ML_DSA_65_PARAMETER_SET;
	}
	if (oidLen == sizeof(mldsaOID87) && memcmp(oid, mldsaOID87, oidLen) == 0)
	{
		return MLDSAParameters::ML_DSA_87_PARAMETER_SET;
	}
	return 0UL;
}

// Expand a 32-byte ML-DSA seed to the FIPS 204 private key encoding using SymCrypt
static bool expandSeed(unsigned long parameterSet, const ByteString& seed, ByteString& expandedOut)
{
	SYMCRYPT_MLDSA_PARAMS params;
	if (!SymMLDSA::paramsFromParameterSet(parameterSet, params))
	{
		return false;
	}

	SIZE_T cbPriv = 0;
	SYMCRYPT_ERROR scError = SymCryptMlDsaSizeofKeyFormatFromParams(
		params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPriv);
	if (scError != SYMCRYPT_NO_ERROR || cbPriv == 0)
	{
		return false;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(params);
	if (key == NULL)
	{
		return false;
	}

	scError = SymCryptMlDsakeySetValue(
		seed.const_byte_str(), seed.size(),
		SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymCryptMlDsakeyFree(key);
		return false;
	}

	ByteString expanded;
	expanded.resize(cbPriv);
	scError = SymCryptMlDsakeyGetValue(
		key, &expanded[0], cbPriv,
		SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
		0);
	SymCryptMlDsakeyFree(key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		return false;
	}

	expandedOut = expanded;
	return true;
}
}

// --- SymCryptMLDSAPrivateKey ---------------------------------------------

// Constructors
SymCryptMLDSAPrivateKey::SymCryptMLDSAPrivateKey()
{
	mldsakey = NULL;
}

// Destructor
SymCryptMLDSAPrivateKey::~SymCryptMLDSAPrivateKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptMLDSAPrivateKey::type = "SymCrypt ML-DSA Private Key";

// Check if the key is of the given type
bool SymCryptMLDSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(SymCryptMLDSAPrivateKey::type, inType) || MLDSAPrivateKey::isOfType(inType);
}

void SymCryptMLDSAPrivateKey::setValue(const ByteString& inValue)
{
	MLDSAPrivateKey::setValue(inValue);

	freeSymCryptKey();
}

void SymCryptMLDSAPrivateKey::setSeed(const ByteString& inSeed)
{
	MLDSAPrivateKey::setSeed(inSeed);

	freeSymCryptKey();
}

// Encode into PKCS#8 DER
ByteString SymCryptMLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;

	const unsigned char* oid = NULL;
	size_t oidLen = 0;
	if (!oidForParameterSet(getParameterSet(), oid, oidLen))
	{
		ERROR_MSG("Unknown ML-DSA parameter set; cannot PKCS#8 encode");
		return der;
	}

	// privateKey CHOICE: prefer the seed representation when available, otherwise
	// fall back to the expanded key representation.
	ByteString innerChoice;
	if (seed.size() == 32)
	{
		innerChoice = derTLV(0x80, seed);		// [0] IMPLICIT OCTET STRING (seed)
	}
	else if (value.size() != 0)
	{
		innerChoice = derTLV(0x04, value);		// expandedKey OCTET STRING
	}
	else
	{
		ERROR_MSG("No ML-DSA private key material to PKCS#8 encode");
		return der;
	}

	// AlgorithmIdentifier { OID } (no parameters)
	ByteString algId = derTLV(0x06, ByteString(oid, oidLen));
	ByteString algIdSeq = derTLV(0x30, algId);

	// PrivateKeyInfo
	ByteString pkInfo;
	pkInfo += derSmallInteger(0x00);		// version = 0
	pkInfo += algIdSeq;
	pkInfo += derTLV(0x04, innerChoice);		// privateKey OCTET STRING

	der = derTLV(0x30, pkInfo);

	return der;
}

// Decode from PKCS#8 BER
bool SymCryptMLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
{
	if (ber.size() == 0)
	{
		return false;
	}

	DerCursor top(ber);
	unsigned char tag;
	const unsigned char* content;
	size_t len;

	// PrivateKeyInfo SEQUENCE
	if (!top.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	DerCursor info(content, len);

	// version INTEGER
	if (!info.readTLV(tag, content, len) || tag != 0x02)
	{
		return false;
	}

	// AlgorithmIdentifier SEQUENCE
	if (!info.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	DerCursor algId(content, len);

	// OID
	if (!algId.readTLV(tag, content, len) || tag != 0x06)
	{
		return false;
	}
	unsigned long parameterSet = parameterSetForOID(content, len);
	if (parameterSet == 0UL)
	{
		ERROR_MSG("Unknown ML-DSA OID in PKCS#8");
		return false;
	}

	// privateKey OCTET STRING -> CHOICE
	if (!info.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}
	DerCursor choice(content, len);

	// Read the CHOICE alternative
	if (!choice.readTLV(tag, content, len))
	{
		return false;
	}

	if (tag == 0x80)
	{
		// seed [0] IMPLICIT OCTET STRING
		ByteString seedBS(content, len);
		if (seedBS.size() != 32)
		{
			ERROR_MSG("Invalid ML-DSA seed length in PKCS#8: %zu", (size_t)seedBS.size());
			return false;
		}
		ByteString expanded;
		if (!expandSeed(parameterSet, seedBS, expanded))
		{
			ERROR_MSG("Failed to expand ML-DSA seed");
			return false;
		}
		setSeed(seedBS);
		setValue(expanded);
		return true;
	}
	else if (tag == 0x04)
	{
		// expandedKey OCTET STRING
		ByteString expanded(content, len);
		setSeed(ByteString());
		setValue(expanded);
		return true;
	}
	else if (tag == 0x30)
	{
		// both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
		DerCursor both(content, len);
		if (!both.readTLV(tag, content, len) || tag != 0x04)
		{
			return false;
		}
		ByteString seedBS(content, len);
		if (!both.readTLV(tag, content, len) || tag != 0x04)
		{
			return false;
		}
		ByteString expanded(content, len);
		setSeed(seedBS);
		setValue(expanded);
		return true;
	}

	ERROR_MSG("Unsupported ML-DSA private key CHOICE tag 0x%02X", (unsigned)tag);
	return false;
}

// Release the cached SymCrypt object
void SymCryptMLDSAPrivateKey::freeSymCryptKey()
{
	if (mldsakey != NULL)
	{
		SymCryptMlDsakeyFree(mldsakey);
		mldsakey = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_MLDSAKEY SymCryptMLDSAPrivateKey::getSymCryptKey()
{
	if (mldsakey == NULL)
	{
		createSymCryptKey();
	}

	return mldsakey;
}

// Build the SymCrypt key representation from the stored components
void SymCryptMLDSAPrivateKey::createSymCryptKey()
{
	if (mldsakey != NULL)
	{
		return;
	}

	if (value.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt ML-DSA private key: missing value");
		return;
	}

	SYMCRYPT_MLDSA_PARAMS params;
	if (!SymMLDSA::paramsFromParameterSet(getParameterSet(), params))
	{
		ERROR_MSG("Unknown ML-DSA parameter set (private key length: %zu)", (size_t)value.size());
		return;
	}

	PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(params);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt ML-DSA key");
		return;
	}

	SYMCRYPT_ERROR scError = SymCryptMlDsakeySetValue(
		value.const_byte_str(), value.size(),
		SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
		0,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptMlDsakeySetValue (private) failed (0x%08X)", (unsigned)scError);
		SymCryptMlDsakeyFree(key);
		return;
	}

	mldsakey = key;
}

#endif // WITH_ML_DSA
