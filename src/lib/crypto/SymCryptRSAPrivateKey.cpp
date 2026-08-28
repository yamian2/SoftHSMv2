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
 SymCryptRSAPrivateKey.cpp

 SymCrypt RSA private key class

 SymCrypt has no DER key (de)serialisation, so the PKCS#8 encode/decode used by
 SoftHSM for private key wrapping is implemented here with a small, self
 contained ASN.1 DER encoder/parser.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptRSAPrivateKey.h"
#include "SymCryptUtil.h"
#include <string.h>

// The rsaEncryption OID: 1.2.840.113549.1.1.1
static const unsigned char rsaEncryptionOID[] =
	{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

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
		// Emit most significant byte first
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

// Encode a magnitude (big-endian) as a DER INTEGER
static ByteString derInteger(const ByteString& magnitude)
{
	// Strip leading zero bytes
	const unsigned char* raw = magnitude.const_byte_str();
	size_t i = 0;
	while (i < magnitude.size() && raw[i] == 0)
	{
		i++;
	}

	ByteString content;
	if (i == magnitude.size())
	{
		// Value is zero
		content += (unsigned char)0x00;
	}
	else
	{
		content = magnitude.substr(i);
		// Prepend 0x00 if the high bit is set (keep it positive)
		if (content.const_byte_str()[0] & 0x80)
		{
			content = (unsigned char)0x00 + content;
		}
	}

	return derTLV(0x02, content);
}

// A simple forward cursor DER parser
namespace {
struct DerCursor
{
	const unsigned char* p;
	size_t remaining;

	DerCursor(const ByteString& b) : p(b.const_byte_str()), remaining(b.size()) { }

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
		// Advance past this element
		p += idx + len;
		remaining -= idx + len;
		return true;
	}
};
}

// Read a DER INTEGER value into a raw magnitude (leading sign byte stripped)
static bool derReadInteger(DerCursor& cur, ByteString& magnitude)
{
	unsigned char tag;
	const unsigned char* content;
	size_t len;
	if (!cur.readTLV(tag, content, len) || tag != 0x02)
	{
		return false;
	}
	// Strip a single leading 0x00 sign byte
	size_t start = 0;
	if (len > 1 && content[0] == 0x00)
	{
		start = 1;
	}
	magnitude.resize(len - start);
	if (len - start > 0)
	{
		memcpy(&magnitude[0], content + start, len - start);
	}
	return true;
}

// --- SymCryptRSAPrivateKey ----------------------------------------------

// Constructors
SymCryptRSAPrivateKey::SymCryptRSAPrivateKey()
{
	rsa = NULL;
}

// Destructor
SymCryptRSAPrivateKey::~SymCryptRSAPrivateKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptRSAPrivateKey::type = "SymCrypt RSA Private Key";

// Check if the key is of the given type
bool SymCryptRSAPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the RSA private key components
void SymCryptRSAPrivateKey::setP(const ByteString& inP)
{
	RSAPrivateKey::setP(inP);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setQ(const ByteString& inQ)
{
	RSAPrivateKey::setQ(inQ);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setPQ(const ByteString& inPQ)
{
	RSAPrivateKey::setPQ(inPQ);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setDP1(const ByteString& inDP1)
{
	RSAPrivateKey::setDP1(inDP1);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setDQ1(const ByteString& inDQ1)
{
	RSAPrivateKey::setDQ1(inDQ1);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setD(const ByteString& inD)
{
	RSAPrivateKey::setD(inD);
	freeSymCryptKey();
}

// Setters for the RSA public key components
void SymCryptRSAPrivateKey::setN(const ByteString& inN)
{
	RSAPrivateKey::setN(inN);
	freeSymCryptKey();
}

void SymCryptRSAPrivateKey::setE(const ByteString& inE)
{
	RSAPrivateKey::setE(inE);
	freeSymCryptKey();
}

// Encode into PKCS#8 DER
ByteString SymCryptRSAPrivateKey::PKCS8Encode()
{
	ByteString der;

	if (n.size() == 0 || e.size() == 0 || d.size() == 0 || p.size() == 0 || q.size() == 0)
	{
		return der;
	}

	// PKCS#1 RSAPrivateKey
	ByteString rsaPrivateKey;
	rsaPrivateKey += derInteger(ByteString("00"));	// version
	rsaPrivateKey += derInteger(n);
	rsaPrivateKey += derInteger(e);
	rsaPrivateKey += derInteger(d);
	rsaPrivateKey += derInteger(p);
	rsaPrivateKey += derInteger(q);
	rsaPrivateKey += derInteger(dp1);
	rsaPrivateKey += derInteger(dq1);
	rsaPrivateKey += derInteger(pq);
	ByteString rsaPrivateKeySeq = derTLV(0x30, rsaPrivateKey);

	// AlgorithmIdentifier { rsaEncryption, NULL }
	ByteString algId;
	algId += ByteString(rsaEncryptionOID, sizeof(rsaEncryptionOID));
	algId += (unsigned char)0x05;	// NULL
	algId += (unsigned char)0x00;
	ByteString algIdSeq = derTLV(0x30, algId);

	// PrivateKeyInfo
	ByteString pkInfo;
	pkInfo += derInteger(ByteString("00"));	// version
	pkInfo += algIdSeq;
	pkInfo += derTLV(0x04, rsaPrivateKeySeq);	// privateKey OCTET STRING

	der = derTLV(0x30, pkInfo);

	return der;
}

// Decode from PKCS#8 BER
bool SymCryptRSAPrivateKey::PKCS8Decode(const ByteString& ber)
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
	ByteString pkInfo(content, len);
	DerCursor info(pkInfo);

	// version INTEGER
	ByteString version;
	if (!derReadInteger(info, version))
	{
		return false;
	}

	// AlgorithmIdentifier SEQUENCE (skipped, assumed rsaEncryption)
	if (!info.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}

	// privateKey OCTET STRING
	if (!info.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}
	ByteString rsaPrivateKeySeq(content, len);

	// Parse the inner RSAPrivateKey SEQUENCE
	DerCursor pk(rsaPrivateKeySeq);
	if (!pk.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	ByteString body(content, len);
	DerCursor comp(body);

	ByteString vers, inN, inE, inD, inP, inQ, inDP1, inDQ1, inPQ;
	if (!derReadInteger(comp, vers) ||
	    !derReadInteger(comp, inN) ||
	    !derReadInteger(comp, inE) ||
	    !derReadInteger(comp, inD) ||
	    !derReadInteger(comp, inP) ||
	    !derReadInteger(comp, inQ) ||
	    !derReadInteger(comp, inDP1) ||
	    !derReadInteger(comp, inDQ1) ||
	    !derReadInteger(comp, inPQ))
	{
		return false;
	}

	setN(inN);
	setE(inE);
	setD(inD);
	setP(inP);
	setQ(inQ);
	setDP1(inDP1);
	setDQ1(inDQ1);
	setPQ(inPQ);

	return true;
}

// Release the cached SymCrypt key
void SymCryptRSAPrivateKey::freeSymCryptKey()
{
	if (rsa != NULL)
	{
		SymCryptRsakeyFree(rsa);
		rsa = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_RSAKEY SymCryptRSAPrivateKey::getSymCryptKey()
{
	if (rsa == NULL)
	{
		createSymCryptKey();
	}

	return rsa;
}

// Build the SymCrypt representation from the stored components
void SymCryptRSAPrivateKey::createSymCryptKey()
{
	if (rsa != NULL)
	{
		return;
	}

	if (n.size() == 0 || e.size() == 0 || p.size() == 0 || q.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt RSA private key: missing components");
		return;
	}

	UINT64 pubExp = 0;
	if (!SymUtil::toUInt64(e, pubExp))
	{
		ERROR_MSG("RSA public exponent does not fit in 64 bits");
		return;
	}

	SYMCRYPT_RSA_PARAMS params;
	params.version = 1;
	params.nBitsOfModulus = SymUtil::bitLength(n);
	params.nPrimes = 2;
	params.nPubExp = 1;

	PSYMCRYPT_RSAKEY key = SymCryptRsakeyAllocate(&params, 0);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt RSA private key");
		return;
	}

	PCBYTE primes[2] = { p.const_byte_str(), q.const_byte_str() };
	SIZE_T primeSizes[2] = { p.size(), q.size() };

	SYMCRYPT_ERROR scError = SymCryptRsakeySetValue(
		n.const_byte_str(), n.size(),
		&pubExp, 1,
		primes, primeSizes, 2,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_RSAKEY_ENCRYPT,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		SymUtil::logError("SymCryptRsakeySetValue (private)", scError);
		SymCryptRsakeyFree(key);
		return;
	}

	rsa = key;
}
