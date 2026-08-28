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
 SymCryptECPrivateKey.cpp

 SymCrypt Elliptic Curve private key class

 SymCrypt has no DER key (de)serialisation, so the PKCS#8 encode/decode used by
 SoftHSM for private key wrapping is implemented here with a small, self
 contained ASN.1 DER encoder/parser, producing a standard RFC 5915/5208
 EC PrivateKeyInfo structure.
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "SymCryptECPrivateKey.h"
#include "SymCryptECUtil.h"
#include <string.h>

// The id-ecPublicKey OID: 1.2.840.10045.2.1
static const unsigned char ecPublicKeyOID[] =
	{ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

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
}

// --- SymCryptECPrivateKey ------------------------------------------------

// Constructors
SymCryptECPrivateKey::SymCryptECPrivateKey()
{
	curve = NULL;
	eckey = NULL;
}

// Destructor
SymCryptECPrivateKey::~SymCryptECPrivateKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptECPrivateKey::type = "SymCrypt EC Private Key";

// Check if the key is of the given type
bool SymCryptECPrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the base point order length
unsigned long SymCryptECPrivateKey::getOrderLength() const
{
	PSYMCRYPT_ECURVE c = ensureCurve();

	if (c == NULL)
	{
		return 0;
	}

	return (unsigned long)((SymCryptEcurveBitsizeofGroupOrder(c) + 7) / 8);
}

// Setters for the EC private key components
void SymCryptECPrivateKey::setD(const ByteString& inD)
{
	ECPrivateKey::setD(inD);

	freeSymCryptKey();
}

// Setters for the EC public key components
void SymCryptECPrivateKey::setEC(const ByteString& inEC)
{
	ECPrivateKey::setEC(inEC);

	freeSymCryptKey();
}

// Encode into PKCS#8 DER
ByteString SymCryptECPrivateKey::PKCS8Encode()
{
	ByteString der;

	if (ec.size() == 0 || d.size() == 0)
	{
		return der;
	}

	// RFC 5915 ECPrivateKey
	ByteString ecPrivateKey;
	ecPrivateKey += derSmallInteger(0x01);		// version = 1
	ecPrivateKey += derTLV(0x04, d);		// privateKey OCTET STRING (raw scalar)
	ByteString ecPrivateKeySeq = derTLV(0x30, ecPrivateKey);

	// AlgorithmIdentifier { id-ecPublicKey, namedCurve OID }
	ByteString algId;
	algId += ByteString(ecPublicKeyOID, sizeof(ecPublicKeyOID));
	algId += ec;					// the curve OID (already DER encoded)
	ByteString algIdSeq = derTLV(0x30, algId);

	// PrivateKeyInfo
	ByteString pkInfo;
	pkInfo += derSmallInteger(0x00);		// version = 0
	pkInfo += algIdSeq;
	pkInfo += derTLV(0x04, ecPrivateKeySeq);	// privateKey OCTET STRING

	der = derTLV(0x30, pkInfo);

	return der;
}

// Decode from PKCS#8 BER
bool SymCryptECPrivateKey::PKCS8Decode(const ByteString& ber)
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

	// id-ecPublicKey OID (skipped)
	if (!algId.readTLV(tag, content, len) || tag != 0x06)
	{
		return false;
	}

	// namedCurve OID -> reconstruct the DER-encoded ECParameters (the OID TLV)
	if (!algId.readTLV(tag, content, len) || tag != 0x06)
	{
		return false;
	}
	ByteString curveOID = derTLV(0x06, ByteString(content, len));

	// privateKey OCTET STRING -> ECPrivateKey SEQUENCE
	if (!info.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}
	DerCursor ecPriv(content, len);

	// ECPrivateKey SEQUENCE
	if (!ecPriv.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	DerCursor ecPrivBody(content, len);

	// version INTEGER (1)
	if (!ecPrivBody.readTLV(tag, content, len) || tag != 0x02)
	{
		return false;
	}

	// privateKey OCTET STRING -> the scalar d
	if (!ecPrivBody.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}
	ByteString inD(content, len);

	setEC(curveOID);
	setD(inD);

	return true;
}

// Ensure the SymCrypt curve object has been built from the stored EC params
PSYMCRYPT_ECURVE SymCryptECPrivateKey::ensureCurve() const
{
	if (curve == NULL && ec.size() != 0)
	{
		curve = SymEC::curveFromParams(ec);
	}

	return curve;
}

// Release the cached SymCrypt objects
void SymCryptECPrivateKey::freeSymCryptKey()
{
	if (eckey != NULL)
	{
		SymCryptEckeyFree(eckey);
		eckey = NULL;
	}

	if (curve != NULL)
	{
		SymCryptEcurveFree(curve);
		curve = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_ECKEY SymCryptECPrivateKey::getSymCryptKey()
{
	if (eckey == NULL)
	{
		createSymCryptKey();
	}

	return eckey;
}

// Build the SymCrypt key representation from the stored components
void SymCryptECPrivateKey::createSymCryptKey()
{
	if (eckey != NULL)
	{
		return;
	}

	if (ec.size() == 0 || d.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt EC private key: missing curve or scalar");
		return;
	}

	PSYMCRYPT_ECURVE c = ensureCurve();
	if (c == NULL)
	{
		return;
	}

	PSYMCRYPT_ECKEY key = SymCryptEckeyAllocate(c);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt EC key");
		return;
	}

	// SymCrypt requires the private scalar to be exactly the size of the group
	// order scalar; the stored value may have had leading zero bytes stripped,
	// so left-pad it to the expected length.
	SIZE_T cbPrivateKey = SymCryptEckeySizeofPrivateKey(key);
	ByteString priv = d;
	if (priv.size() > cbPrivateKey)
	{
		ERROR_MSG("EC private scalar is larger than the group order size");
		SymCryptEckeyFree(key);
		return;
	}
	if (priv.size() < cbPrivateKey)
	{
		ByteString padded;
		padded.resize(cbPrivateKey - priv.size());
		memset(&padded[0], 0, padded.size());
		padded += priv;
		priv = padded;
	}

	SYMCRYPT_ERROR scError = SymCryptEckeySetValue(
		priv.const_byte_str(), cbPrivateKey,
		NULL, 0,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		SYMCRYPT_ECPOINT_FORMAT_XY,
		SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptEckeySetValue (private) failed (0x%08X)", (unsigned)scError);
		SymCryptEckeyFree(key);
		return;
	}

	eckey = key;
}

#endif // WITH_ECC
