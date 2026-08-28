/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAPrivateKey.cpp

 SymCrypt composite ML-DSA private key class

 The interoperable private key encoding wraps the raw composite private key
 (mldsaSeed || tradSK) in a OneAsymmetricKey/PrivateKeyInfo structure whose
 algorithm identifier is the composite algorithm OID and whose parameters are
 absent, as specified by draft-ietf-lamps-pq-composite-sigs.
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "log.h"
#include "SymCryptCompositeMLDSAPrivateKey.h"
#include "CompositeMLDSAUtil.h"
#include <string.h>

// --- Minimal DER helpers --------------------------------------------------

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

static ByteString derTLV(unsigned char tag, const ByteString& content)
{
	ByteString out;
	out += tag;
	out += derLength(content.size());
	out += content;
	return out;
}

namespace {
struct DerCursor
{
	const unsigned char* p;
	size_t remaining;

	DerCursor(const ByteString& b) : p(b.const_byte_str()), remaining(b.size()) { }
	DerCursor(const unsigned char* buf, size_t len) : p(buf), remaining(len) { }

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

// --- SymCryptCompositeMLDSAPrivateKey -------------------------------------

// The type
/*static*/ const char* SymCryptCompositeMLDSAPrivateKey::type = "SymCrypt Composite ML-DSA Private Key";

bool SymCryptCompositeMLDSAPrivateKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

unsigned long SymCryptCompositeMLDSAPrivateKey::getBitLength() const
{
	return value.bits();
}

unsigned long SymCryptCompositeMLDSAPrivateKey::getOutputLength() const
{
	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(algorithm, meta))
	{
		return 0;
	}

	return (unsigned long)(meta.mldsaSigLen + 2 * (meta.ecFieldLen + 3) + 4);
}

unsigned long SymCryptCompositeMLDSAPrivateKey::getAlgorithm() const
{
	return algorithm;
}

void SymCryptCompositeMLDSAPrivateKey::setAlgorithm(const unsigned long inAlgorithm)
{
	algorithm = inAlgorithm;
}

const ByteString& SymCryptCompositeMLDSAPrivateKey::getValue() const
{
	return value;
}

void SymCryptCompositeMLDSAPrivateKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

// Encode into PKCS#8 DER
ByteString SymCryptCompositeMLDSAPrivateKey::PKCS8Encode()
{
	ByteString der;

	CompositeMLDSA::Metadata meta;
	if (value.size() == 0 || !CompositeMLDSA::metadataFor(algorithm, meta))
	{
		return der;
	}

	// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER } (no params)
	ByteString algId = derTLV(0x30, derTLV(0x06, meta.oid));

	// PrivateKeyInfo ::= SEQUENCE { version INTEGER 0, algId, privateKey OCTET STRING }
	ByteString pkInfo;
	ByteString ver;
	ver += (unsigned char)0x00;
	pkInfo += derTLV(0x02, ver);        // version = 0
	pkInfo += algId;
	pkInfo += derTLV(0x04, value);      // privateKey OCTET STRING (raw composite key)

	der = derTLV(0x30, pkInfo);

	return der;
}

// Decode from PKCS#8 BER
bool SymCryptCompositeMLDSAPrivateKey::PKCS8Decode(const ByteString& ber)
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

	// algorithm OBJECT IDENTIFIER
	if (!algId.readTLV(tag, content, len) || tag != 0x06)
	{
		return false;
	}
	ByteString oidValue(content, len);

	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataForOID(oidValue, meta))
	{
		ERROR_MSG("Unknown composite ML-DSA algorithm OID");
		return false;
	}

	// privateKey OCTET STRING
	if (!info.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}

	setAlgorithm(meta.algorithm);
	setValue(ByteString(content, len));

	return true;
}

ByteString SymCryptCompositeMLDSAPrivateKey::serialise() const
{
	return value.serialise() +
	       ByteString(algorithm).serialise();
}

bool SymCryptCompositeMLDSAPrivateKey::deserialise(ByteString& serialised)
{
	ByteString dValue = ByteString::chainDeserialise(serialised);
	ByteString dAlgorithm = ByteString::chainDeserialise(serialised);

	if (dValue.size() == 0 || dAlgorithm.size() != 8)
	{
		return false;
	}

	setValue(dValue);
	setAlgorithm(dAlgorithm.long_val());

	return true;
}

#endif // WITH_ML_DSA && WITH_ECC
