/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSAUtil.cpp

 Shared helpers implementing the IETF composite ML-DSA construction
 (draft-ietf-lamps-pq-composite-sigs).
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "CompositeMLDSAUtil.h"
#include "CryptoFactory.h"
#include "MLDSAParameters.h"
#include "log.h"
#include <string.h>

// The fixed prefix: ASCII "CompositeAlgorithmSignatures2025"
static const char* COMPOSITE_PREFIX = "CompositeAlgorithmSignatures2025";

// EC curve OID DER encodings (full TLV)
static const unsigned char OID_P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const unsigned char OID_P384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const unsigned char OID_P521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

// --- Minimal DER helpers (mirrors SymCryptECPrivateKey.cpp) ---------------

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

// Encode a non-negative big-endian magnitude as a DER INTEGER
static ByteString derInteger(const ByteString& magnitude)
{
	// Strip leading zero bytes
	size_t start = 0;
	while (start + 1 < magnitude.size() && magnitude.const_byte_str()[start] == 0x00)
	{
		start++;
	}
	ByteString value = magnitude.substr(start);
	if (value.size() == 0)
	{
		value += (unsigned char)0x00;
	}
	// Add a leading zero if the high bit is set (to keep it positive)
	ByteString content;
	if (value.const_byte_str()[0] & 0x80)
	{
		content += (unsigned char)0x00;
	}
	content += value;
	return derTLV(0x02, content);
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

// --- Metadata table -------------------------------------------------------

static ByteString compositeOID(unsigned char lastArc)
{
	unsigned char v[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, lastArc };
	return ByteString(v, sizeof(v));
}

bool CompositeMLDSA::metadataFor(unsigned long algorithm, Metadata& out)
{
	switch (algorithm)
	{
		case Algorithm::MLDSA44_ECDSA_P256_SHA256:
			out.algorithm = algorithm;
			out.label = "COMPSIG-MLDSA44-ECDSA-P256-SHA256";
			out.mldsaParameterSet = MLDSAParameters::ML_DSA_44_PARAMETER_SET;
			out.mldsaPubLen = MLDSAParameters::ML_DSA_44_PUB_LENGTH;
			out.mldsaSigLen = MLDSAParameters::ML_DSA_44_SIGNATURE_LENGTH;
			out.curveOID = ByteString(OID_P256, sizeof(OID_P256));
			out.ecFieldLen = 32;
			out.phHash = HashAlgo::SHA256;
			out.ecdsaHash = HashAlgo::SHA256;
			out.oid = compositeOID(40);
			return true;

		case Algorithm::MLDSA65_ECDSA_P256_SHA512:
			out.algorithm = algorithm;
			out.label = "COMPSIG-MLDSA65-ECDSA-P256-SHA512";
			out.mldsaParameterSet = MLDSAParameters::ML_DSA_65_PARAMETER_SET;
			out.mldsaPubLen = MLDSAParameters::ML_DSA_65_PUB_LENGTH;
			out.mldsaSigLen = MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
			out.curveOID = ByteString(OID_P256, sizeof(OID_P256));
			out.ecFieldLen = 32;
			out.phHash = HashAlgo::SHA512;
			out.ecdsaHash = HashAlgo::SHA256;
			out.oid = compositeOID(45);
			return true;

		case Algorithm::MLDSA65_ECDSA_P384_SHA512:
			out.algorithm = algorithm;
			out.label = "COMPSIG-MLDSA65-ECDSA-P384-SHA512";
			out.mldsaParameterSet = MLDSAParameters::ML_DSA_65_PARAMETER_SET;
			out.mldsaPubLen = MLDSAParameters::ML_DSA_65_PUB_LENGTH;
			out.mldsaSigLen = MLDSAParameters::ML_DSA_65_SIGNATURE_LENGTH;
			out.curveOID = ByteString(OID_P384, sizeof(OID_P384));
			out.ecFieldLen = 48;
			out.phHash = HashAlgo::SHA512;
			out.ecdsaHash = HashAlgo::SHA384;
			out.oid = compositeOID(46);
			return true;

		case Algorithm::MLDSA87_ECDSA_P384_SHA512:
			out.algorithm = algorithm;
			out.label = "COMPSIG-MLDSA87-ECDSA-P384-SHA512";
			out.mldsaParameterSet = MLDSAParameters::ML_DSA_87_PARAMETER_SET;
			out.mldsaPubLen = MLDSAParameters::ML_DSA_87_PUB_LENGTH;
			out.mldsaSigLen = MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
			out.curveOID = ByteString(OID_P384, sizeof(OID_P384));
			out.ecFieldLen = 48;
			out.phHash = HashAlgo::SHA512;
			out.ecdsaHash = HashAlgo::SHA384;
			out.oid = compositeOID(49);
			return true;

		case Algorithm::MLDSA87_ECDSA_P521_SHA512:
			out.algorithm = algorithm;
			out.label = "COMPSIG-MLDSA87-ECDSA-P521-SHA512";
			out.mldsaParameterSet = MLDSAParameters::ML_DSA_87_PARAMETER_SET;
			out.mldsaPubLen = MLDSAParameters::ML_DSA_87_PUB_LENGTH;
			out.mldsaSigLen = MLDSAParameters::ML_DSA_87_SIGNATURE_LENGTH;
			out.curveOID = ByteString(OID_P521, sizeof(OID_P521));
			out.ecFieldLen = 66;
			out.phHash = HashAlgo::SHA512;
			out.ecdsaHash = HashAlgo::SHA512;
			out.oid = compositeOID(54);
			return true;

		default:
			return false;
	}
}

bool CompositeMLDSA::metadataForOID(const ByteString& oidValue, Metadata& out)
{
	static const unsigned long allAlgorithms[] = {
		Algorithm::MLDSA44_ECDSA_P256_SHA256,
		Algorithm::MLDSA65_ECDSA_P256_SHA512,
		Algorithm::MLDSA65_ECDSA_P384_SHA512,
		Algorithm::MLDSA87_ECDSA_P384_SHA512,
		Algorithm::MLDSA87_ECDSA_P521_SHA512
	};

	for (size_t i = 0; i < sizeof(allAlgorithms) / sizeof(allAlgorithms[0]); i++)
	{
		Metadata m;
		if (metadataFor(allAlgorithms[i], m) && m.oid == oidValue)
		{
			out = m;
			return true;
		}
	}

	return false;
}

// --- Message representative -----------------------------------------------

bool CompositeMLDSA::buildMessageRepresentative(const Metadata& meta, const ByteString& context,
						const ByteString& message, ByteString& mPrime)
{
	if (context.size() > 255)
	{
		ERROR_MSG("Composite ML-DSA context too long (%zu > 255)", context.size());
		return false;
	}

	// PH( M )
	HashAlgorithm* digest = CryptoFactory::i()->getHashAlgorithm(meta.phHash);
	if (digest == NULL)
	{
		return false;
	}

	ByteString ph;
	if (!digest->hashInit() || !digest->hashUpdate(message) || !digest->hashFinal(ph))
	{
		CryptoFactory::i()->recycleHashAlgorithm(digest);
		return false;
	}
	CryptoFactory::i()->recycleHashAlgorithm(digest);

	// M' = Prefix || Label || len(ctx) || ctx || PH( M )
	mPrime.wipe();
	mPrime += ByteString((const unsigned char*)COMPOSITE_PREFIX, strlen(COMPOSITE_PREFIX));
	mPrime += ByteString((const unsigned char*)meta.label, strlen(meta.label));
	mPrime += (unsigned char)context.size();
	mPrime += context;
	mPrime += ph;

	return true;
}

// --- ECDSA signature (raw <-> DER) ----------------------------------------

ByteString CompositeMLDSA::ecdsaRawToDer(const ByteString& raw, size_t ecFieldLen)
{
	if (raw.size() != 2 * ecFieldLen)
	{
		return ByteString();
	}

	ByteString r = raw.substr(0, ecFieldLen);
	ByteString s = raw.substr(ecFieldLen, ecFieldLen);

	ByteString seq;
	seq += derInteger(r);
	seq += derInteger(s);

	return derTLV(0x30, seq);
}

bool CompositeMLDSA::ecdsaDerToRaw(const ByteString& der, size_t ecFieldLen, ByteString& raw)
{
	DerCursor top(der);
	unsigned char tag;
	const unsigned char* content;
	size_t len;

	if (!top.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	DerCursor body(content, len);

	const unsigned char* rContent;
	size_t rLen;
	if (!body.readTLV(tag, rContent, rLen) || tag != 0x02)
	{
		return false;
	}

	const unsigned char* sContent;
	size_t sLen;
	if (!body.readTLV(tag, sContent, sLen) || tag != 0x02)
	{
		return false;
	}

	// Left-pad each component to ecFieldLen (stripping any leading 0x00 sign byte)
	ByteString rBS(rContent, rLen);
	ByteString sBS(sContent, sLen);

	// Strip leading zeros
	size_t rStart = 0;
	while (rStart + 1 <= rBS.size() && rStart < rBS.size() && rBS[rStart] == 0x00 && (rBS.size() - rStart) > ecFieldLen)
	{
		rStart++;
	}
	size_t sStart = 0;
	while (sStart + 1 <= sBS.size() && sStart < sBS.size() && sBS[sStart] == 0x00 && (sBS.size() - sStart) > ecFieldLen)
	{
		sStart++;
	}
	rBS = rBS.substr(rStart);
	sBS = sBS.substr(sStart);

	if (rBS.size() > ecFieldLen || sBS.size() > ecFieldLen)
	{
		return false;
	}

	ByteString padR, padS;
	if (rBS.size() < ecFieldLen)
	{
		padR.resize(ecFieldLen - rBS.size());
		memset(&padR[0], 0, padR.size());
	}
	padR += rBS;
	if (sBS.size() < ecFieldLen)
	{
		padS.resize(ecFieldLen - sBS.size());
		memset(&padS[0], 0, padS.size());
	}
	padS += sBS;

	raw.wipe();
	raw += padR;
	raw += padS;

	return raw.size() == 2 * ecFieldLen;
}

// --- EC private key (RFC 5915 ECPrivateKey) -------------------------------

ByteString CompositeMLDSA::encodeEcPrivateKey(const ByteString& d, const ByteString& curveOID)
{
	// ECPrivateKey ::= SEQUENCE {
	//     version        INTEGER { 1 },
	//     privateKey     OCTET STRING,
	//     parameters [0] EXPLICIT ECParameters (namedCurve OID) }
	ByteString body;

	ByteString ver;
	ver += (unsigned char)0x01;
	body += derTLV(0x02, ver);          // version = 1
	body += derTLV(0x04, d);            // privateKey OCTET STRING
	body += derTLV(0xA0, curveOID);     // [0] namedCurve OID

	return derTLV(0x30, body);
}

bool CompositeMLDSA::decodeEcPrivateKey(const ByteString& der, ByteString& d)
{
	DerCursor top(der);
	unsigned char tag;
	const unsigned char* content;
	size_t len;

	if (!top.readTLV(tag, content, len) || tag != 0x30)
	{
		return false;
	}
	DerCursor body(content, len);

	// version INTEGER
	if (!body.readTLV(tag, content, len) || tag != 0x02)
	{
		return false;
	}

	// privateKey OCTET STRING
	if (!body.readTLV(tag, content, len) || tag != 0x04)
	{
		return false;
	}

	d = ByteString(content, len);

	return d.size() != 0;
}

#endif // WITH_ML_DSA && WITH_ECC
