/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSAUtil.h

 Shared helpers implementing the IETF composite ML-DSA construction
 (draft-ietf-lamps-pq-composite-sigs). Only the ECDSA based combinations over
 the NIST curves are provided, matching the set supported by the .NET
 Bcl.Cryptography CompositeMLDsa implementation.

 The construction of the signed message representative is:

     M' = Prefix || Label || len(ctx) || ctx || PH( M )

 where Prefix is the fixed ASCII string "CompositeAlgorithmSignatures2025",
 Label is a per-algorithm ASCII string such as
 "COMPSIG-MLDSA65-ECDSA-P256-SHA512", len(ctx) is a single byte and PH is the
 per-algorithm pre-hash. The ML-DSA component signs M' with its context set to
 Label; the ECDSA component signs M' (hashed with the component hash) and the
 signature is DER encoded as an Ecdsa-Sig-Value. The composite public key,
 private key and signature are the simple concatenations of the component
 encodings.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_COMPOSITEMLDSAUTIL_H
#define _SOFTHSM_V2_COMPOSITEMLDSAUTIL_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "ByteString.h"
#include "HashAlgorithm.h"
#include "AsymmetricAlgorithm.h"

namespace CompositeMLDSA
{
	// Composite ML-DSA algorithm identifiers. The numeric values are the final
	// arc of the algorithm OID (1.3.6.1.5.5.7.6.<id>) as assigned by the draft.
	struct Algorithm
	{
		enum Type
		{
			Unknown                     = 0,
			MLDSA44_ECDSA_P256_SHA256   = 40,
			MLDSA65_ECDSA_P256_SHA512   = 45,
			MLDSA65_ECDSA_P384_SHA512   = 46,
			MLDSA87_ECDSA_P384_SHA512   = 49,
			MLDSA87_ECDSA_P521_SHA512   = 54
		};
	};

	// Per-algorithm metadata resolved from an algorithm identifier.
	struct Metadata
	{
		unsigned long   algorithm;      // Algorithm::Type value
		const char*     label;          // ASCII signature label
		unsigned long   mldsaParameterSet;   // CKP_ML_DSA_* value
		size_t          mldsaPubLen;    // ML-DSA public key length
		size_t          mldsaSigLen;    // ML-DSA signature length
		ByteString      curveOID;       // DER encoded EC curve OID
		size_t          ecFieldLen;     // EC field / coordinate length in bytes
		HashAlgo::Type  phHash;         // pre-hash (PH) for M'
		HashAlgo::Type  ecdsaHash;      // hash used by the ECDSA component
		ByteString      oid;            // DER encoded composite algorithm OID (value only, no tag/len)
	};

	// Resolve the metadata for a composite algorithm identifier.
	bool metadataFor(unsigned long algorithm, Metadata& out);

	// Resolve the metadata from a DER encoded composite algorithm OID value
	// (the bytes inside the OBJECT IDENTIFIER, without tag and length).
	bool metadataForOID(const ByteString& oidValue, Metadata& out);

	// Build the message representative M' for the given algorithm, context and
	// message. Returns false on error (e.g. context too long or hashing fails).
	bool buildMessageRepresentative(const Metadata& meta, const ByteString& context,
					const ByteString& message, ByteString& mPrime);

	// Convert a raw fixed-length ECDSA signature (r || s, each ecFieldLen bytes)
	// into a DER encoded Ecdsa-Sig-Value.
	ByteString ecdsaRawToDer(const ByteString& raw, size_t ecFieldLen);

	// Convert a DER encoded Ecdsa-Sig-Value into the raw fixed-length r || s
	// representation (2 * ecFieldLen bytes). Returns false on malformed input.
	bool ecdsaDerToRaw(const ByteString& der, size_t ecFieldLen, ByteString& raw);

	// Encode an EC private scalar as an RFC 5915 ECPrivateKey (including the
	// [0] namedCurve parameters), which is the traditional private key encoding
	// used by composite ML-DSA.
	ByteString encodeEcPrivateKey(const ByteString& d, const ByteString& curveOID);

	// Decode an RFC 5915 ECPrivateKey, extracting the private scalar d.
	bool decodeEcPrivateKey(const ByteString& der, ByteString& d);
}

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_COMPOSITEMLDSAUTIL_H
