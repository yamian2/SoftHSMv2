/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAPrivateKey.h

 SymCrypt composite ML-DSA private key class. The key value is the raw
 concatenation of the 32-byte ML-DSA seed and the traditional (ECDSA) private
 key (an RFC 5915 ECPrivateKey), as specified by
 draft-ietf-lamps-pq-composite-sigs.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPRIVATEKEY_H
#define _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPRIVATEKEY_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "PrivateKey.h"
#include "ByteString.h"

class SymCryptCompositeMLDSAPrivateKey : public PrivateKey
{
public:
	SymCryptCompositeMLDSAPrivateKey() : algorithm(0) {}

	// The type
	static const char* type;

	// Check if the key is of the given type
	virtual bool isOfType(const char* inType);

	// Get the bit length
	virtual unsigned long getBitLength() const;

	// Get the (maximum) signature length
	virtual unsigned long getOutputLength() const;

	// Composite algorithm identifier
	virtual unsigned long getAlgorithm() const;
	virtual void setAlgorithm(const unsigned long inAlgorithm);

	// The composite private key value (mldsaSeed || tradSK)
	virtual const ByteString& getValue() const;
	virtual void setValue(const ByteString& inValue);

	// Encode into PKCS#8 DER
	virtual ByteString PKCS8Encode();

	// Decode from PKCS#8 BER
	virtual bool PKCS8Decode(const ByteString& ber);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	ByteString value;
	unsigned long algorithm;
};

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPRIVATEKEY_H
