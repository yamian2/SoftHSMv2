/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAPublicKey.h

 SymCrypt composite ML-DSA public key class. The key value is the raw
 concatenation of the ML-DSA public key and the traditional (ECDSA) public
 key, as specified by draft-ietf-lamps-pq-composite-sigs.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPUBLICKEY_H
#define _SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPUBLICKEY_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "PublicKey.h"
#include "ByteString.h"

class SymCryptCompositeMLDSAPublicKey : public PublicKey
{
public:
	SymCryptCompositeMLDSAPublicKey() : algorithm(0) {}

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

	// The composite public key value (mldsaPK || tradPK)
	virtual const ByteString& getValue() const;
	virtual void setValue(const ByteString& inValue);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

protected:
	ByteString value;
	unsigned long algorithm;
};

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_SYMCRYPTCOMPOSITEMLDSAPUBLICKEY_H
