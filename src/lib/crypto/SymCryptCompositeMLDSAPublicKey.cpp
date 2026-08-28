/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptCompositeMLDSAPublicKey.cpp

 SymCrypt composite ML-DSA public key class
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "log.h"
#include "SymCryptCompositeMLDSAPublicKey.h"
#include "CompositeMLDSAUtil.h"
#include <string.h>

// The type
/*static*/ const char* SymCryptCompositeMLDSAPublicKey::type = "SymCrypt Composite ML-DSA Public Key";

bool SymCryptCompositeMLDSAPublicKey::isOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return !strcmp(type, inType);
}

unsigned long SymCryptCompositeMLDSAPublicKey::getBitLength() const
{
	return value.bits();
}

unsigned long SymCryptCompositeMLDSAPublicKey::getOutputLength() const
{
	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(algorithm, meta))
	{
		return 0;
	}

	// ML-DSA signature (fixed) + DER Ecdsa-Sig-Value (upper bound). Each INTEGER
	// can carry up to ecFieldLen + 1 magnitude bytes plus 2 bytes tag/length; the
	// enclosing SEQUENCE adds up to 4 bytes of tag/length.
	return (unsigned long)(meta.mldsaSigLen + 2 * (meta.ecFieldLen + 3) + 4);
}

unsigned long SymCryptCompositeMLDSAPublicKey::getAlgorithm() const
{
	return algorithm;
}

void SymCryptCompositeMLDSAPublicKey::setAlgorithm(const unsigned long inAlgorithm)
{
	algorithm = inAlgorithm;
}

const ByteString& SymCryptCompositeMLDSAPublicKey::getValue() const
{
	return value;
}

void SymCryptCompositeMLDSAPublicKey::setValue(const ByteString& inValue)
{
	value = inValue;
}

ByteString SymCryptCompositeMLDSAPublicKey::serialise() const
{
	return value.serialise() +
	       ByteString(algorithm).serialise();
}

bool SymCryptCompositeMLDSAPublicKey::deserialise(ByteString& serialised)
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
