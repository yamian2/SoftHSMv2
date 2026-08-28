/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSAParameters.cpp

 Composite ML-DSA parameters (only used for key generation)
 *****************************************************************************/

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "log.h"
#include "CompositeMLDSAParameters.h"
#include "CompositeMLDSAUtil.h"
#include <string.h>

// The type
/*static*/ const char* CompositeMLDSAParameters::type = "Composite ML-DSA parameters";

unsigned long CompositeMLDSAParameters::getAlgorithm() const
{
	return algorithm;
}

void CompositeMLDSAParameters::setAlgorithm(const unsigned long inAlgorithm)
{
	algorithm = inAlgorithm;
}

bool CompositeMLDSAParameters::areOfType(const char* inType)
{
	if (inType == NULL)
	{
		return false;
	}
	return (strcmp(type, inType) == 0);
}

ByteString CompositeMLDSAParameters::serialise() const
{
	return ByteString(getAlgorithm());
}

bool CompositeMLDSAParameters::deserialise(ByteString& serialised)
{
	if (serialised.size() != 8)
	{
		return false;
	}

	unsigned long value = serialised.long_val();

	CompositeMLDSA::Metadata meta;
	if (!CompositeMLDSA::metadataFor(value, meta))
	{
		return false;
	}

	setAlgorithm(value);

	return true;
}

#endif // WITH_ML_DSA && WITH_ECC
