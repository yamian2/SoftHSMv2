/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSAParameters.h

 Composite ML-DSA parameters (only used for key generation). The single
 parameter is the composite algorithm identifier (see CompositeMLDSAUtil.h).
 *****************************************************************************/

#ifndef _SOFTHSM_V2_COMPOSITEMLDSAPARAMETERS_H
#define _SOFTHSM_V2_COMPOSITEMLDSAPARAMETERS_H

#include "config.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "ByteString.h"
#include "AsymmetricParameters.h"

class CompositeMLDSAParameters : public AsymmetricParameters
{
public:
	CompositeMLDSAParameters() : algorithm(0) {}

	// The type
	static const char* type;

	// Get/set the composite algorithm identifier
	virtual unsigned long getAlgorithm() const;
	virtual void setAlgorithm(const unsigned long inAlgorithm);

	// Are the parameters of the given type?
	virtual bool areOfType(const char* inType);

	// Serialisation
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);

private:
	unsigned long algorithm;
};

#endif // WITH_ML_DSA && WITH_ECC
#endif // !_SOFTHSM_V2_COMPOSITEMLDSAPARAMETERS_H
