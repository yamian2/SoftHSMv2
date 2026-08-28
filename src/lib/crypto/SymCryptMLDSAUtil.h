/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLDSAUtil.h

 Small helpers shared by the SymCrypt ML-DSA classes: mapping between the
 SoftHSM parameter-set constants and the SymCrypt ML-DSA parameter enum.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLDSAUTIL_H
#define _SOFTHSM_V2_SYMCRYPTMLDSAUTIL_H

#include "config.h"
#ifdef WITH_ML_DSA
#include "MLDSAParameters.h"
#include <symcrypt.h>

namespace SymMLDSA
{
	// Map a SoftHSM/PKCS#11 ML-DSA parameter set to the SymCrypt parameter enum.
	// Returns true on success and stores the result in out.
	static inline bool paramsFromParameterSet(unsigned long parameterSet, SYMCRYPT_MLDSA_PARAMS& out)
	{
		switch (parameterSet)
		{
			case MLDSAParameters::ML_DSA_44_PARAMETER_SET:
				out = SYMCRYPT_MLDSA_PARAMS_MLDSA44;
				return true;
			case MLDSAParameters::ML_DSA_65_PARAMETER_SET:
				out = SYMCRYPT_MLDSA_PARAMS_MLDSA65;
				return true;
			case MLDSAParameters::ML_DSA_87_PARAMETER_SET:
				out = SYMCRYPT_MLDSA_PARAMS_MLDSA87;
				return true;
			default:
				return false;
		}
	}
}

#endif // WITH_ML_DSA
#endif // !_SOFTHSM_V2_SYMCRYPTMLDSAUTIL_H
