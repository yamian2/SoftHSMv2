/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 SymCryptMLKEMUtil.h

 Small helpers shared by the SymCrypt ML-KEM classes: mapping between the
 SoftHSM parameter-set constants and the SymCrypt ML-KEM parameter enum.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTMLKEMUTIL_H
#define _SOFTHSM_V2_SYMCRYPTMLKEMUTIL_H

#include "config.h"
#ifdef WITH_ML_KEM
#include "MLKEMParameters.h"
#include <symcrypt.h>

namespace SymMLKEM
{
	// Map a SoftHSM/PKCS#11 ML-KEM parameter set to the SymCrypt parameter enum.
	// Returns true on success and stores the result in out.
	static inline bool paramsFromParameterSet(unsigned long parameterSet, SYMCRYPT_MLKEM_PARAMS& out)
	{
		switch (parameterSet)
		{
			case MLKEMParameters::ML_KEM_512_PARAMETER_SET:
				out = SYMCRYPT_MLKEM_PARAMS_MLKEM512;
				return true;
			case MLKEMParameters::ML_KEM_768_PARAMETER_SET:
				out = SYMCRYPT_MLKEM_PARAMS_MLKEM768;
				return true;
			case MLKEMParameters::ML_KEM_1024_PARAMETER_SET:
				out = SYMCRYPT_MLKEM_PARAMS_MLKEM1024;
				return true;
			default:
				return false;
		}
	}
}

#endif // WITH_ML_KEM
#endif // !_SOFTHSM_V2_SYMCRYPTMLKEMUTIL_H
