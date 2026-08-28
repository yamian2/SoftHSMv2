/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 SymCryptECUtil.cpp

 SymCrypt elliptic-curve helpers shared by the SymCrypt EC crypto classes.
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "SymCryptECUtil.h"
#include "log.h"
#include <cstring>

namespace
{
	// The DER encoding of the ECParameters that SoftHSM stores for a named
	// curve is just the object identifier of that curve. Match the raw DER
	// bytes (including the 0x06 OID tag and length) against the NIST curves
	// that SymCrypt supports and translate to a SymCrypt curve ID.
	struct CurveMapping
	{
		SYMCRYPT_ECURVE_ID	id;
		size_t			derLen;
		unsigned char		der[16];
	};

	const CurveMapping g_curveMappings[] =
	{
		// prime192v1 / secp192r1 :: 1.2.840.10045.3.1.1
		{ SYMCRYPT_ECURVE_ID_NIST_P192, 10, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 } },
		// secp224r1 :: 1.3.132.0.33
		{ SYMCRYPT_ECURVE_ID_NIST_P224,  7, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 } },
		// prime256v1 / secp256r1 :: 1.2.840.10045.3.1.7
		{ SYMCRYPT_ECURVE_ID_NIST_P256, 10, { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 } },
		// secp384r1 :: 1.3.132.0.34
		{ SYMCRYPT_ECURVE_ID_NIST_P384,  7, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 } },
		// secp521r1 :: 1.3.132.0.35
		{ SYMCRYPT_ECURVE_ID_NIST_P521,  7, { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 } }
	};
}

PSYMCRYPT_ECURVE SymEC::curveFromParams(const ByteString& ec)
{
	SYMCRYPT_ECURVE_ID curveId = SYMCRYPT_ECURVE_ID_NULL;

	for (size_t i = 0; i < sizeof(g_curveMappings) / sizeof(g_curveMappings[0]); i++)
	{
		const CurveMapping& m = g_curveMappings[i];

		if (ec.size() == m.derLen && memcmp(ec.const_byte_str(), m.der, m.derLen) == 0)
		{
			curveId = m.id;
			break;
		}
	}

	if (curveId == SYMCRYPT_ECURVE_ID_NULL)
	{
		ERROR_MSG("Unsupported or unrecognised EC curve parameters");

		return NULL;
	}

	PCSYMCRYPT_ECURVE_PARAMS params = SymCryptGetEcurveParams(curveId);

	if (params == NULL)
	{
		ERROR_MSG("SymCryptGetEcurveParams returned no parameters for curve id %d", (int) curveId);

		return NULL;
	}

	PSYMCRYPT_ECURVE curve = SymCryptEcurveAllocate(params, 0);

	if (curve == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt curve");

		return NULL;
	}

	return curve;
}

#endif // WITH_ECC
