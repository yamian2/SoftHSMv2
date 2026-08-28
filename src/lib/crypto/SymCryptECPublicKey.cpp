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
 SymCryptECPublicKey.cpp

 SymCrypt Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "SymCryptECPublicKey.h"
#include "SymCryptECUtil.h"
#include "DerUtil.h"
#include <string.h>

// Constructors
SymCryptECPublicKey::SymCryptECPublicKey()
{
	curve = NULL;
	eckey = NULL;
}

// Destructor
SymCryptECPublicKey::~SymCryptECPublicKey()
{
	freeSymCryptKey();
}

// The type
/*static*/ const char* SymCryptECPublicKey::type = "SymCrypt EC Public Key";

// Check if the key is of the given type
bool SymCryptECPublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Get the base point order length
unsigned long SymCryptECPublicKey::getOrderLength() const
{
	PSYMCRYPT_ECURVE c = ensureCurve();

	if (c == NULL)
	{
		return 0;
	}

	return (unsigned long)((SymCryptEcurveBitsizeofGroupOrder(c) + 7) / 8);
}

// Setters for the EC public key components
void SymCryptECPublicKey::setEC(const ByteString& inEC)
{
	ECPublicKey::setEC(inEC);

	freeSymCryptKey();
}

void SymCryptECPublicKey::setQ(const ByteString& inQ)
{
	ECPublicKey::setQ(inQ);

	freeSymCryptKey();
}

// Ensure the SymCrypt curve object has been built from the stored EC params
PSYMCRYPT_ECURVE SymCryptECPublicKey::ensureCurve() const
{
	if (curve == NULL && ec.size() != 0)
	{
		curve = SymEC::curveFromParams(ec);
	}

	return curve;
}

// Release the cached SymCrypt objects
void SymCryptECPublicKey::freeSymCryptKey()
{
	if (eckey != NULL)
	{
		SymCryptEckeyFree(eckey);
		eckey = NULL;
	}

	if (curve != NULL)
	{
		SymCryptEcurveFree(curve);
		curve = NULL;
	}
}

// Retrieve the SymCrypt representation of the key
PSYMCRYPT_ECKEY SymCryptECPublicKey::getSymCryptKey()
{
	if (eckey == NULL)
	{
		createSymCryptKey();
	}

	return eckey;
}

// Build the SymCrypt key representation from the stored components
void SymCryptECPublicKey::createSymCryptKey()
{
	if (eckey != NULL)
	{
		return;
	}

	if (ec.size() == 0 || q.size() == 0)
	{
		ERROR_MSG("Cannot build SymCrypt EC public key: missing curve or public point");
		return;
	}

	PSYMCRYPT_ECURVE c = ensureCurve();
	if (c == NULL)
	{
		return;
	}

	// The stored public point is a DER OCTET STRING wrapping an uncompressed
	// point 0x04 || X || Y. Strip the OCTET STRING and the leading 0x04 to get
	// the raw X || Y buffer that SymCrypt expects in XY format.
	ByteString point = DERUTIL::octet2Raw(q);
	if (point.size() < 1 || point[0] != 0x04)
	{
		ERROR_MSG("Unsupported EC public point encoding (only uncompressed points are supported)");
		return;
	}
	ByteString xy = point.substr(1);

	PSYMCRYPT_ECKEY key = SymCryptEckeyAllocate(c);
	if (key == NULL)
	{
		ERROR_MSG("Failed to allocate SymCrypt EC key");
		return;
	}

	SIZE_T cbPublicKey = SymCryptEckeySizeofPublicKey(key, SYMCRYPT_ECPOINT_FORMAT_XY);
	if (xy.size() != cbPublicKey)
	{
		ERROR_MSG("EC public point has unexpected length");
		SymCryptEckeyFree(key);
		return;
	}

	SYMCRYPT_ERROR scError = SymCryptEckeySetValue(
		NULL, 0,
		xy.const_byte_str(), cbPublicKey,
		SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
		SYMCRYPT_ECPOINT_FORMAT_XY,
		SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH,
		key);
	if (scError != SYMCRYPT_NO_ERROR)
	{
		ERROR_MSG("SymCryptEckeySetValue (public) failed (0x%08X)", (unsigned)scError);
		SymCryptEckeyFree(key);
		return;
	}

	eckey = key;
}

#endif // WITH_ECC
