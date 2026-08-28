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
 SymCryptECUtil.h

 SymCrypt elliptic-curve helpers shared by the SymCrypt EC crypto classes.
 SoftHSM stores an EC domain as the DER encoding of an ECParameters value; for
 the named curves supported by SymCrypt this is simply the curve OID. These
 helpers translate that encoding into an allocated SymCrypt curve object and
 convert between SoftHSM's public point representation (a DER OCTET STRING that
 wraps an uncompressed 0x04||X||Y point) and SymCrypt's raw XY format.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTECUTIL_H
#define _SOFTHSM_V2_SYMCRYPTECUTIL_H

#include "config.h"
#ifdef WITH_ECC
#include "ByteString.h"
#include <symcrypt.h>

namespace SymEC
{
	// Allocate a SymCrypt curve object for the given DER-encoded ECParameters
	// (curve OID). Returns NULL if the curve is not supported by SymCrypt or if
	// allocation fails. The caller owns the returned object and must release it
	// with SymCryptEcurveFree().
	PSYMCRYPT_ECURVE curveFromParams(const ByteString& ec);
}

#endif // WITH_ECC
#endif // !_SOFTHSM_V2_SYMCRYPTECUTIL_H
