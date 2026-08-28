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
 SymCryptImports.h

 SymCrypt exports a number of global data symbols (the generic hash algorithm
 objects and the pre-computed PKCS#1 DigestInfo OID lists). When SymCrypt is
 consumed as a DLL through its import library, these data symbols are only
 reachable through their auto-generated __imp_ import-address-table entries;
 unlike functions, the linker cannot synthesise a thunk for imported data that
 is referenced without __declspec(dllimport), and the SymCrypt headers do not
 decorate them. This header exposes thin accessors that resolve the data via
 the __imp_ pointers so the rest of the backend can use the objects normally.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTIMPORTS_H
#define _SOFTHSM_V2_SYMCRYPTIMPORTS_H

#include <symcrypt.h>

namespace SymImports
{
	// Generic hash algorithm objects
	PCSYMCRYPT_HASH md5();
	PCSYMCRYPT_HASH sha1();
	PCSYMCRYPT_HASH sha224();
	PCSYMCRYPT_HASH sha256();
	PCSYMCRYPT_HASH sha384();
	PCSYMCRYPT_HASH sha512();

	// Pre-computed PKCS#1 DigestInfo OID lists
	PCSYMCRYPT_OID md5Oids();
	PCSYMCRYPT_OID sha1Oids();
	PCSYMCRYPT_OID sha224Oids();
	PCSYMCRYPT_OID sha256Oids();
	PCSYMCRYPT_OID sha384Oids();
	PCSYMCRYPT_OID sha512Oids();
}

#endif // !_SOFTHSM_V2_SYMCRYPTIMPORTS_H
