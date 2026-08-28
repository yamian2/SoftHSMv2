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
 SymCryptImports.cpp

 Accessors for SymCrypt global data symbols exported by the SymCrypt DLL. See
 SymCryptImports.h for the rationale. Each symbol is reached through its
 auto-generated __imp_ import-address-table entry, whose value is the address
 of the object in the DLL.
 *****************************************************************************/

#include "config.h"
#include "SymCryptImports.h"

// The __imp_ entries hold the address of the corresponding DLL data symbol.
// For a scalar (const PCSYMCRYPT_HASH), the import points at the pointer value.
// For an array (const SYMCRYPT_OID[]), the import points at the first element.
extern "C"
{
	extern const PCSYMCRYPT_HASH* __imp_SymCryptMd5Algorithm;
	extern const PCSYMCRYPT_HASH* __imp_SymCryptSha1Algorithm;
	extern const PCSYMCRYPT_HASH* __imp_SymCryptSha224Algorithm;
	extern const PCSYMCRYPT_HASH* __imp_SymCryptSha256Algorithm;
	extern const PCSYMCRYPT_HASH* __imp_SymCryptSha384Algorithm;
	extern const PCSYMCRYPT_HASH* __imp_SymCryptSha512Algorithm;

	extern const SYMCRYPT_OID* __imp_SymCryptMd5OidList;
	extern const SYMCRYPT_OID* __imp_SymCryptSha1OidList;
	extern const SYMCRYPT_OID* __imp_SymCryptSha224OidList;
	extern const SYMCRYPT_OID* __imp_SymCryptSha256OidList;
	extern const SYMCRYPT_OID* __imp_SymCryptSha384OidList;
	extern const SYMCRYPT_OID* __imp_SymCryptSha512OidList;
}

namespace SymImports
{
	PCSYMCRYPT_HASH md5()    { return *__imp_SymCryptMd5Algorithm; }
	PCSYMCRYPT_HASH sha1()   { return *__imp_SymCryptSha1Algorithm; }
	PCSYMCRYPT_HASH sha224() { return *__imp_SymCryptSha224Algorithm; }
	PCSYMCRYPT_HASH sha256() { return *__imp_SymCryptSha256Algorithm; }
	PCSYMCRYPT_HASH sha384() { return *__imp_SymCryptSha384Algorithm; }
	PCSYMCRYPT_HASH sha512() { return *__imp_SymCryptSha512Algorithm; }

	PCSYMCRYPT_OID md5Oids()    { return __imp_SymCryptMd5OidList; }
	PCSYMCRYPT_OID sha1Oids()   { return __imp_SymCryptSha1OidList; }
	PCSYMCRYPT_OID sha224Oids() { return __imp_SymCryptSha224OidList; }
	PCSYMCRYPT_OID sha256Oids() { return __imp_SymCryptSha256OidList; }
	PCSYMCRYPT_OID sha384Oids() { return __imp_SymCryptSha384OidList; }
	PCSYMCRYPT_OID sha512Oids() { return __imp_SymCryptSha512OidList; }
}
