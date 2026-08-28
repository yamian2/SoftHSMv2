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
 SymCryptDigests.cpp

 SymCrypt digest implementations
 *****************************************************************************/

#include "config.h"
#include "SymCryptDigests.h"
#include "SymCryptImports.h"

int SymCryptMD5::getHashSize() { return 16; }
PCSYMCRYPT_HASH SymCryptMD5::getHash() const { return SymImports::md5(); }

int SymCryptSHA1::getHashSize() { return 20; }
PCSYMCRYPT_HASH SymCryptSHA1::getHash() const { return SymImports::sha1(); }

int SymCryptSHA224::getHashSize() { return 28; }
PCSYMCRYPT_HASH SymCryptSHA224::getHash() const { return SymImports::sha224(); }

int SymCryptSHA256::getHashSize() { return 32; }
PCSYMCRYPT_HASH SymCryptSHA256::getHash() const { return SymImports::sha256(); }

int SymCryptSHA384::getHashSize() { return 48; }
PCSYMCRYPT_HASH SymCryptSHA384::getHash() const { return SymImports::sha384(); }

int SymCryptSHA512::getHashSize() { return 64; }
PCSYMCRYPT_HASH SymCryptSHA512::getHash() const { return SymImports::sha512(); }
