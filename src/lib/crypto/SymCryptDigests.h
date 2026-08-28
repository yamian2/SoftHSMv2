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
 SymCryptDigests.h

 SymCrypt digest implementations (MD5, SHA-1, SHA-224, SHA-256, SHA-384,
 SHA-512). Each class merely binds the shared SymCryptHashAlgorithm base to a
 SymCrypt hash object and reports its digest length.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SYMCRYPTDIGESTS_H
#define _SOFTHSM_V2_SYMCRYPTDIGESTS_H

#include "config.h"
#include "SymCryptHashAlgorithm.h"

class SymCryptMD5 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

class SymCryptSHA1 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

class SymCryptSHA224 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

class SymCryptSHA256 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

class SymCryptSHA384 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

class SymCryptSHA512 : public SymCryptHashAlgorithm
{
public:
	virtual int getHashSize();
protected:
	virtual PCSYMCRYPT_HASH getHash() const;
};

#endif // !_SOFTHSM_V2_SYMCRYPTDIGESTS_H
