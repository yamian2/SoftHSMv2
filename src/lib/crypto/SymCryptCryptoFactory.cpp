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
 SymCryptCryptoFactory.cpp

 This is a SymCrypt based cryptographic algorithm factory
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "SymCryptCryptoFactory.h"
#include "SymCryptRNG.h"
#include "SymCryptDigests.h"
#include "SymCryptRSA.h"
#ifdef WITH_ECC
#include "SymCryptECDSA.h"
#include "SymCryptECDH.h"
#endif
#ifdef WITH_ML_DSA
#include "SymCryptMLDSA.h"
#endif
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "SymCryptCompositeMLDSA.h"
#endif
#include <symcrypt.h>

// Constructor
SymCryptCryptoFactory::SymCryptCryptoFactory()
{
	// Initialise the SymCrypt module. This must be called once before any other
	// SymCrypt API is used when linking against the SymCrypt shared library.
	SYMCRYPT_MODULE_INIT();

	// Create the one-and-only RNG
	rng = new SymCryptRNG();
}

// Destructor
SymCryptCryptoFactory::~SymCryptCryptoFactory()
{
	// Destroy the RNG
	delete rng;
}

// Return the one-and-only instance
SymCryptCryptoFactory* SymCryptCryptoFactory::i()
{
	if (!instance.get())
	{
		instance.reset(new SymCryptCryptoFactory());
	}

	return instance.get();
}

// This will destroy the one-and-only instance.
void SymCryptCryptoFactory::reset()
{
	instance.reset();
}

// Create a concrete instance of a symmetric algorithm
SymmetricAlgorithm* SymCryptCryptoFactory::getSymmetricAlgorithm(SymAlgo::Type algorithm)
{
	// Symmetric algorithms are not yet implemented for the SymCrypt backend
	ERROR_MSG("Unsupported algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of an asymmetric algorithm
AsymmetricAlgorithm* SymCryptCryptoFactory::getAsymmetricAlgorithm(AsymAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case AsymAlgo::RSA:
			return new SymCryptRSA();
#ifdef WITH_ECC
		case AsymAlgo::ECDSA:
			return new SymCryptECDSA();
		case AsymAlgo::ECDH:
			return new SymCryptECDH();
#endif
#ifdef WITH_ML_DSA
		case AsymAlgo::MLDSA:
			return new SymCryptMLDSA();
#endif
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
		case AsymAlgo::COMPOSITE_MLDSA:
			return new SymCryptCompositeMLDSA();
#endif
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unsupported algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a hash algorithm
HashAlgorithm* SymCryptCryptoFactory::getHashAlgorithm(HashAlgo::Type algorithm)
{
	switch (algorithm)
	{
		case HashAlgo::MD5:
			return new SymCryptMD5();
		case HashAlgo::SHA1:
			return new SymCryptSHA1();
		case HashAlgo::SHA224:
			return new SymCryptSHA224();
		case HashAlgo::SHA256:
			return new SymCryptSHA256();
		case HashAlgo::SHA384:
			return new SymCryptSHA384();
		case HashAlgo::SHA512:
			return new SymCryptSHA512();
		default:
			break;
	}

	// No algorithm implementation is available
	ERROR_MSG("Unsupported algorithm '%i'", algorithm);
	return NULL;
}

// Create a concrete instance of a MAC algorithm
MacAlgorithm* SymCryptCryptoFactory::getMacAlgorithm(MacAlgo::Type algorithm)
{
	// MAC algorithms are not yet implemented for the SymCrypt backend
	ERROR_MSG("Unsupported algorithm '%i'", algorithm);
	return NULL;
}

// Get the global RNG (may be an unique RNG per thread)
RNG* SymCryptCryptoFactory::getRNG(RNGImpl::Type name /* = RNGImpl::Default */)
{
	if (name == RNGImpl::Default)
	{
		return rng;
	}
	else
	{
		// No RNG implementation is available
		ERROR_MSG("Unknown RNG '%i'", name);
		return NULL;
	}
}
