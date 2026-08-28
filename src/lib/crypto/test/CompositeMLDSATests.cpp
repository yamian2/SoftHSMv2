/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSATests.cpp

 Contains test cases to test the composite ML-DSA class
 *****************************************************************************/

#include <stdlib.h>
#include <vector>
#include <cppunit/extensions/HelperMacros.h>
#include "CompositeMLDSATests.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "AsymmetricKeyPair.h"
#include "AsymmetricAlgorithm.h"
#if defined(WITH_ML_DSA) && defined(WITH_ECC)
#include "MLDSAMechanismParam.h"
#include "CompositeMLDSAUtil.h"
#include "CompositeMLDSAParameters.h"
#include "SymCryptCompositeMLDSAPublicKey.h"
#include "SymCryptCompositeMLDSAPrivateKey.h"

CPPUNIT_TEST_SUITE_REGISTRATION(CompositeMLDSATests);

static const std::vector<unsigned long> allAlgorithms = {
	CompositeMLDSA::Algorithm::MLDSA44_ECDSA_P256_SHA256,
	CompositeMLDSA::Algorithm::MLDSA65_ECDSA_P256_SHA512,
	CompositeMLDSA::Algorithm::MLDSA65_ECDSA_P384_SHA512,
	CompositeMLDSA::Algorithm::MLDSA87_ECDSA_P384_SHA512,
	CompositeMLDSA::Algorithm::MLDSA87_ECDSA_P521_SHA512
};

void CompositeMLDSATests::setUp()
{
	composite = CryptoFactory::i()->getAsymmetricAlgorithm(AsymAlgo::COMPOSITE_MLDSA);

	CPPUNIT_ASSERT(composite != NULL);
}

void CompositeMLDSATests::tearDown()
{
	if (composite != NULL)
	{
		CryptoFactory::i()->recycleAsymmetricAlgorithm(composite);
	}

	fflush(stdout);
}

void CompositeMLDSATests::testKeyGeneration()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

		SymCryptCompositeMLDSAPublicKey* pub = (SymCryptCompositeMLDSAPublicKey*)kp->getPublicKey();
		SymCryptCompositeMLDSAPrivateKey* priv = (SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey();

		CPPUNIT_ASSERT(pub->getAlgorithm() == algorithm);
		CPPUNIT_ASSERT(priv->getAlgorithm() == algorithm);

		// Verify the composite public key length matches mldsaPubLen + uncompressed EC point
		CompositeMLDSA::Metadata meta;
		CPPUNIT_ASSERT(CompositeMLDSA::metadataFor(algorithm, meta));
		CPPUNIT_ASSERT(pub->getValue().size() == meta.mldsaPubLen + 1 + 2 * meta.ecFieldLen);

		composite->recycleParameters(p);
		composite->recycleKeyPair(kp);
	}
}

void CompositeMLDSATests::testSerialisation()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		// Serialise/deserialise the parameters
		ByteString serialisedParams = p->serialise();
		AsymmetricParameters* dParams;
		CPPUNIT_ASSERT(composite->reconstructParameters(&dParams, serialisedParams));
		CPPUNIT_ASSERT(dParams->areOfType(CompositeMLDSAParameters::type));
		CPPUNIT_ASSERT(((CompositeMLDSAParameters*)dParams)->getAlgorithm() == algorithm);

		// Generate and serialise a key-pair
		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, dParams));

		ByteString serialisedKP = kp->serialise();

		AsymmetricKeyPair* dKP;
		CPPUNIT_ASSERT(composite->reconstructKeyPair(&dKP, serialisedKP));

		SymCryptCompositeMLDSAPrivateKey* privKey = (SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey();
		SymCryptCompositeMLDSAPublicKey* pubKey = (SymCryptCompositeMLDSAPublicKey*)kp->getPublicKey();
		SymCryptCompositeMLDSAPrivateKey* dPrivKey = (SymCryptCompositeMLDSAPrivateKey*)dKP->getPrivateKey();
		SymCryptCompositeMLDSAPublicKey* dPubKey = (SymCryptCompositeMLDSAPublicKey*)dKP->getPublicKey();

		CPPUNIT_ASSERT(privKey->getAlgorithm() == dPrivKey->getAlgorithm());
		CPPUNIT_ASSERT(privKey->getValue() == dPrivKey->getValue());
		CPPUNIT_ASSERT(pubKey->getAlgorithm() == dPubKey->getAlgorithm());
		CPPUNIT_ASSERT(pubKey->getValue() == dPubKey->getValue());

		composite->recycleParameters(p);
		composite->recycleParameters(dParams);
		composite->recycleKeyPair(kp);
		composite->recycleKeyPair(dKP);
	}
}

void CompositeMLDSATests::testPKCS8()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));
		CPPUNIT_ASSERT(kp != NULL);

		SymCryptCompositeMLDSAPrivateKey* priv = (SymCryptCompositeMLDSAPrivateKey*)kp->getPrivateKey();
		CPPUNIT_ASSERT(priv != NULL);

		// Encode and decode the private key
		ByteString pkcs8 = priv->PKCS8Encode();
		CPPUNIT_ASSERT(pkcs8.size() != 0);

		SymCryptCompositeMLDSAPrivateKey* dPriv = (SymCryptCompositeMLDSAPrivateKey*)composite->newPrivateKey();
		CPPUNIT_ASSERT(dPriv != NULL);

		CPPUNIT_ASSERT(dPriv->PKCS8Decode(pkcs8));

		CPPUNIT_ASSERT(priv->getAlgorithm() == dPriv->getAlgorithm());
		CPPUNIT_ASSERT(priv->getValue() == dPriv->getValue());

		composite->recycleParameters(p);
		composite->recyclePrivateKey(dPriv);
		composite->recycleKeyPair(kp);
	}
}

void CompositeMLDSATests::testSigningVerifying()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		ByteString dataToSign;
		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 567));

		ByteString sig;
		CPPUNIT_ASSERT(composite->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA));

		CPPUNIT_ASSERT(composite->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA));

		// A different message must not verify
		ByteString otherData;
		CPPUNIT_ASSERT(rng->generateRandom(otherData, 567));
		CPPUNIT_ASSERT(!composite->verify(kp->getPublicKey(), otherData, sig, AsymMech::COMPOSITE_MLDSA));

		composite->recycleKeyPair(kp);
		composite->recycleParameters(p);
	}
}

void CompositeMLDSATests::testSigningVerifyingWithContext()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		ByteString dataToSign;
		CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 421));

		const std::string contextStr("composite-context");
		const ByteString contextBS((const unsigned char*)contextStr.data(), contextStr.size());
		MLDSAMechanismParam context(Hedge::Type::HEDGE_PREFERRED, contextBS);

		ByteString sig;
		CPPUNIT_ASSERT(composite->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA, &context));

		// Verifying with the same context succeeds
		CPPUNIT_ASSERT(composite->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA, &context));

		// Verifying without the context (or a different one) fails
		CPPUNIT_ASSERT(!composite->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA));

		composite->recycleKeyPair(kp);
		composite->recycleParameters(p);
	}
}

void CompositeMLDSATests::testSigningMultiPartVerifyingMultiPart()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		ByteString part1, part2;
		CPPUNIT_ASSERT(rng->generateRandom(part1, 567));
		CPPUNIT_ASSERT(rng->generateRandom(part2, 890));
		ByteString all = part1 + part2;

		ByteString sigMultiPart;
		CPPUNIT_ASSERT(composite->signInit(kp->getPrivateKey(), AsymMech::COMPOSITE_MLDSA));
		CPPUNIT_ASSERT(composite->signUpdate(part1));
		CPPUNIT_ASSERT(composite->signUpdate(part2));
		CPPUNIT_ASSERT(composite->signFinal(sigMultiPart));

		// The multi-part signature verifies against the concatenated single-shot data
		CPPUNIT_ASSERT(composite->verify(kp->getPublicKey(), all, sigMultiPart, AsymMech::COMPOSITE_MLDSA));

		// And via the multi-part verify path
		CPPUNIT_ASSERT(composite->verifyInit(kp->getPublicKey(), AsymMech::COMPOSITE_MLDSA));
		CPPUNIT_ASSERT(composite->verifyUpdate(part1));
		CPPUNIT_ASSERT(composite->verifyUpdate(part2));
		CPPUNIT_ASSERT(composite->verifyFinal(sigMultiPart));

		composite->recycleKeyPair(kp);
		composite->recycleParameters(p);
	}
}

void CompositeMLDSATests::testSigningMultiPartVerifyingMultiPartWithContext()
{
	for (const unsigned long algorithm : allAlgorithms)
	{
		CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
		p->setAlgorithm(algorithm);

		AsymmetricKeyPair* kp;
		CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

		RNG* rng = CryptoFactory::i()->getRNG();
		CPPUNIT_ASSERT(rng != NULL);

		ByteString part1, part2;
		CPPUNIT_ASSERT(rng->generateRandom(part1, 321));
		CPPUNIT_ASSERT(rng->generateRandom(part2, 654));

		const std::string contextStr("multipart-context");
		const ByteString contextBS((const unsigned char*)contextStr.data(), contextStr.size());
		MLDSAMechanismParam context(Hedge::Type::HEDGE_PREFERRED, contextBS);

		ByteString sigMultiPart;
		CPPUNIT_ASSERT(composite->signInit(kp->getPrivateKey(), AsymMech::COMPOSITE_MLDSA, &context));
		CPPUNIT_ASSERT(composite->signUpdate(part1));
		CPPUNIT_ASSERT(composite->signUpdate(part2));
		CPPUNIT_ASSERT(composite->signFinal(sigMultiPart));

		CPPUNIT_ASSERT(composite->verifyInit(kp->getPublicKey(), AsymMech::COMPOSITE_MLDSA, &context));
		CPPUNIT_ASSERT(composite->verifyUpdate(part1));
		CPPUNIT_ASSERT(composite->verifyUpdate(part2));
		CPPUNIT_ASSERT(composite->verifyFinal(sigMultiPart));

		composite->recycleKeyPair(kp);
		composite->recycleParameters(p);
	}
}

void CompositeMLDSATests::testVerifyingTamperedSignature()
{
	// Use a single algorithm; the point is to exercise the AND of both components
	CompositeMLDSAParameters* p = new CompositeMLDSAParameters();
	p->setAlgorithm(CompositeMLDSA::Algorithm::MLDSA65_ECDSA_P256_SHA512);

	AsymmetricKeyPair* kp;
	CPPUNIT_ASSERT(composite->generateKeyPair(&kp, p));

	RNG* rng = CryptoFactory::i()->getRNG();
	CPPUNIT_ASSERT(rng != NULL);

	ByteString dataToSign;
	CPPUNIT_ASSERT(rng->generateRandom(dataToSign, 200));

	ByteString sig;
	CPPUNIT_ASSERT(composite->sign(kp->getPrivateKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA));
	CPPUNIT_ASSERT(composite->verify(kp->getPublicKey(), dataToSign, sig, AsymMech::COMPOSITE_MLDSA));

	CompositeMLDSA::Metadata meta;
	CPPUNIT_ASSERT(CompositeMLDSA::metadataFor(CompositeMLDSA::Algorithm::MLDSA65_ECDSA_P256_SHA512, meta));

	// Tamper with the ML-DSA component (first byte)
	{
		ByteString tampered = sig;
		tampered[0] ^= 0xFF;
		CPPUNIT_ASSERT(!composite->verify(kp->getPublicKey(), dataToSign, tampered, AsymMech::COMPOSITE_MLDSA));
	}

	// Tamper with the ECDSA component (a byte past the ML-DSA signature)
	{
		ByteString tampered = sig;
		tampered[meta.mldsaSigLen + 3] ^= 0xFF;
		CPPUNIT_ASSERT(!composite->verify(kp->getPublicKey(), dataToSign, tampered, AsymMech::COMPOSITE_MLDSA));
	}

	composite->recycleKeyPair(kp);
	composite->recycleParameters(p);
}

#endif // WITH_ML_DSA && WITH_ECC
