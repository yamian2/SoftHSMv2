/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
/*****************************************************************************
 CompositeMLDSATests.h

 Contains test cases to test the composite ML-DSA class
 *****************************************************************************/

#ifndef _SOFTHSM_V2_COMPOSITEMLDSATESTS_H
#define _SOFTHSM_V2_COMPOSITEMLDSATESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "AsymmetricAlgorithm.h"

class CompositeMLDSATests : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(CompositeMLDSATests);
	CPPUNIT_TEST(testKeyGeneration);
	CPPUNIT_TEST(testSerialisation);
	CPPUNIT_TEST(testPKCS8);
	CPPUNIT_TEST(testSigningVerifying);
	CPPUNIT_TEST(testSigningVerifyingWithContext);
	CPPUNIT_TEST(testSigningMultiPartVerifyingMultiPart);
	CPPUNIT_TEST(testSigningMultiPartVerifyingMultiPartWithContext);
	CPPUNIT_TEST(testVerifyingTamperedSignature);
	CPPUNIT_TEST_SUITE_END();

public:
	CompositeMLDSATests() : composite(NULL) {}
	void testKeyGeneration();
	void testSerialisation();
	void testPKCS8();
	void testSigningVerifying();
	void testSigningVerifyingWithContext();
	void testSigningMultiPartVerifyingMultiPart();
	void testSigningMultiPartVerifyingMultiPartWithContext();
	void testVerifyingTamperedSignature();

	void setUp();
	void tearDown();

private:
	// Composite ML-DSA instance
	AsymmetricAlgorithm* composite;
};

#endif // !_SOFTHSM_V2_COMPOSITEMLDSATESTS_H
