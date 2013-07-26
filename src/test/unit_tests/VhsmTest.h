#ifndef VHSMTEST_H
#define VHSMTEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

class VhsmTest : public CppUnit::TestFixture {
public:
    void testLogin();
    void testDigestSHA1();
    void testMac();
    void testKeyMgmt(); //only authorization checks

private:
    CPPUNIT_TEST_SUITE(VhsmTest);
    CPPUNIT_TEST(testLogin);
    CPPUNIT_TEST(testDigestSHA1);
    CPPUNIT_TEST(testMac);
    CPPUNIT_TEST(testKeyMgmt);
    CPPUNIT_TEST_SUITE_END();
};

#endif // VHSMTEST_H
