#ifndef VHSMSTORAGETEST_H
#define VHSMSTORAGETEST_H

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <vector>

class VhsmStorageTest : public CppUnit::TestFixture {
public:
    void testInitDatabase();
    void testCreateUser();
    void testLogin();
    void testImportKey();
    void testDeleteKey();
    void testGetUserPrivateKey();
    void testGetKeyIdsCount();
    void testGetKeyIds();
    void testGetKeyInfo();

private:
    std::vector<std::string> keyIDs;

    CPPUNIT_TEST_SUITE(VhsmStorageTest);
    CPPUNIT_TEST(testInitDatabase);
    CPPUNIT_TEST(testCreateUser);
    CPPUNIT_TEST(testLogin);
    CPPUNIT_TEST(testImportKey);
    CPPUNIT_TEST(testDeleteKey);
    CPPUNIT_TEST(testGetUserPrivateKey);
    CPPUNIT_TEST(testGetKeyIdsCount);
    CPPUNIT_TEST(testGetKeyIds);
    CPPUNIT_TEST(testGetKeyInfo);
    CPPUNIT_TEST_SUITE_END();
};

#endif // VHSMSTORAGETEST_H
