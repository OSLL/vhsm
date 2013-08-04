#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/key_mgmt.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

class KeyMgmtTest : public CppUnit::TestFixture {
public:
    void run() {
        vhsm_credentials vhsmUser = {"user", "password"};
        vhsm_key_id vhsmKeyId = {"some_key_id"};
        vhsm_key_id generatedKeyId1 = {"\0"};
        vhsm_key_id generatedKeyId2 = {"\0"};
        vhsm_key vhsmKey = { vhsmKeyId, NULL, 0};

        vhsm_session s1, s2;
        unsigned int keyIdsCount0 = 0, keyIdsCount1 = 0, keyIdsCount2 = 0;

        //login
        CPPUNIT_ASSERT_MESSAGE("start session 1 failed", vhsm_start_session(&s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("start session 2 failed", vhsm_start_session(&s2) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm_login(s1, vhsmUser) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("unable to get key ids count", vhsm_key_mgmt_get_key_ids(s1, NULL, &keyIdsCount0) == VHSM_RV_BAD_BUFFER_SIZE);

        //generation
        CPPUNIT_ASSERT_MESSAGE("generate key failed", vhsm_key_mgmt_generate_key(s1, &vhsmKeyId, 32, 0) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid key id accepted", vhsm_key_mgmt_generate_key(s1, &vhsmKeyId, 32, 0) == VHSM_RV_KEY_ID_OCCUPIED);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_generate_key(s2, &vhsmKeyId, 32, 0) == VHSM_RV_NOT_AUTHORIZED);
        vhsmKey.id.id[0] = 0;
        CPPUNIT_ASSERT_MESSAGE("unable to generate key id", vhsm_key_mgmt_generate_key(s1, &generatedKeyId1, 32, 0) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("bad key id generated", generatedKeyId1.id[0] != 0);
        CPPUNIT_ASSERT_MESSAGE("unable to get key ids count", vhsm_key_mgmt_get_key_ids(s1, NULL, &keyIdsCount1) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("key database logic error after key creation", keyIdsCount0 + 2 == keyIdsCount1);

        //deletion
        CPPUNIT_ASSERT_MESSAGE("unable to delete key", vhsm_key_mgmt_delete_key(s1, vhsmKeyId) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid key id accepted", vhsm_key_mgmt_delete_key(s1, vhsmKeyId) == VHSM_RV_KEY_NOT_FOUND);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_delete_key(s2, vhsmKeyId) == VHSM_RV_NOT_AUTHORIZED);
        CPPUNIT_ASSERT_MESSAGE("unable to get key ids count", vhsm_key_mgmt_get_key_ids(s1, NULL, &keyIdsCount2) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("key database logic error after key deletion", keyIdsCount1 - 1 == keyIdsCount2);

        //import
        vhsmKey.id = vhsmKeyId;
        CPPUNIT_ASSERT_MESSAGE("import key failed", vhsm_key_mgmt_create_key(s1, vhsmKey, 0) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid key id accepted", vhsm_key_mgmt_create_key(s1, vhsmKey, 0) == VHSM_RV_KEY_ID_OCCUPIED);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_create_key(s2, vhsmKey, 0) == VHSM_RV_NOT_AUTHORIZED);
        vhsmKey.id.id[0] = 0;
        CPPUNIT_ASSERT_MESSAGE("unable to generate key id", vhsm_key_mgmt_create_key(s1, vhsmKey, &generatedKeyId2, 0) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("bad key id generated", generatedKeyId2.id[0] != 0);
        CPPUNIT_ASSERT_MESSAGE("unable to delete key", vhsm_key_mgmt_delete_key(s1, vhsmKeyId) == VHSM_RV_OK);

        //key ids request
        CPPUNIT_ASSERT_MESSAGE("unable to get key ids count", vhsm_key_mgmt_get_key_ids(s1, NULL, &keyIdsCount1) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_get_key_ids(s2, NULL, &keyIdsCount2) == VHSM_RV_NOT_AUTHORIZED);
        vhsm_key_id *ids = new vhsm_key_id[keyIdsCount1];
        CPPUNIT_ASSERT_MESSAGE("unable to get key ids", vhsm_key_mgmt_get_key_ids(s1, ids, &keyIdsCount1) == VHSM_RV_OK);
        keyIdsCount1--;
        CPPUNIT_ASSERT_MESSAGE("bad buffer size accepted", vhsm_key_mgmt_get_key_ids(s1, ids, &keyIdsCount1) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_get_key_ids(s2, ids, &keyIdsCount2) == VHSM_RV_NOT_AUTHORIZED);
        keyIdsCount1++;

        //key info request
        vhsm_key_info *info = new vhsm_key_info[keyIdsCount1];
        CPPUNIT_ASSERT_MESSAGE("unable to get key info", vhsm_key_mgmt_get_key_info(s1, info, &keyIdsCount1) == VHSM_RV_OK);
        keyIdsCount1--;
        CPPUNIT_ASSERT_MESSAGE("bad buffer size accepted", vhsm_key_mgmt_get_key_info(s1, info, &keyIdsCount1) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_key_mgmt_get_key_info(s2, info, &keyIdsCount2) == VHSM_RV_NOT_AUTHORIZED);
        CPPUNIT_ASSERT_MESSAGE("unable to get single key info", vhsm_key_mgmt_get_key_info(s1, generatedKeyId1, info) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("key database logic error", info[0].length == 32);

        //logout
        CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm_logout(s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s1) == VHSM_RV_OK);
    }

private:
    CPPUNIT_TEST_SUITE(KeyMgmtTest);
    CPPUNIT_TEST(run);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION (KeyMgmtTest);

int main (int argc, char **argv) {
    CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
    CppUnit::TextTestRunner runner;
    runner.addTest(test);
    runner.run();
    return 0;
}
