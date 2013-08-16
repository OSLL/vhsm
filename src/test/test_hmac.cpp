#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/digest.h"
#include "vhsm_api_prototype/mac.h"
#include "vhsm_api_prototype/key_mgmt.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

#include <osrng.h>
#include <hmac.h>
#include <sha.h>

class HmacTest : public CppUnit::TestFixture {
public:
    void run() {
        vhsm_credentials vhsmUser = {"user", "password"};
        vhsm_session s1, s2;

        char msg[VHSM_MAX_DATA_LENGTH];
        CryptoPP::AutoSeededRandomPool rnd;
        rnd.GenerateBlock((byte*)msg, VHSM_MAX_DATA_LENGTH);

        char md[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
        char realmd[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
        CryptoPP::HMAC<CryptoPP::SHA1>((byte*)"abcd", 4).CalculateDigest((byte*)realmd, (byte*)msg, VHSM_MAX_DATA_LENGTH);

        vhsm_key_id vhsmKeyId = {"some_key_id"};
        vhsm_key vhsmKey = {vhsmKeyId, (void*)"abcd", 4 };
        vhsm_digest_method sha1 = {VHSM_DIGEST_SHA1, NULL};
        vhsm_digest_method badDigestMethod = {0, NULL};
        vhsm_mac_method macMethod = {VHSM_MAC_HMAC, &sha1, vhsmKeyId};
        vhsm_mac_method badMacMethod1 = {VHSM_MAC_HMAC, &badDigestMethod, vhsmKeyId};
        vhsm_mac_method badMacMethod2 = {VHSM_MAC_HMAC, &sha1, {"same_key_id"}};

        //login
        CPPUNIT_ASSERT_MESSAGE("unable to start session 1", vhsm_start_session(&s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("unable to start session 2", vhsm_start_session(&s2) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm_login(s1, vhsmUser) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("create key failed", vhsm_key_mgmt_create_key(s1, vhsmKey, 0) == ERR_NO_ERROR);

        //init
        CPPUNIT_ASSERT_MESSAGE("unsupported method accepted", vhsm_mac_init(s1, badMacMethod1) != ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("invalid key id accepted", vhsm_mac_init(s1, badMacMethod2) == ERR_KEY_NOT_FOUND);
        CPPUNIT_ASSERT_MESSAGE("mac_init failed", vhsm_mac_init(s1, macMethod) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_init(s2, macMethod) != ERR_NO_ERROR);

        //update
        CPPUNIT_ASSERT_MESSAGE("mac_update failed", vhsm_mac_update(s1, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_update(s2, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) != ERR_NO_ERROR);

        //final
        unsigned int md_size, bad_md_size;
        CPPUNIT_ASSERT_MESSAGE("unable to get mac size", vhsm_mac_end(s1, NULL, &md_size) == ERR_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("wrong size returned", md_size == CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_end(s2, NULL, &bad_md_size) == ERR_NOT_AUTHORIZED);
        CPPUNIT_ASSERT_MESSAGE("mac_end failed", vhsm_mac_end(s1, (unsigned char*)md, &md_size) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("double mac_end", vhsm_mac_end(s1, (unsigned char*)md, &md_size) != ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("wrong message digest", memcmp(realmd, md, CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE) == 0);

        //logout
        CPPUNIT_ASSERT_MESSAGE("unable to delete key", vhsm_key_mgmt_delete_key(s1, vhsmKeyId) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm_logout(s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s2) == ERR_NO_ERROR);
    }

private:
    CPPUNIT_TEST_SUITE(HmacTest);
    CPPUNIT_TEST(run);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION (HmacTest);

int main (int argc, char **argv) {
    CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
    CppUnit::TextTestRunner runner;
    runner.addTest(test);
    runner.run();
    return 0;
}
