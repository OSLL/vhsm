#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/digest.h"
#include "vhsm_api_prototype/mac.h"
#include "vhsm_api_prototype/key_mgmt.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

#include <crypto++/osrng.h>
#include <crypto++/hmac.h>
#include <crypto++/sha.h>

#include <pthread.h>

class ParallelTest : public CppUnit::TestFixture {
public:
    static void *differentSessionsHmacTest(void *key) {
        vhsm_credentials vhsmUser = {"user", "password"};
        vhsm_session s1, s2;

        char msg[VHSM_MAX_DATA_LENGTH];
        CryptoPP::AutoSeededRandomPool rnd;
        rnd.GenerateBlock((byte*)msg, VHSM_MAX_DATA_LENGTH);

        char md[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
        char realmd[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
        CryptoPP::HMAC<CryptoPP::SHA1>((byte*)"abcd", 4).CalculateDigest((byte*)realmd, (byte*)msg, VHSM_MAX_DATA_LENGTH);

        vhsm_key_id vhsmKeyId;
        memset(vhsmKeyId.id, 0, sizeof(vhsmKeyId.id));
        memcpy(vhsmKeyId.id, (char*)key, std::min(sizeof(vhsmKeyId.id), strlen((char*)key)));
        vhsm_key vhsmKey = {vhsmKeyId, (void*)"abcd", 4 };
        vhsm_digest_method sha1 = {VHSM_DIGEST_SHA1, NULL};
        vhsm_digest_method badDigestMethod = {0, NULL};
        vhsm_mac_method macMethod = {VHSM_MAC_HMAC, &sha1, vhsmKeyId};
        vhsm_mac_method badMacMethod1 = {VHSM_MAC_HMAC, &badDigestMethod, vhsmKeyId};
        vhsm_mac_method badMacMethod2 = {VHSM_MAC_HMAC, &sha1, {"same_key_id"}};

        //login
        CPPUNIT_ASSERT_MESSAGE("unable to start session 1", vhsm_start_session(&s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("unable to start session 2", vhsm_start_session(&s2) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm_login(s1, vhsmUser) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("create key failed", vhsm_key_mgmt_create_key(s1, vhsmKey, 0) == VHSM_RV_OK);

        //init
        CPPUNIT_ASSERT_MESSAGE("unsupported method accepted", vhsm_mac_init(s1, badMacMethod1) != VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid key id accepted", vhsm_mac_init(s1, badMacMethod2) != VHSM_RV_OK);
        int res = vhsm_mac_init(s1, macMethod);
        std::stringstream resstr;
        resstr << "mac_init failed: " << (char*)key << " | error: " << res;
        CPPUNIT_ASSERT_MESSAGE(resstr.str(), res == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_init(s2, macMethod) != VHSM_RV_OK);

        //update
        CPPUNIT_ASSERT_MESSAGE("mac_update failed", vhsm_mac_update(s1, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_update(s2, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) != VHSM_RV_OK);

        //final
        unsigned int md_size, bad_md_size;
        CPPUNIT_ASSERT_MESSAGE("unable to get mac size", vhsm_mac_end(s1, NULL, &md_size) == VHSM_RV_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("wrong size returned", md_size == CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_mac_end(s2, NULL, &bad_md_size) == VHSM_RV_NOT_AUTHORIZED);
        CPPUNIT_ASSERT_MESSAGE("mac_end failed", vhsm_mac_end(s1, (unsigned char*)md, &md_size) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("double mac_end", vhsm_mac_end(s1, (unsigned char*)md, &md_size) != VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("wrong message digest", memcmp(realmd, md, CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE) == 0);

        //logout
        res = vhsm_key_mgmt_delete_key(s1, vhsmKeyId);
        resstr << "unable to delete key: " << (char*)key << " | error: " << res;
        CPPUNIT_ASSERT_MESSAGE(resstr.str(), res == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm_logout(s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s2) == VHSM_RV_OK);

        return 0;
    }

    void run() {
        pthread_t th1, th2;
        char keyId1[14] = "some_key_id_1";
        char keyId2[14] = "some_key_id_2";
        pthread_create(&th1, 0, ParallelTest::differentSessionsHmacTest, keyId1);
        pthread_create(&th2, 0, ParallelTest::differentSessionsHmacTest, keyId2);
        pthread_join(th1, NULL);
        pthread_join(th2, NULL);
    }

private:
    CPPUNIT_TEST_SUITE(ParallelTest);
    CPPUNIT_TEST(run);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION (ParallelTest);

int main (int argc, char **argv) {
    CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
    CppUnit::TextTestRunner runner;
    runner.addTest(test);
    runner.run();
    return 0;
}
