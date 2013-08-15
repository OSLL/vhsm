#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/digest.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

#include <crypto++/osrng.h>
#include <crypto++/sha.h>

class DigestTest : public CppUnit::TestFixture {
public:
    void run() {
        vhsm_credentials vhsmUser = {"user", "password"};
        vhsm_session s1, s2;

        vhsm_digest_method digestMethod = {VHSM_DIGEST_SHA1, NULL};
        vhsm_digest_method badDigestMethod = {0, NULL};

        char msg[VHSM_MAX_DATA_LENGTH];
        CryptoPP::AutoSeededRandomPool rnd;
        rnd.GenerateBlock((byte*)msg, VHSM_MAX_DATA_LENGTH);

        char md[CryptoPP::SHA1::DIGESTSIZE];
        byte realmd[CryptoPP::SHA1::DIGESTSIZE];
        CryptoPP::SHA1().CalculateDigest((byte*)realmd, (byte*)msg, VHSM_MAX_DATA_LENGTH);

        //login
        CPPUNIT_ASSERT_MESSAGE("unable to start session 1", vhsm_start_session(&s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("unable to start session 2", vhsm_start_session(&s2) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm_login(s1, vhsmUser) == ERR_NO_ERROR);

        //init
        CPPUNIT_ASSERT_MESSAGE("unsupported method accepted", vhsm_digest_init(s1, badDigestMethod) != ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("digest_init failed", vhsm_digest_init(s1, digestMethod) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_digest_init(s2, digestMethod) != ERR_NO_ERROR);

        //update
        CPPUNIT_ASSERT_MESSAGE("digest_update failed", vhsm_digest_update(s1, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_digest_update(s2, (unsigned char*)msg, VHSM_MAX_DATA_LENGTH) != ERR_NO_ERROR);

        //final
        unsigned int md_size, bad_md_size;
        CPPUNIT_ASSERT_MESSAGE("unable to get digest size", vhsm_digest_end(s1, NULL, &md_size) == ERR_BAD_BUFFER_SIZE);
        CPPUNIT_ASSERT_MESSAGE("wrong size returned", md_size == CryptoPP::SHA1::DIGESTSIZE);
        CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm_digest_end(s2, NULL, &bad_md_size) == ERR_NOT_AUTHORIZED);
        CPPUNIT_ASSERT_MESSAGE("digest_end failed", vhsm_digest_end(s1, (unsigned char*)md, &md_size) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("double digest_end", vhsm_digest_end(s1, (unsigned char*)md, &md_size) != ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("wrong message digest", memcmp(realmd, md, CryptoPP::SHA1::DIGESTSIZE) == 0);

        //logout
        CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm_logout(s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s1) == ERR_NO_ERROR);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s2) == ERR_NO_ERROR);
    }

private:
    CPPUNIT_TEST_SUITE(DigestTest);
    CPPUNIT_TEST(run);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION (DigestTest);

int main (int argc, char **argv) {
    CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
    CppUnit::TextTestRunner runner;
    runner.addTest(test);
    runner.run();
    return 0;
}
