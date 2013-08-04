#include "vhsm_api_prototype/common.h"

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

class LoginTest : public CppUnit::TestFixture {
public:
    void run() {
        vhsm_credentials vhsmUser = {"user", "password"};

        vhsm_session s1, s2, s3;
        CPPUNIT_ASSERT_MESSAGE("unable to start session 1", vhsm_start_session(&s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("unable to start session 2", vhsm_start_session(&s2) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm_login(s1, vhsmUser) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("double login in one session", vhsm_login(s1, vhsmUser) != VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("double login in different sessions failed", vhsm_login(s2, vhsmUser) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm_logout(s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("double logout", vhsm_logout(s1) != VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s1) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("double close session", vhsm_end_session(s1) != VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm_end_session(s2) == VHSM_RV_OK);

        CPPUNIT_ASSERT_MESSAGE("unable to start session 3", vhsm_start_session(&s3) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("second login user failed", vhsm_login(s3, vhsmUser) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("second close session failed", vhsm_end_session(s3) == VHSM_RV_OK);
        CPPUNIT_ASSERT_MESSAGE("user remains logged in after session close", vhsm_logout(s3) != VHSM_RV_OK);
    }

private:
    CPPUNIT_TEST_SUITE(LoginTest);
    CPPUNIT_TEST(run);
    CPPUNIT_TEST_SUITE_END();
};

CPPUNIT_TEST_SUITE_REGISTRATION (LoginTest);

int main (int argc, char **argv) {
    CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
    CppUnit::TextTestRunner runner;
    runner.addTest(test);
    runner.run();
    return 0;
}
