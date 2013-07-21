#include "VhsmTest.h"
#include "vhsm.h"
#include <string.h>
#include <vector>
#include <crypto++/osrng.h>
#include <crypto++/sha.h>

#define BUF_SIZE 4096

void VhsmTest::testLogin() {
    VHSM vhsm;
    ClientId cid;
    cid.pid = 0; cid.veid = 0;
    std::string user = "user";
    std::string password = "password";

    VhsmSession s = vhsm.openSession(cid);
    CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("double login", !vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("logout failed", vhsm.logoutUser(s.sid()));
    CPPUNIT_ASSERT_MESSAGE("double logout", !vhsm.logoutUser(s.sid()));
    CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm.closeSession(cid, s));
    CPPUNIT_ASSERT_MESSAGE("double close session", !vhsm.closeSession(cid, s));

    s = vhsm.openSession(cid);
    CPPUNIT_ASSERT_MESSAGE("second login user failed", vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("second close session failed", vhsm.closeSession(cid, s));
    CPPUNIT_ASSERT_MESSAGE("user remains logged in after session close", !vhsm.isLoggedIn(cid, s.sid()));
}

void VhsmTest::testDigestSHA1() {
    VHSM vhsm;
    ClientId cid;
    cid.pid = 0; cid.veid = 0;
    std::string user = "user";
    std::string password = "password";

    unsigned int mdsize;

    char msg[BUF_SIZE];
    std::vector<char> md;

    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock((byte*)msg, BUF_SIZE);

    byte realmd[CryptoPP::SHA1::DIGESTSIZE];
    CryptoPP::SHA1().CalculateDigest(realmd, (byte*)msg, BUF_SIZE);

    VhsmSession s = vhsm.openSession(cid);
    CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("digestInit failed", vhsm.digestInit(SHA1, s.sid()) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("unsupported method accepted", vhsm.digestInit((VhsmDigestMechanismId)0, s.sid()) == ERR_BAD_DIGEST_METHOD);
    CPPUNIT_ASSERT_MESSAGE("digestUpdate failed", vhsm.digestUpdate(s.sid(), std::string(msg, BUF_SIZE)) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.digestUpdate(s.sid() + 1, std::string(msg, BUF_SIZE)) == ERR_DIGEST_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("digestGetSize failed", vhsm.digestGetSize(s.sid(), &mdsize) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("wrong size returned", mdsize == CryptoPP::SHA1::DIGESTSIZE);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.digestGetSize(s.sid() + 1, &mdsize) == ERR_DIGEST_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("digestFinal failed", vhsm.digestFinal(s.sid(), md) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("double digest finalization", vhsm.digestFinal(s.sid(), md) == ERR_DIGEST_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("wrong digest", memcmp(realmd, md.data(), CryptoPP::SHA1::DIGESTSIZE) == 0);
    CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm.closeSession(cid, s));
}

void VhsmTest::testMac() {
    VHSM vhsm;
    ClientId cid;
    cid.pid = 0; cid.veid = 0;
    std::string user = "user";
    std::string password = "password";

    unsigned int mdsize;

    char msg[BUF_SIZE];
    std::vector<char> md;

    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock((byte*)msg, BUF_SIZE);

    byte realmd[CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE];
    CryptoPP::HMAC<CryptoPP::SHA1>((byte*)"", 0).CalculateDigest(realmd, (byte*)msg, BUF_SIZE);

    VhsmSession s = vhsm.openSession(cid);
    CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("macInit failed", vhsm.macInit(HMAC, SHA1, s.sid(), "") == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("unsupported method accepted", vhsm.macInit((VhsmMacMechanismId)0, (VhsmDigestMechanismId)0, s.sid(), "") == ERR_BAD_MAC_METHOD);
    CPPUNIT_ASSERT_MESSAGE("macUpdate failed", vhsm.macUpdate(s.sid(), std::string(msg, BUF_SIZE)) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.macUpdate(s.sid() + 1, std::string(msg, BUF_SIZE)) == ERR_MAC_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("macGetSize failed", vhsm.macGetSize(s.sid(), &mdsize) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("wrong size returned", mdsize == CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.macGetSize(s.sid() + 1, &mdsize) == ERR_MAC_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("macFinal failed", vhsm.macFinal(s.sid(), md) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("double digest finalization", vhsm.macFinal(s.sid(), md) == ERR_MAC_NOT_INITIALIZED);
    CPPUNIT_ASSERT_MESSAGE("wrong digest", memcmp(realmd, md.data(), CryptoPP::HMAC<CryptoPP::SHA1>::DIGESTSIZE) == 0);
    CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm.closeSession(cid, s));
}

void VhsmTest::testKeyMgmt() {
    VHSM vhsm;
    ClientId cid;
    cid.pid = 0; cid.veid = 0;
    std::string user = "user", password = "password", keyID = "", keyData = "";

    VhsmSession s = vhsm.openSession(cid);
    CPPUNIT_ASSERT_MESSAGE("login user failed", vhsm.loginUser(user, password, s.sid()));
    CPPUNIT_ASSERT_MESSAGE("authorization check failed", vhsm.importKey(s.sid(), keyID, keyData, 0, true) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.importKey(s.sid() + 1, keyID, keyData, 0, true) == ERR_NOT_AUTHORIZED);
    CPPUNIT_ASSERT_MESSAGE("authorization check failed", vhsm.deleteKey(s.sid(), "") == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.deleteKey(s.sid() + 1, "") == ERR_NOT_AUTHORIZED);
    CPPUNIT_ASSERT_MESSAGE("authorization check failed", vhsm.getKeyIdsCount(s.sid()) == 1);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.getKeyIdsCount(s.sid() + 1) == -1);
    CPPUNIT_ASSERT_MESSAGE("authorization check failed", vhsm.getKeyIds(s.sid()).size() == 1);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.getKeyIds(s.sid() + 1).empty());
    CPPUNIT_ASSERT_MESSAGE("authorization check failed", vhsm.getKeyInfo(s.sid()).size() == 1);
    CPPUNIT_ASSERT_MESSAGE("invalid session id accepted", vhsm.getKeyInfo(s.sid() + 1).empty());
    CPPUNIT_ASSERT_MESSAGE("close session failed", vhsm.closeSession(cid, s));
}
