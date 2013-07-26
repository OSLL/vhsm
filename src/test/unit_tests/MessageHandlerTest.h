#ifndef MESSAGEHANDLERTEST_H
#define MESSAGEHANDLERTEST_H
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>
#include <cppunit/extensions/HelperMacros.h>
#include "MessageHandler.h"

class MessageHandlerTest : public CppUnit::TestFixture {
public:
    void testSessionMessageHandler();
    void testMacMessageHandler();
    void testDigestMessageHandler();
    void testsKeyMgmtMessageHandler();
private:
    MacMessageHandler     macMessageHandler;
    SessionMessageHandler sessionMessageHandler;
    DigestMessageHandler  digestMessageHandler;
    KeyMgmtMessageHandler keyMgmtMessageHandler;

    VhsmMessage createStartMessage();
    VhsmMessage createLoginMessage();
    VhsmMessage createLogoutMessage();
    VhsmMessage createEndMessage ();

    VhsmMessage createMacMessage(VhsmMacMessage_MessageType const& type, VhsmSession const& session);
    VhsmMessage createMacInitMessage(VhsmSession const& session);
    VhsmMessage createMacUpdateMessage(VhsmSession const& session);

    VhsmMessage createDigestMessage(VhsmDigestMessage_MessageType const& type, VhsmSession const& session);
    VhsmMessage createDigestInitMsg(VhsmSession const& session);
    VhsmMessage createDigestUpdateMsg(VhsmSession const& session);
    VhsmMessage createDigestUpdateKeyMsg(VhsmSession const& session);

    VhsmMessage createKeyMgmtMessage(VhsmKeyMgmtMessage_MessageType const& type, VhsmSession const& session);
    VhsmMessage createCreateKeyMsg(VhsmSession const& session);
    VhsmMessage createDeleteKeyMsg(VhsmSession const& session);
    VhsmMessage createGetKeyInfoMsg(VhsmSession const& session);

    //-------------------------------------------------------------------------------------------
    CPPUNIT_TEST_SUITE(MessageHandlerTest);
    CPPUNIT_TEST(testSessionMessageHandler);
    CPPUNIT_TEST(testMacMessageHandler);
    CPPUNIT_TEST(testDigestMessageHandler);
    CPPUNIT_TEST (testsKeyMgmtMessageHandler);
    CPPUNIT_TEST_SUITE_END();
};

#endif // MESSAGEHANDLERTEST_H
