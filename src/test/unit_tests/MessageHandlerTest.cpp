#include "MessageHandlerTest.h"

void MessageHandlerTest::testSessionMessageHandler(){
    VHSM vhsm;
    ClientId id;
    VhsmSession session;

    //Start session tests
    VhsmMessage startSessionMsg = createStartMessage();
    VhsmResponse r = sessionMessageHandler.handle(vhsm, startSessionMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Start session is failed", r.error_code() == ERR_NO_ERROR);

    //login tests
    VhsmMessage loginMsg = createLoginMessage();
    r = sessionMessageHandler.handle(vhsm, loginMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Login is failed", r.error_code() == ERR_NO_ERROR);
    loginMsg.mutable_session_message()->mutable_login_message()->set_username("evil", sizeof("evil"));
    r = sessionMessageHandler.handle(vhsm, loginMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Wrong user or password", r.error_code() == ERR_BAD_CREDENTIALS);

    //logout tests
    VhsmMessage logoutMsg = createLogoutMessage();
    r = sessionMessageHandler.handle(vhsm, logoutMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Logout is failed", r.error_code() == ERR_NO_ERROR);
    r = sessionMessageHandler.handle(vhsm, logoutMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Double logout", r.error_code() == ERR_BAD_SESSION);

    //end session tests
    VhsmMessage endMsg = createEndMessage();
    r = sessionMessageHandler.handle(vhsm, endMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Close session is failed", r.error_code() == ERR_NO_ERROR);
    r = sessionMessageHandler.handle(vhsm, endMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Double close sesson", r.error_code() == ERR_BAD_SESSION);
}

void MessageHandlerTest::testMacMessageHandler() {
    VHSM vhsm;
    ClientId id;
    VhsmSession session;

    //LOGIN
    sessionMessageHandler.handle(vhsm, createStartMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createLoginMessage(), id, session);

    //Init tests
    VhsmMessage initMacMsg = createMacInitMessage(session);
    VhsmResponse r = macMessageHandler.handle(vhsm, initMacMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac init failed", r.error_code() == ERR_NO_ERROR);

    //update tests
    VhsmMessage updateMacMsg = createMacUpdateMessage(session);
    r = macMessageHandler.handle(vhsm, updateMacMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac update failed", r.error_code() == ERR_NO_ERROR);

    //GetMacSizeHandler tests
    VhsmMessage getSizeMessage = createMacMessage(VhsmMacMessage::GET_MAC_SIZE, session);
    r = macMessageHandler.handle(vhsm, getSizeMessage, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac get size failed", r.error_code() == ERR_NO_ERROR);

    //End tests
    VhsmMessage endMacMsg = createMacMessage(VhsmMacMessage::END, session);
    r = macMessageHandler.handle(vhsm, endMacMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac end failed", r.error_code() == ERR_NO_ERROR);

    //test operations without init
    r = macMessageHandler.handle(vhsm, updateMacMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac update without init", r.error_code() == ERR_MAC_NOT_INITIALIZED);
    r = macMessageHandler.handle(vhsm, getSizeMessage, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac getSize without init", r.error_code() == ERR_MAC_NOT_INITIALIZED);
    r = macMessageHandler.handle(vhsm, endMacMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Mac end without init", r.error_code() == ERR_MAC_NOT_INITIALIZED);

    //LOGOUT
    sessionMessageHandler.handle(vhsm, createLogoutMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createEndMessage(), id, session);
}

void MessageHandlerTest::testDigestMessageHandler() {
    VHSM vhsm;
    ClientId id;
    VhsmSession session;

    //LOGIN
    sessionMessageHandler.handle(vhsm, createStartMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createLoginMessage(), id, session);

    //init tests
    VhsmMessage initMsg = createDigestInitMsg(session);
    VhsmResponse r = digestMessageHandler.handle(vhsm, initMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest init failed", r.error_code() == ERR_NO_ERROR);

    //update tests
    VhsmMessage updateMsg = createDigestUpdateMsg(session);
    r = digestMessageHandler.handle(vhsm, updateMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest update failed", r.error_code() == ERR_NO_ERROR);

    //UpdateKey tests
    VhsmMessage updateKeyMsg = createDigestUpdateKeyMsg(session);
    r = digestMessageHandler.handle(vhsm, updateKeyMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest key update failed", r.error_code() == ERR_BAD_DIGEST_METHOD);

    //get size tests
    VhsmMessage getSizeMsg = createDigestMessage(VhsmDigestMessage::GET_DIGEST_SIZE, session);
    r = digestMessageHandler.handle(vhsm, getSizeMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest get size failed", r.error_code() == ERR_NO_ERROR);

    //end tests
    VhsmMessage endMsg = createDigestMessage(VhsmDigestMessage::END, session);
    r = digestMessageHandler.handle(vhsm, endMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest end failed", r.error_code() == ERR_NO_ERROR);

    //test operations without init
    r = digestMessageHandler.handle(vhsm, updateMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digets update without init:", r.error_code() == ERR_DIGEST_NOT_INITIALIZED);
    r = digestMessageHandler.handle(vhsm, getSizeMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest get size without init:", r.error_code() == ERR_DIGEST_NOT_INITIALIZED);
    r = digestMessageHandler.handle(vhsm, endMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Digest end without init:", r.error_code() == ERR_DIGEST_NOT_INITIALIZED);

    //LOGOUT
    sessionMessageHandler.handle(vhsm, createLogoutMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createEndMessage(), id, session);
}

void MessageHandlerTest::testsKeyMgmtMessageHandler() {
    VHSM vhsm;
    ClientId id;
    VhsmSession session;

    //LOGIN
    sessionMessageHandler.handle(vhsm, createStartMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createLoginMessage(), id, session);

    //create key tests
    VhsmMessage createKeyMsg = createCreateKeyMsg(session);
    VhsmResponse r = keyMgmtMessageHandler.handle(vhsm, createKeyMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Create key failed", r.error_code() == ERR_NO_ERROR);
    r = keyMgmtMessageHandler.handle(vhsm, createKeyMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Create two keys with equal ids", r.error_code() == ERR_KEY_ID_OCCUPIED);

    //delete key tests
    VhsmMessage delKeyMsg= createDeleteKeyMsg(session);
    r = keyMgmtMessageHandler.handle(vhsm, delKeyMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Delete key failed", r.error_code() == ERR_NO_ERROR);

    //get key ids tests
    VhsmMessage getKeyIdsMsg= createKeyMgmtMessage(VhsmKeyMgmtMessage::GET_KEY_IDS, session);
    r = keyMgmtMessageHandler.handle(vhsm, getKeyIdsMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Get key ids failed", r.error_code() == ERR_NO_ERROR);

    //get key ids count tests
    VhsmMessage getKeyIdsCountMsg= createKeyMgmtMessage(VhsmKeyMgmtMessage::GET_KEY_IDS_COUNT, session);
    r = keyMgmtMessageHandler.handle(vhsm, getKeyIdsCountMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Get key ids count failed", r.error_code() == ERR_NO_ERROR);

    //get key info tests
    VhsmMessage getKeyIdsKeyMsg= createGetKeyInfoMsg(session);
    r = keyMgmtMessageHandler.handle(vhsm, getKeyIdsKeyMsg, id, session);
    CPPUNIT_ASSERT_MESSAGE("Get key info failed", r.error_code() == ERR_NO_ERROR);

    //LOGOUT
    sessionMessageHandler.handle(vhsm, createLogoutMessage(), id, session);
    sessionMessageHandler.handle(vhsm, createEndMessage(), id, session);
}

//---------------------------------------------------------------------------------------------------------
VhsmMessage MessageHandlerTest::createStartMessage () {
    VhsmMessage message;
    message.mutable_session()->set_sid(1);
    message.set_message_class(SESSION);
    message.mutable_session_message()->set_type(VhsmSessionMessage::START);
    return message;
}

VhsmMessage MessageHandlerTest::createLoginMessage() {
    VhsmMessage message;
    message.mutable_session()->set_sid(1);
    message.set_message_class(SESSION);
    message.mutable_session_message()->set_type(VhsmSessionMessage::LOGIN);
    message.mutable_session_message()->mutable_login_message()->set_username("user");
    message.mutable_session_message()->mutable_login_message()->set_password("password");
    return message;
}

VhsmMessage MessageHandlerTest::createLogoutMessage() {
    VhsmMessage message;
    message.mutable_session()->set_sid(1);
    message.set_message_class(SESSION);
    message.mutable_session_message()->set_type(VhsmSessionMessage::LOGOUT);
    return message;
}

VhsmMessage MessageHandlerTest::createEndMessage () {
    VhsmMessage message;
    message.mutable_session()->set_sid(1);
    message.set_message_class(SESSION);
    message.mutable_session_message()->set_type(VhsmSessionMessage::END);
    return message;
}

//---------------------------------------------------------------------------------------------------------
VhsmMessage MessageHandlerTest::createMacMessage(const VhsmMacMessage_MessageType &type, const VhsmSession &session) {
    VhsmMessage message;
    message.set_message_class(MAC);
    message.mutable_session()->set_sid(session.sid());
    message.mutable_mac_message()->set_type(type);
    return message;
}

VhsmMessage MessageHandlerTest::createMacInitMessage(const VhsmSession &session) {
    VhsmMessage message = createMacMessage(VhsmMacMessage::INIT, session);
    std::string key_id("asdf");
    message.mutable_mac_message()->
            mutable_init_message()->
            mutable_mechanism()->
            set_mid(HMAC);
    message.mutable_mac_message()->
            mutable_init_message()->
            mutable_mechanism()->
            mutable_hmac_parameters()->
            mutable_digest_mechanism()->
            set_mid(SHA1);
    message.mutable_mac_message()->
            mutable_init_message()->
            mutable_mechanism()->
            mutable_hmac_parameters()->
            mutable_key_id()->
            set_id((void const *) key_id.c_str(), sizeof(key_id));
    return message;
}

VhsmMessage MessageHandlerTest::createMacUpdateMessage(const VhsmSession &session) {
    VhsmMessage message = createMacMessage(VhsmMacMessage::UPDATE, session);
    message.mutable_mac_message()->
            mutable_update_message()->
            mutable_data_chunk()->
            set_data((void const *)"", 0);
    return message;
}

//---------------------------------------------------------------------------------------------------------
VhsmMessage MessageHandlerTest::createDigestMessage(const VhsmDigestMessage_MessageType &type, const VhsmSession &session) {
    VhsmMessage message;
    message.set_message_class(DIGEST);
    message.mutable_session()->set_sid(session.sid());
    message.mutable_digest_message()->set_type(type);
    return message;
}

VhsmMessage MessageHandlerTest::createDigestInitMsg(const VhsmSession &session) {
    VhsmMessage message = createDigestMessage(VhsmDigestMessage::INIT, session);
    message.mutable_digest_message()->
            mutable_init_message()->
            mutable_mechanism()->
            set_mid(SHA1);
    return message;
}

VhsmMessage MessageHandlerTest::createDigestUpdateMsg(const VhsmSession &session) {
    VhsmMessage message = createDigestMessage(VhsmDigestMessage::UPDATE, session);
    message.mutable_digest_message()->
            mutable_update_message()->
            mutable_data_chunk()->
            set_data(std::string((char const *)"", 0));
    return message;
}

VhsmMessage MessageHandlerTest::createDigestUpdateKeyMsg(const VhsmSession &session) {
    VhsmMessage message = createDigestMessage(VhsmDigestMessage::UPDATE_KEY, session);
    char keyId[] = "new_key";
    message.mutable_digest_message()->
            mutable_update_key_message()->
            mutable_key_id()->
            set_id((void const *) keyId, sizeof(keyId));
    return message;
}

//---------------------------------------------------------------------------------------------------------
VhsmMessage MessageHandlerTest::createKeyMgmtMessage(const VhsmKeyMgmtMessage_MessageType &type, const VhsmSession &session) {
    VhsmMessage message;
    message.mutable_session()->set_sid(session.sid());

    message.set_message_class(KEY_MGMT);
    message.mutable_key_mgmt_message()->set_type(type);

    return message;
}

VhsmMessage MessageHandlerTest::createCreateKeyMsg(const VhsmSession &session) {
    VhsmMessage message = createKeyMgmtMessage(VhsmKeyMgmtMessage::CREATE_KEY, session);
    char key[] = "test_key";
    message.mutable_key_mgmt_message()->
            mutable_create_key_message()->
            mutable_key_id()->
            set_id((void const *) key, sizeof(key));
    message.mutable_key_mgmt_message()->
            mutable_create_key_message()->
            set_purpose(0);
    message.mutable_key_mgmt_message()->
            mutable_create_key_message()->
            set_force_import(true);
    return message;
}

VhsmMessage MessageHandlerTest::createDeleteKeyMsg(const VhsmSession &session) {
    VhsmMessage message = createKeyMgmtMessage(VhsmKeyMgmtMessage::DELETE_KEY, session);
    char key[] = "test_key";
    message.mutable_key_mgmt_message()->
            mutable_delete_key_message()->
            mutable_key_id()->
            set_id((void const *) key, sizeof(key));
    return message;
}

VhsmMessage MessageHandlerTest::createGetKeyInfoMsg(const VhsmSession &session) {
    VhsmMessage message = createKeyMgmtMessage(VhsmKeyMgmtMessage::GET_KEY_INFO, session);
    char key[] = "test_key";
    message.mutable_key_mgmt_message()->
            mutable_delete_key_message()->
            mutable_key_id()->
            set_id((void const *) key, sizeof(key));
    return message;
}
