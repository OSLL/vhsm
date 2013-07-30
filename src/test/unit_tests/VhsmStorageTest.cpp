#include "VhsmStorageTest.h"
#include "VhsmStorage.h"

#include <sqlite3.h>

void VhsmStorageTest::testInitDatabase() {
    VhsmStorage storage("./");
    VhsmStorage badStorage("./data/");

    CPPUNIT_ASSERT_MESSAGE("DB creation failed", storage.initDatabase() && FSUtils::isFileExists("keys.db"));
    CPPUNIT_ASSERT_MESSAGE("storage initialized in non-existing location", !badStorage.initDatabase());

    sqlite3 *db;
    CPPUNIT_ASSERT_MESSAGE("unable to open database", sqlite3_open("keys.db", &db) == SQLITE_OK);

    std::string queryText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
    sqlite3_stmt *query;
    CPPUNIT_ASSERT_MESSAGE("sql query creation failed", sqlite3_prepare(db, queryText.c_str(), queryText.size(), &query, NULL) == SQLITE_OK);

    std::vector<std::string> tables;
    while(sqlite3_step(query) == SQLITE_ROW) tables.push_back((char*)sqlite3_column_text(query, 0));
    CPPUNIT_ASSERT_MESSAGE("Table 'Keys' not found in DB", std::find(tables.begin(), tables.end(), "Keys") != tables.end());
    CPPUNIT_ASSERT_MESSAGE("Table 'Users' not found in DB", std::find(tables.begin(), tables.end(), "Users") != tables.end());
    sqlite3_finalize(query);
    sqlite3_close(db);
}

void VhsmStorageTest::testCreateUser() {
    VhsmStorage storage("./");

    CPPUNIT_ASSERT_MESSAGE("user creation failed", storage.createUser("user_1", "password") == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("double user creation", storage.createUser("user_1", "password_2") != ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("user creation failed", storage.createUser("user_2", "password") == ERR_NO_ERROR);

    sqlite3 *db;
    CPPUNIT_ASSERT_MESSAGE("unable to open database", sqlite3_open("keys.db", &db) == SQLITE_OK);

    std::string queryText = "SELECT count(UID) FROM Users";
    sqlite3_stmt *userCountQuery;
    CPPUNIT_ASSERT_MESSAGE("sql query creation failed", sqlite3_prepare(db, queryText.c_str(), queryText.size(), &userCountQuery, NULL) == SQLITE_OK);
    CPPUNIT_ASSERT_MESSAGE("user count sql query failed", sqlite3_step(userCountQuery) == SQLITE_ROW);
    CPPUNIT_ASSERT_MESSAGE("invalid user count", sqlite3_column_int(userCountQuery, 0) == 2);

    sqlite3_finalize(userCountQuery);
    sqlite3_close(db);
}

void VhsmStorageTest::testLogin() {
     VhsmStorage storage("./");

     CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(VhsmUser("user_1", "password")));
     CPPUNIT_ASSERT_MESSAGE("double login failed", storage.loginUser(VhsmUser("user_1", "password")));
     CPPUNIT_ASSERT_MESSAGE("invalid user logged in", !storage.loginUser(VhsmUser("user_3", "")));
     CPPUNIT_ASSERT_MESSAGE("invalid password accepted", !storage.loginUser(VhsmUser("user_2", "")));
     CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(VhsmUser("user_2", "password")));
     storage.logoutUser(VhsmUser("user_1", "password"));
     storage.logoutUser(VhsmUser("user_2", "password"));
}

void VhsmStorageTest::testImportKey() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));
    CPPUNIT_ASSERT_MESSAGE("import key failed", storage.importKey(user, "123", "1", 0) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("double import", storage.importKey(user, "321", "1", 0) == ERR_KEY_ID_OCCUPIED);
    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.importKey(badUser, "123", "1", 0) == ERR_NOT_AUTHORIZED);

    std::string keyID;
    CPPUNIT_ASSERT_MESSAGE("key generation failed", storage.importKey(user, "", keyID, 0) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("key generation failed", !keyID.empty());
    CPPUNIT_ASSERT_MESSAGE("DB corrupted", storage.getKeyIdsCount(user) == 2);
    storage.logoutUser(user);

    keyIDs.push_back(keyID);
}

void VhsmStorageTest::testDeleteKey() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));
    CPPUNIT_ASSERT_MESSAGE("delete key failed", storage.deleteKey(user, "1") == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("non-existing key deleted", storage.deleteKey(user, "1") == ERR_KEY_NOT_FOUND);
    CPPUNIT_ASSERT_MESSAGE("non-existing key deleted", storage.getKeyIdsCount(user) == 1);
    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.deleteKey(badUser, "") == ERR_NOT_AUTHORIZED);
    storage.logoutUser(user);
}

void VhsmStorageTest::testGetUserPrivateKey() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");
    std::string keyID, pkey;

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));
    CPPUNIT_ASSERT_MESSAGE("key generation failed", storage.importKey(user, "123", keyID, 0) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("private key extraction failed", storage.getUserPrivateKey(user, keyID, pkey) == ERR_NO_ERROR);
    CPPUNIT_ASSERT_MESSAGE("private key corrupted", pkey == "123");
    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.getUserPrivateKey(badUser, "", pkey) == ERR_NOT_AUTHORIZED);
    CPPUNIT_ASSERT_MESSAGE("invalid keyID accepted", storage.getUserPrivateKey(user, "", pkey) == ERR_KEY_NOT_FOUND);
    storage.logoutUser(user);

    keyIDs.push_back(keyID);
}

void VhsmStorageTest::testGetKeyIdsCount() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));
    CPPUNIT_ASSERT_MESSAGE("DB corrupted", storage.getKeyIdsCount(user) == 2);
    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.getKeyIdsCount(badUser) == -1);
    storage.logoutUser(user);
}

void VhsmStorageTest::testGetKeyIds() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));

    std::vector<std::string> ids = storage.getKeyIds(user);
    for(std::vector<std::string>::iterator i = keyIDs.begin(); i != keyIDs.end(); ++i) {
        CPPUNIT_ASSERT_MESSAGE("KeyID not found in DB", std::find(ids.begin(), ids.end(), *i) != ids.end());
    }

    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.getKeyIds(badUser).empty());
    storage.logoutUser(user);
}

void VhsmStorageTest::testGetKeyInfo() {
    VhsmStorage storage("./");
    VhsmUser user("user_1", "password"), badUser("user_2", "password");

    CPPUNIT_ASSERT_MESSAGE("login failed", storage.loginUser(user));

    std::vector<VhsmKeyInfo> kinfo = storage.getKeyInfo(user, "");
    for(std::vector<std::string>::iterator i = keyIDs.begin(); i != keyIDs.end(); ++i) {
        std::vector<VhsmKeyInfo>::iterator k = kinfo.begin();
        for(; k != kinfo.end(); ++k) {
            if(k->keyID == *i) break;
        }
        CPPUNIT_ASSERT_MESSAGE("DB corrupted", k != kinfo.end() && k->length == 32);
        kinfo.erase(k);
    }

    CPPUNIT_ASSERT_MESSAGE("not authorized user accepted", storage.getKeyInfo(badUser, "").empty());
    storage.logoutUser(user);
}
