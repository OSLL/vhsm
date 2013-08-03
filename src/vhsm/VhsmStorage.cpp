#include "VhsmStorage.h"

#include <iostream>
#include <fstream>

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include <crypto++/osrng.h>
#include <crypto++/integer.h>
#include <crypto++/pwdbased.h>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/base64.h>

#define MAX_USER_KEY_LENGTH 3072

bool FSUtils::getStat(const std::string &path, struct stat *s) {
    return stat(path.c_str(), s) == 0;
}

bool FSUtils::isDirectoryExists(const std::string &path) {
    struct stat s;
    return getStat(path, &s) ? S_ISDIR(s.st_mode) : false;
}

bool FSUtils::isFileExists(const std::string &path) {
    struct stat s;
    return getStat(path, &s) ? S_ISREG(s.st_mode) : false;
}

bool FSUtils::createDirectory(const std::string &path) {
    return mkdir(path.c_str(), 0777) == 0;
}

bool FSUtils::createFile(const std::string &path) {
    std::ofstream file(path.c_str());
    bool res = file.is_open();
    file.close();
    return res;
}

bool FSUtils::removeDirectory(const std::string &path) {
    return rmdir(path.c_str()) == 0;
}

bool FSUtils::removeFile(const std::string &path) {
    return unlink(path.c_str()) == 0;
}

static inline bool ec2bool(const ErrorCode &ec) {
    return ec == ERR_NO_ERROR;
}

/**********************************************************************************/

VhsmStorage::VhsmStorage(const std::string &storageRoot) : dbPath(storageRoot), kdb(0) {
    if(!dbPath.empty() && dbPath.at(dbPath.size() - 1) != '/') dbPath.push_back('/');
    dbPath += "keys.db";

    sqlite3_open(dbPath.c_str(), &kdb);
    prepareQueries();
}

VhsmStorage::~VhsmStorage() {
    sqlite3_finalize(createUserQuery);
    sqlite3_finalize(getUserQuery);
    sqlite3_finalize(hasKeyIdQuery);
    sqlite3_finalize(insertKeyQuery);
    sqlite3_finalize(deleteKeyQuery);
    sqlite3_finalize(getKeyIdsCountQuery);
    sqlite3_finalize(getKeyIdsQuery);
    sqlite3_finalize(getKeyInfoQuery);
    sqlite3_finalize(getKeysInfoQuery);
    sqlite3_finalize(getUserPrivateKeyQuery);

    sqlite3_close(kdb);
//    for(UserKeyMap::iterator i = activeUsers.begin(); i != activeUsers.end(); ++i) {
//        closeDatabase(i->first);
//    }
}

void VhsmStorage::prepareQueries() {
    if(!kdb) return;

    std::string qtext = "INSERT INTO Users (Name, AuthKey, Salt, Iterations) VALUES (?, ?, ?, ?)";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &createUserQuery, NULL);

    qtext = "SELECT * FROM Users WHERE Name = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getUserQuery, NULL);

    qtext = "SELECT KeyID FROM Keys WHERE KeyID = ? AND UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &hasKeyIdQuery, NULL);

    qtext = "INSERT INTO Keys (KeyID, UID, Key, Purpose, ImportDate) VALUES (?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &insertKeyQuery, NULL);

    qtext = "DELETE FROM Keys WHERE KeyID = ? AND UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &deleteKeyQuery, NULL);

    qtext = "SELECT count(KeyID) FROM Keys WHERE UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getKeyIdsCountQuery, NULL);

    qtext = "SELECT KeyID FROM Keys WHERE UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getKeyIdsQuery, NULL);

    qtext = "SELECT KeyID, Key, Purpose, ImportDate FROM Keys WHERE UID = ? AND KeyID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getKeyInfoQuery, NULL);

    qtext = "SELECT KeyID, Key, Purpose, ImportDate FROM Keys WHERE UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getKeysInfoQuery, NULL);

    qtext = "SELECT Key FROM Keys WHERE KeyID = ? AND UID = ?";
    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &getUserPrivateKeyQuery, NULL);

}

//------------------------------------------------------------------------------

bool VhsmStorage::initDatabase() {
    sqlite3 *db = 0;
    if(sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cout << "Unable to open database file: " << dbPath  << std::endl;
        return false;
    }

    static const std::string qtext = "create table Users ("
            "UID                  INTEGER              primary key autoincrement,"
            "Name                 TEXT                 not null,"
            "AuthKey              BLOB                 not null,"
            "Salt                 BLOB                 not null,"
            "Iterations           INTEGER              not null"
            ");"
            "create unique index Users_PK on Users (UID);"
            "create table Keys ("
            "KeyID                TEXT                 not null,"
            "UID                  INTEGER              not null,"
            "Key                  BLOB                 not null,"
            "Purpose              INTEGER              not null,"
            "ImportDate           DATETIME             not null,"
            "CONSTRAINT Keys_PrimaryKey PRIMARY KEY(KeyID, UID),"
            "CONSTRAINT Keys_ForeignKey FOREIGN KEY(UID) REFERENCES Users(UID) ON DELETE RESTRICT ON UPDATE RESTRICT"
            ");"
            "create unique index Keys_PK on Keys (KeyID);"
            "create index UserKeys_FK on Keys (UID);";

    bool res = sqlite3_exec(db, qtext.c_str(), NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return res;
}

bool VhsmStorage::loginUser(const VhsmUser &user) {
    if(!kdb) return false;

    if(activeUsers.find(user.name) != activeUsers.end()) return true;

    sqlite3_reset(getUserQuery);
    sqlite3_clear_bindings(getUserQuery);
    sqlite3_bind_text(getUserQuery, 1, user.name.c_str(), user.name.size(), NULL);
    if(sqlite3_step(getUserQuery) != SQLITE_ROW) return false;

    PKDFInfo info;
    info.salt = std::string((const char*)sqlite3_column_blob(getUserQuery, 3), sqlite3_column_bytes(getUserQuery, 3));
    info.iters = sqlite3_column_int(getUserQuery, 4);
    info.purpose = 0;
    std::string key = getDerivedKey(info, user.key);
    std::string authKey((const char*)sqlite3_column_blob(getUserQuery, 2), sqlite3_column_bytes(getUserQuery, 2));

    std::string authKeyDec;
    if(decrypt(authKey, key, authKeyDec)) {
        int id = sqlite3_column_int(getUserQuery, 0);
        return activeUsers.insert(std::make_pair(user.name, std::make_pair(id, key))).second;
    }

    return false;
}

void VhsmStorage::logoutUser(const VhsmUser &user) {
    activeUsers.erase(user.name);
//    closeDatabase(user.name);
}

ErrorCode VhsmStorage::createUser(const std::string &name, const std::string &password) {
    if(!kdb) return ERR_VHSM_ERROR;
    if(hasUser(name)) return ERR_BAD_ARGUMENTS;

    PKDFInfo info = generatePKDFOptions(0);
    std::string key = getDerivedKey(info, password);
    std::string authKeyRaw = generateBlock(USER_KEY_LENGTH);
    std::string authKey;
    if(!encrypt(authKeyRaw, key, authKey)) return ERR_VHSM_ERROR;

    sqlite3_bind_text(createUserQuery, 1, name.c_str(), name.size(), SQLITE_STATIC);
    sqlite3_bind_blob(createUserQuery, 2, authKey.data(), authKey.size(), SQLITE_STATIC);
    sqlite3_bind_blob(createUserQuery, 3, info.salt.data(), info.salt.size(), SQLITE_STATIC);
    sqlite3_bind_int(createUserQuery, 4, info.iters);

    int res = sqlite3_step(createUserQuery);
    if(res != SQLITE_DONE) {
        std::cout << "Error: " << res << " | " << sqlite3_errmsg(kdb);
    }

    sqlite3_reset(createUserQuery);
    sqlite3_clear_bindings(createUserQuery);

    return res == SQLITE_DONE ? ERR_NO_ERROR : ERR_VHSM_ERROR;
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, std::string &keyID, int purpose, size_t length, bool nokeygen) {
    if(!kdb) return ERR_VHSM_ERROR;

    std::string realKey = key;

//    DB kdb = openDatabase(user.name, user.key);
//    if(!kdb.db) goto cleanup;
    UserKeyMap::iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return ERR_NOT_AUTHORIZED;
    int userID = i->second.first;
    std::string userKey = i->second.second;

    if(!keyID.empty()) {
        //check uniqueness
        if(hasKeyId(keyID, userID)) return ERR_KEY_ID_OCCUPIED;
    } else {
        //generate key id
        do {
            keyID = base64(generateBlock(KEY_ID_LENGTH)).substr(0, KEY_ID_LENGTH);
        } while(hasKeyId(keyID, userID));
    }

    if(key.empty() && !nokeygen) {
        if(length > MAX_USER_KEY_LENGTH) return ERR_BAD_ARGUMENTS;
        realKey = generateBlock(length);
        //        } else if(key.size() != USER_KEY_LENGTH) {
        //            std::cerr << "Bad key specified" << std::endl;
        //            goto cleanup;
    } else {
        realKey = key;
    }

    std::string encRealKey;
    if(!encrypt(realKey, userKey, encRealKey)) return ERR_VHSM_ERROR;

    ErrorCode result = insertKey(keyID, userID, realKey, purpose) ? ERR_NO_ERROR : ERR_VHSM_ERROR;
//    if(result == ERR_NO_ERROR) i->second.dirty = true;
    return result;
}

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, const std::string &keyID, int purpose, size_t length, bool nokeygen) {
    std::string copyKeyID(keyID);
    return importKey(user, key, copyKeyID, purpose, length, nokeygen);
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::deleteKey(const VhsmUser &user, const std::string &keyID) {
    ErrorCode result = ERR_KEY_NOT_FOUND;
    UserKeyMap::iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return ERR_NOT_AUTHORIZED;
    int userID = i->second.first;

//    DB kdb = openDatabase(user.name, user.key);
    if(kdb && hasKeyId(keyID, userID)) {
        sqlite3_bind_text(deleteKeyQuery, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
        sqlite3_bind_int(deleteKeyQuery, 2, userID);
        int qres = sqlite3_step(deleteKeyQuery);
        switch(qres) {
        case SQLITE_DONE:
            result = ERR_NO_ERROR;
            break;
        default:
            result = ERR_VHSM_ERROR;
            std::cerr << "Unexpected query result on \'deleteKey\': " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
        }
        sqlite3_reset(deleteKeyQuery);
        sqlite3_clear_bindings(deleteKeyQuery);
    }

//    if(result == ERR_NO_ERROR) i->second.dirty = true;

    return result;
}

//------------------------------------------------------------------------------

int VhsmStorage::getKeyIdsCount(const VhsmUser &user) const {
    int icount = -1;
//    DB kdb = openDatabase(user.name, user.key);
    UserKeyMap::const_iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return -1;
    int userID = i->second.first;

    if(!kdb) return -1;
    sqlite3_bind_int(getKeyIdsCountQuery, 1, userID);
    int qres = sqlite3_step(getKeyIdsCountQuery);
    switch(qres) {
    case SQLITE_ROW:
        icount = sqlite3_column_int(getKeyIdsCountQuery, 0);
        break;
    default:
        std::cerr << "Unexpected query result on \'getKeyIdsCount\': " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
    }

    sqlite3_reset(getKeyIdsCountQuery);
    sqlite3_clear_bindings(getKeyIdsCountQuery);
    return icount;
}

//------------------------------------------------------------------------------

std::vector<std::string> VhsmStorage::getKeyIds(const VhsmUser &user) const {
    std::vector<std::string> ids;
    if(!kdb) return ids;

//    DB kdb = openDatabase(user.name, user.key);
    UserKeyMap::const_iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return ids;
    int userID = i->second.first;

    sqlite3_bind_int(getKeyIdsQuery, 1, userID);
    while(sqlite3_step(getKeyIdsQuery) == SQLITE_ROW) {
        ids.push_back((const char*)sqlite3_column_text(getKeyIdsQuery, 0));
    }

    sqlite3_reset(getKeyIdsQuery);
    sqlite3_clear_bindings(getKeyIdsQuery);

//    closeDatabase(kdb, user.name, false);
    return ids;
}

//------------------------------------------------------------------------------

std::vector<VhsmKeyInfo> VhsmStorage::getKeyInfo(const VhsmUser &user, const std::string &keyID) const {
    std::vector<VhsmKeyInfo> kinfo;
    if(!kdb) return kinfo;

//    DB kdb = openDatabase(user.name, user.key);
    UserKeyMap::const_iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return kinfo;
    int userID = i->second.first;

    sqlite3_stmt *query = keyID.empty() ? getKeysInfoQuery : getKeyInfoQuery;
    sqlite3_bind_int(query, 1, userID);
    if(!keyID.empty()) sqlite3_bind_text(query, 2, keyID.c_str(), keyID.size(), SQLITE_STATIC);

    while(sqlite3_step(query) == SQLITE_ROW) {
        VhsmKeyInfo i;
        i.keyID = (char*)sqlite3_column_text(query, 0);
        sqlite3_column_blob(query, 1);
        i.length = sqlite3_column_bytes(query, 1);
        i.purpose = sqlite3_column_int(query, 2);
        i.importDate = sqlite3_column_int64(query, 3);
        kinfo.push_back(i);
    }

    sqlite3_reset(query);
    sqlite3_clear_bindings(query);

//    closeDatabase(kdb, user.name, false);
    return kinfo;
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::getUserPrivateKey(const VhsmUser &user, const std::string &keyID, std::string &pkey) const {
    if(!kdb) return ERR_VHSM_ERROR;

//    DB kdb = openDatabase(user.name, user.key);
    UserKeyMap::const_iterator i = activeUsers.find(user.name);
    if(i == activeUsers.end()) return ERR_NOT_AUTHORIZED;
    int userID = i->second.first;

    sqlite3_bind_text(getUserPrivateKeyQuery, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
    sqlite3_bind_int(getUserPrivateKeyQuery, 2, userID);

    ErrorCode result = ERR_BAD_CREDENTIALS;
    if(sqlite3_step(getUserPrivateKeyQuery) == SQLITE_ROW) {
        pkey = std::string((const char *)sqlite3_column_blob(getUserPrivateKeyQuery, 0), sqlite3_column_bytes(getUserPrivateKeyQuery, 0));
        result = ERR_NO_ERROR;
    } else {
        result = ERR_KEY_NOT_FOUND;
        std::cerr << "Key with id " << keyID << " not found" << std::endl;
    }

    sqlite3_reset(getUserPrivateKeyQuery);
    sqlite3_clear_bindings(getUserPrivateKeyQuery);

//    closeDatabase(kdb, user.name, false);
    return result;
}


//------------------------------------------------------------------------------

/*
bool VhsmStorage::openDatabase(const std::string &user, const std::string &password) {
    DB db;
    std::string basePath = root + user;
    std::string tmpdbPath = root + "tmp/" + user + ".db";

    PKDFInfo info;
    if(!loadPKDFOptions(basePath + "/pkdf", info)) return false;
    db.key = getDerivedKey(info, password);

    if(decryptFile(basePath + "/kdb", tmpdbPath, db.key)) {
        if(sqlite3_open(tmpdbPath.c_str(), &db.db) != SQLITE_OK) {
            sqlite3_close(db.db);
            db.key.clear();
            return false;
        }
    } else {
        db.key.clear();
        return false;
    }

    std::cout << "DB opened | user: " << user << std::endl;

    activeUsers.insert(std::make_pair(user, db));
    return true;
}

void VhsmStorage::closeDatabase(const std::string &user) {
    UserKeyMap::iterator i = activeUsers.find(user);
    if(i == activeUsers.end()) return;

    std::string tmpdbPath = root + "tmp/" + user + ".db";

    if(i->second.dirty) {
        //dump current memory database, maybe should make backup
        encryptFile(tmpdbPath, root + user + "/kdb", i->second.key);
//        encryptFile(root + user + "/kdb.tmp", root + user + "/kdb", db.key);
    }

    sqlite3_close(i->second.db);

    activeUsers.erase(i);

    FSUtils::removeFile(tmpdbPath);

    std::cout << "DB closed | user: " << user << std::endl;

}
*/

//------------------------------------------------------------------------------

std::string VhsmStorage::getDerivedKey(const PKDFInfo &info, const std::string &password) const {
    std::vector<char> derivedKey(USER_KEY_LENGTH);

    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1> pkdf;
    pkdf.DeriveKey((byte*)derivedKey.data(), derivedKey.size(),
                   info.purpose,
                   (const byte*)password.data(), password.size(),
                   (const byte*)info.salt.data(), info.salt.size(),
                   info.iters);

    return std::string(derivedKey.data(), derivedKey.size());
}

//------------------------------------------------------------------------------

bool VhsmStorage::encrypt(const std::string &data, const std::string &key, std::string &result) const {
    CryptoPP::AutoSeededRandomPool prng;

    byte iv[CryptoPP::AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV((const byte*)key.data(), key.size(), iv, sizeof(iv));

    std::string cipher;
    try {
        CryptoPP::StringSource(data, true,
                               new CryptoPP::AuthenticatedEncryptionFilter(enc, new CryptoPP::StringSink(cipher), false)
                               );
    } catch(CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        return false;
    }

    result = std::string((const char*)iv, sizeof(iv));
    result.append(cipher);

    return true;
}

bool VhsmStorage::decrypt(const std::string &data, const std::string &key, std::string &result) const {
    static const size_t iv_size = CryptoPP::AES::BLOCKSIZE;

    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)data.data(), iv_size);

    CryptoPP::AuthenticatedDecryptionFilter df(dec, new CryptoPP::StringSink(result));

    try {
        CryptoPP::StringSource((const byte*)data.data() + iv_size,
                               data.size() - iv_size,
                               true,
                               new CryptoPP::Redirector(df)
                               );
    } catch(CryptoPP::Exception &e) {
        std::cerr << e.what() << std::endl;
        return false;
    }

    return df.GetLastResult();
}

//------------------------------------------------------------------------------

bool VhsmStorage::hasUser(const std::string &username) const {
    sqlite3_reset(getUserQuery);
    sqlite3_clear_bindings(getUserQuery);
    sqlite3_bind_text(getUserQuery, 1, username.c_str(), username.size(), SQLITE_STATIC);

    bool result = true;
    int qres = sqlite3_step(getUserQuery);
    switch(qres) {
    case SQLITE_ROW:
        result = true;
        break;
    case SQLITE_DONE:
        result = false;
        break;
    default:
        std::cerr << "Unexpected query result on \'hasKeyID\': " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
    }

    return result;
}

bool VhsmStorage::hasKeyId(const std::string &keyID, int userID) const {
    sqlite3_bind_text(hasKeyIdQuery, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
    sqlite3_bind_int(hasKeyIdQuery, 2, userID);

    bool result = true;
    int qres = sqlite3_step(hasKeyIdQuery);
    switch(qres) {
    case SQLITE_ROW:    //we already have this key id in db
        result = true;
        break;
    case SQLITE_DONE:   //new key id
        result = false;
        break;
    default:
        std::cerr << "Unexpected query result on \'hasKeyID\': " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
    }

    sqlite3_reset(hasKeyIdQuery);
    sqlite3_clear_bindings(hasKeyIdQuery);

    return result;
}

bool VhsmStorage::insertKey(const std::string &keyID, int userID, const std::string &key, int purpose) {
    sqlite3_bind_text(insertKeyQuery, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
    sqlite3_bind_int(insertKeyQuery, 2, userID);
    sqlite3_bind_blob(insertKeyQuery, 3, key.data(), key.size(), SQLITE_STATIC);
    sqlite3_bind_int(insertKeyQuery, 4, purpose);
    sqlite3_bind_int64(insertKeyQuery, 5, time(0));

    bool result = false;
    int qres = sqlite3_step(insertKeyQuery);
    switch(qres) {
    case SQLITE_DONE:
        result = true;
        break;
    default:
        std::cerr << "Unexpected query result on \'insertKey\': " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
    }

    sqlite3_reset(insertKeyQuery);
    sqlite3_clear_bindings(insertKeyQuery);

    return result;
}

//------------------------------------------------------------------------------

VhsmStorage::PKDFInfo VhsmStorage::generatePKDFOptions(int purpose) const {
    return PKDFInfo(generateBlock(128), 5000, purpose);
}

/*
bool VhsmStorage::loadPKDFOptions(const std::string &path, PKDFInfo &info) const {
    std::ifstream file(path.c_str(), std::ifstream::in | std::ifstream::binary);
    if(!file.is_open()) return false;

    size_t saltsz = 0;
    file.read((char*)&info.iters, sizeof(info.iters));
    file.read((char*)&info.purpose, sizeof(info.purpose));
    file.read((char*)&saltsz, sizeof(saltsz));
//    file >> info.iters >> info.purpose >> saltsz;

    info.salt.resize(saltsz);
    file.read(info.salt.data(), saltsz);
    file.close();
    return true;
}

bool VhsmStorage::savePKDFOptions(const std::string &path, const PKDFInfo &info) const {
    std::ofstream file(path.c_str(), std::ofstream::out | std::ofstream::binary);
    if(!file.is_open()) return false;
//    std::string salt(info.salt.data(), info.salt.size());

    size_t saltsz = info.salt.size();
    file.write((const char*)&info.iters, sizeof(info.iters));
    file.write((const char*)&info.purpose, sizeof(info.purpose));
    file.write((const char*)&saltsz, sizeof(saltsz));
    file.write(info.salt.data(), info.salt.size());
//    file << info.iters << '\0' << info.purpose << '\0' << salt.size() << salt;

    file.close();
    return true;
}
*/

//------------------------------------------------------------------------------

std::string VhsmStorage::generateBlock(size_t size) const {
    std::vector<char> b(size);
    rnd.GenerateBlock((byte*)b.data(), b.size());
    return std::string(b.data(), b.size());
}

std::string VhsmStorage::base64(const std::string &str) const {
    std::string bs;
    CryptoPP::StringSource(str, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(bs)));
    return bs;
}
