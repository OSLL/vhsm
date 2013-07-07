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

bool FSUtils::getStat(const std::string &path, struct stat *s) {
    return stat(path.c_str(), s) == 0;
}

bool FSUtils::isDirectoryExists(const std::string &path) {
    struct stat s;
    return getStat(path, &s) ? S_ISDIR(s.st_mode) : false;
}

bool FSUtils::createDirectory(const std::string &path) {
    return mkdir(path.c_str(), 0777) == 0;
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

VhsmStorage::VhsmStorage(const std::string &rootDir) : root(rootDir) {
    if(root.empty() || root.at(root.size() - 1) != '/') root.push_back('/');
}

VhsmStorage::~VhsmStorage() {
    for(UserDBMap::iterator i = activeDBs.begin(); i != activeDBs.end(); ++i) {
        closeDatabase(i->first);
    }
}

void VhsmStorage::setRoot(const std::string &rootDir) {
    if(!activeDBs.empty()) return;
    root = rootDir;
    if(root.empty() || root.at(root.size() - 1) != '/') root.push_back('/');
}

std::string VhsmStorage::getRoot() const {
    return root;
}

//------------------------------------------------------------------------------

bool VhsmStorage::loginUser(const VhsmUser &user) {
    return openDatabase(user.name, user.key);
    /*
    bool result = false;
    DB kdb = openDatabase(user.name, user.key);
    if(kdb.db.handle) {
        result = true;
        activeDBs.insert(std::make_pair(user.name, kdb));
    }
    closeDatabase(kdb, user.name, false);
    return result;
    */
}

void VhsmStorage::logoutUser(const VhsmUser &user) {
    closeDatabase(user.name);
}

ErrorCode VhsmStorage::createUser(const std::string &name, const std::string &password) {
    std::string basePath = root + name;
    if(!FSUtils::createDirectory(basePath)) return ERR_VHSM_ERROR;

    PKDFInfo info = generatePKDFOptions();
    std::string derivedKey = getDerivedKey(info, password);


    if( initKeyDatabase(basePath + "/kdb") &&
            encryptFile(basePath + "/kdb", basePath + "/kdb", derivedKey) &&
            savePKDFOptions(basePath + "/pkdf", info))
    {
        return ERR_NO_ERROR;
    } else {
        FSUtils::removeFile(basePath + "/kdb");
        FSUtils::removeDirectory(basePath);
        return ERR_VHSM_ERROR;
    }
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, std::string &keyID, int purpose, bool nokeygen) {
    std::string realKey = key;

//    DB kdb = openDatabase(user.name, user.key);
//    if(!kdb.db) goto cleanup;
    UserDBMap::iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return ERR_NOT_AUTHORIZED;
    sqlite3 *kdb = i->second.db;

    if(!keyID.empty()) {
        //check uniqueness
        if(hasKeyId(kdb, keyID)) return ERR_KEY_ID_OCCUPIED;
    } else {
        //generate key id
        do {
            keyID = base64(generateBlock(KEY_ID_LENGTH)).substr(0, KEY_ID_LENGTH);
        } while(hasKeyId(kdb, keyID));
    }

    if(key.empty() && !nokeygen) {
        realKey = generateBlock(USER_KEY_LENGTH);
        //        } else if(key.size() != USER_KEY_LENGTH) {
        //            std::cerr << "Bad key specified" << std::endl;
        //            goto cleanup;
    } else {
        realKey = key;
    }

    ErrorCode result = insertKey(kdb, keyID, realKey, purpose) ? ERR_NO_ERROR : ERR_VHSM_ERROR;
    if(result == ERR_NO_ERROR) i->second.dirty = true;
    return result;
}

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, const std::string &keyID, int purpose, bool nokeygen) {
    std::string copyKeyID(keyID);
    return importKey(user, key, copyKeyID, purpose, nokeygen);
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::deleteKey(const VhsmUser &user, const std::string &keyID) {
    static const std::string qtext = "DELETE FROM Keys WHERE KeyID = ?";
    ErrorCode result = ERR_BAD_CREDENTIALS;

    UserDBMap::iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return ERR_NOT_AUTHORIZED;
    sqlite3 *kdb = i->second.db;

//    DB kdb = openDatabase(user.name, user.key);
    if(kdb && hasKeyId(kdb, keyID)) {
        sqlite3_stmt *query = 0;
        sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);
        sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
        int qres = sqlite3_step(query);
        switch(qres) {
        case SQLITE_DONE:
            result = ERR_NO_ERROR;
            break;
        default:
            result = ERR_VHSM_ERROR;
            std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
        }
        sqlite3_finalize(query);
    }

    if(result == ERR_NO_ERROR) i->second.dirty = true;

    return result;
}

//------------------------------------------------------------------------------

int VhsmStorage::getKeyIdsCount(const VhsmUser &user) const {
    static const std::string qtext = "SELECT count(KeyID) FROM Keys";
    int icount = -1;

//    DB kdb = openDatabase(user.name, user.key);
    UserDBMap::const_iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return ERR_NOT_AUTHORIZED;
    sqlite3 *kdb = i->second.db;

    if(kdb) {
        sqlite3_stmt *query = 0;
        sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);
        int qres = sqlite3_step(query);
        switch(qres) {
        case SQLITE_ROW:
            icount = sqlite3_column_int(query, 0);
            break;
        default:
            std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(kdb) << std::endl;
        }
        sqlite3_finalize(query);
    }

//    closeDatabase(kdb, user.name, false);
    return icount;
}

//------------------------------------------------------------------------------

std::vector<std::string> VhsmStorage::getKeyIds(const VhsmUser &user) const {
    static const std::string qtext = "SELECT KeyID FROM Keys";
    std::vector<std::string> ids;

//    DB kdb = openDatabase(user.name, user.key);
    UserDBMap::const_iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return ids;
    sqlite3 *kdb = i->second.db;

    if(kdb) {
        sqlite3_stmt *query = 0;
        sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);
        while(sqlite3_step(query) == SQLITE_ROW) {
            ids.push_back((const char*)sqlite3_column_text(query, 0));
        }
        sqlite3_finalize(query);
    }

//    closeDatabase(kdb, user.name, false);
    return ids;
}

//------------------------------------------------------------------------------

std::vector<VhsmKeyInfo> VhsmStorage::getKeyInfo(const VhsmUser &user, const std::string &keyID) const {
    std::string qtext = "SELECT * FROM Keys";
    if(!keyID.empty()) qtext.append(" WHERE KeyID = ?");

    std::vector<VhsmKeyInfo> kinfo;
//    DB kdb = openDatabase(user.name, user.key);
    UserDBMap::const_iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return kinfo;
    sqlite3 *kdb = i->second.db;

    if(kdb) {
        sqlite3_stmt *query = 0;
         sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);
         sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
         while(sqlite3_step(query) == SQLITE_ROW) {
             VhsmKeyInfo i;
             i.keyID = (char*)sqlite3_column_text(query, 0);
             sqlite3_column_blob(query, 1);
             i.length = sqlite3_column_bytes(query, 1);
             i.purpose = sqlite3_column_int(query, 2);
             i.importDate = sqlite3_column_int64(query, 3);
             kinfo.push_back(i);
         }
    }

//    closeDatabase(kdb, user.name, false);
    return kinfo;
}

//------------------------------------------------------------------------------

ErrorCode VhsmStorage::getUserPrivateKey(const VhsmUser &user, const std::string &keyID, std::string &pkey) const {
    static const std::string qtext = "SELECT Key FROM Keys WHERE KeyID = ?";
    ErrorCode result = ERR_BAD_CREDENTIALS;

//    DB kdb = openDatabase(user.name, user.key);
    UserDBMap::const_iterator i = activeDBs.find(user.name);
    if(i == activeDBs.end()) return ERR_NOT_AUTHORIZED;
    sqlite3 *kdb = i->second.db;

    if(kdb) {
        sqlite3_stmt *query = 0;
        sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);
        sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
        if(sqlite3_step(query) == SQLITE_ROW) {
            pkey = std::string((const char *)sqlite3_column_blob(query, 0), sqlite3_column_bytes(query, 0));
            result = ERR_NO_ERROR;
        } else {
            result = ERR_KEY_NOT_FOUND;
            std::cerr << "Key with id " << keyID << " not found" << std::endl;
        }
        sqlite3_finalize(query);
    }

//    closeDatabase(kdb, user.name, false);
    return result;
}


//------------------------------------------------------------------------------

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

    activeDBs.insert(std::make_pair(user, db));
    return true;
}

void VhsmStorage::closeDatabase(const std::string &user) {
    UserDBMap::iterator i = activeDBs.find(user);
    if(i == activeDBs.end()) return;

    std::string tmpdbPath = root + "tmp/" + user + ".db";

    if(i->second.dirty) {
        //dump current memory database, maybe should make backup
        encryptFile(tmpdbPath, root + user + "/kdb", i->second.key);
//        encryptFile(root + user + "/kdb.tmp", root + user + "/kdb", db.key);
    }

    sqlite3_close(i->second.db);

    activeDBs.erase(i);

    FSUtils::removeFile(tmpdbPath);

    std::cout << "DB closed | user: " << user << std::endl;

    /*
    if(db.db) {
        sqlite3_close(db.db);
        if(reencrypt) {
            //need to create backup
            encryptFile(root + user + "/kdb.tmp", root + user + "/kdb", db.key);
        }
    }
    FSUtils::removeFile(root + user + "/kdb.tmp");
    */
}

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

bool VhsmStorage::proccessFile(const std::string &inPath, const std::string &outPath, const std::string &key, bool enc) const {
    std::ifstream fileIn(inPath.c_str(), std::ifstream::in | std::ifstream::binary);
    if(!fileIn.is_open()) return false;

    char buf[BUF_SIZE];
    std::string content;
    while(!fileIn.eof()) {
        size_t ln = fileIn.readsome(buf, BUF_SIZE);
        content.append(std::string(buf, ln));
        if(ln < BUF_SIZE) break;
    }
    fileIn.close();

    std::string result;
    if(!(enc ? encrypt(content, key, result) : decrypt(content, key, result))) return false;

    std::ofstream fileOut(outPath.c_str(), std::ofstream::out | std::ofstream::binary);
    if(!fileOut.is_open()) return false;
    fileOut << result;
    fileOut.close();

    return true;
}

bool VhsmStorage::decryptFileInMemory(const std::string &inPath, const std::string &key, std::string &output) const {
    std::ifstream fileIn(inPath.c_str(), std::ifstream::in | std::ifstream::binary);
    if(!fileIn.is_open()) return false;

    char buf[BUF_SIZE];
    std::string content;
    while(!fileIn.eof()) {
        size_t ln = fileIn.readsome(buf, BUF_SIZE);
        content.append(std::string(buf, ln));
        if(ln < BUF_SIZE) break;
    }
    fileIn.close();

    std::cout << "Start decrypting with key: " << base64(key) << std::endl;

    return decrypt(content, key, output);
}

bool VhsmStorage::encryptFileFromMemory(const std::string &input, const std::string &key, const std::string &outPath) const {
    std::string result;
    if(!encrypt(input, key, result)) return false;

    std::ofstream fileOut(outPath.c_str(), std::ofstream::out | std::ofstream::binary);
    if(!fileOut.is_open()) return false;
    fileOut << result;
    fileOut.close();
    return true;
}

//------------------------------------------------------------------------------

bool VhsmStorage::initKeyDatabase(const std::string &path) const {
    bool result = false;
    sqlite3 *kdb = 0;
    sqlite3_stmt *query = 0;

    if(sqlite3_open(path.c_str(), &kdb) != SQLITE_OK) goto cleanup;

    static const std::string qtext = "CREATE TABLE Keys (KeyID CHAR(32) not null,"
            "Key BLOB not null,"
            "Purpose INT4 not null,"
            "ImportDate DATETIME not null,"
            "CONSTRAINT PK_KEYS primary key (KeyID)"
            ");"
            "CREATE UNIQUE INDEX Keys_PK on Keys (KeyID);";

    sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL);

    if(sqlite3_step(query) != SQLITE_DONE) {
        std::cerr << "SQL Error: " << sqlite3_errmsg(kdb) << std::endl;
        goto cleanup;
    }

    result = true;

cleanup:
    sqlite3_finalize(query);
    sqlite3_close(kdb);
    if(!result) FSUtils::removeFile(path);
    return result;
}

bool VhsmStorage::hasKeyId(sqlite3 *db, const std::string &keyID) const {
    static const std::string qtext = "SELECT KeyID FROM Keys WHERE KeyID = ?";
    sqlite3_stmt *query = 0;
    sqlite3_prepare_v2(db, qtext.c_str(), qtext.size(), &query, NULL);
    sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);

    bool result = true;
    int qres = sqlite3_step(query);
    switch(qres) {
    case SQLITE_ROW:    //we already have this key id in db
        result = true;
        break;
    case SQLITE_DONE:   //new key id
        result = false;
        break;
    default:
        std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(query);
    return result;
}

bool VhsmStorage::insertKey(sqlite3 *db, const std::string &keyID, const std::string &key, int purpose) const {
    static const std::string qtext = "INSERT INTO Keys (KeyID, Key, Purpose, ImportDate) VALUES (?, ?, ?, ?)";
    sqlite3_stmt *query = 0;
    sqlite3_prepare_v2(db, qtext.c_str(), qtext.size(), &query, NULL);
    sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
    sqlite3_bind_blob(query, 2, key.data(), key.size(), SQLITE_STATIC);
    sqlite3_bind_int(query, 3, purpose);
    sqlite3_bind_int64(query, 4, time(0));

    bool result = false;
    int qres = sqlite3_step(query);
    switch(qres) {
    case SQLITE_DONE:
        result = true;
        break;
    default:
        std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(query);
    return result;
}

//------------------------------------------------------------------------------

VhsmStorage::PKDFInfo VhsmStorage::generatePKDFOptions(int purpose) const {
    PKDFInfo info;
    info.iters = 512;
    info.purpose = purpose;
    info.salt.resize(128);

    rnd.GenerateBlock((byte*)info.salt.data(), info.salt.size());

    return info;
}

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


/**********************************************************************************/

/*
VhsmStorage::VhsmStorage() : storage(0) {
    storage = EncryptedStorageFactory().create_storage();
}

VhsmStorage::~VhsmStorage() {
    delete storage;
}

bool VhsmStorage::hasUser(const VhsmUser &user) const {
    return storage->namespace_accessible(user.name, user.key);
}

PKeyType VhsmStorage::getUserPrivateKey(const VhsmUser &user, const std::string &keyId) const {
    ES::Namespace &ns = storage->load_namespace(user.name, user.key);
    ES::SecretObject pkey = ns.load_object(keyId);
    storage->unload_namespace(ns);
    return pkey;
}

ErrorCode VhsmStorage::createKey(const VhsmUser &user, const std::string &keyId, const std::string &keyData) {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    ErrorCode res = uns.store_object(keyId, keyData.data(), keyData.size()) ? ERR_NO_ERROR : ERR_KEY_ID_OCCUPIED;
    storage->unload_namespace(uns);
    return res;
}

ErrorCode VhsmStorage::deleteKey(const VhsmUser &user, const std::string &keyId) {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    ErrorCode res = uns.delete_object(keyId) ? ERR_NO_ERROR : ERR_KEY_NOT_FOUND;
    storage->unload_namespace(uns);
    return res;
}

std::vector<std::string> VhsmStorage::getKeyIds(const VhsmUser &user) const {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    std::vector<std::string> ids = uns.list_object_names();
    storage->unload_namespace(uns);
    return ids;
}
*/
