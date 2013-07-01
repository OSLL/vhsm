#include <iostream>
#include <fstream>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>

#include <sqlite3.h>

#include <crypto++/osrng.h>
#include <crypto++/integer.h>
#include <crypto++/pwdbased.h>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/base64.h>

#define USER_KEY_LENGTH 32
#define KEY_ID_LENGTH 16
#define BUF_SIZE 4096

namespace FSUtils {
    static bool getStat(const std::string &path, struct stat *s) {
        return stat(path.c_str(), s) == 0;
    }

    static bool isDirectoryExists(const std::string &path) {
        struct stat s;
        return getStat(path, &s) ? S_ISDIR(s.st_mode) : false;
    }

    static bool createDirectory(const std::string &path) {
        return mkdir(path.c_str(), 0777) == 0;
    }

    static bool removeDirectory(const std::string &path) {
        return rmdir(path.c_str()) == 0;
    }

    static bool removeFile(const std::string &path) {
        return unlink(path.c_str()) == 0;
    }
}

struct KeyInfo {
    std::string keyID;
    int purpose;
    size_t length;
    time_t importDate;
};

/**********************************************************************************/

class VhsmStorage {
    typedef std::string Key;

public:
    VhsmStorage(const std::string &rootDir = "./data/") : root(rootDir) {
        if(root.at(root.size() - 1) != '/') root.push_back('/');
    }

    ~VhsmStorage() {
    }

    //------------------------------------------------------------------------------

    bool createUser(const std::string &name, const std::string &password) {
        std::string basePath = root + name;
        if(!FSUtils::createDirectory(basePath)) return false;

        PKDFInfo info = generatePKDFOptions();
        std::string derivedKey = getDerivedKey(info, password);
//        std::cout << base64(derivedKey) << std::endl;

        if( initKeyDatabase(basePath + "/kdb") &&
            encryptFile(basePath + "/kdb", basePath + "/kdb", derivedKey) &&
            savePKDFOptions(basePath + "/pkdf", info))
        {
            return true;
        } else {
            FSUtils::removeFile(basePath + "/kdb");
            FSUtils::removeDirectory(basePath);
            return false;
        }
    }

    //------------------------------------------------------------------------------

    bool importKey(const std::string &user, const std::string &password, const std::string &key, std::string &keyID, int purpose = 0) {
        bool result = false;
        std::string realKey = key;

        DB kdb = openDatabase(user, password);
        if(!kdb.db) goto cleanup;

        if(!keyID.empty()) {
            //check uniqueness
            if(hasKeyId(kdb.db, keyID)) {
                std::cerr << "Non-unique key id specified" << std::endl;
                goto cleanup;
            }
        } else {
            //generate key id
            do {
                keyID = base64(generateBlock(KEY_ID_LENGTH)).substr(0, KEY_ID_LENGTH);
            } while(hasKeyId(kdb.db, keyID));
        }

        if(key.empty()) {
            realKey = generateBlock(USER_KEY_LENGTH);
//        } else if(key.size() != USER_KEY_LENGTH) {
//            std::cerr << "Bad key specified" << std::endl;
//            goto cleanup;
        } else {
            realKey = key;
        }

//        std::cout << "Importing key: " << base64(realKey) << std::endl;

        result = insertKey(kdb.db, keyID, realKey, purpose);

    cleanup:
        closeDatabase(kdb, user, result);
        return result;
    }

    //------------------------------------------------------------------------------

    bool deleteKey(const std::string &user, const std::string &password, const std::string &keyID) {
        static const std::string qtext = "DELETE FROM Keys WHERE KeyID = ?";
        bool result = false;

        DB kdb = openDatabase(user, password);
        if(kdb.db && hasKeyId(kdb.db, keyID)) {
            sqlite3_stmt *query = 0;
            sqlite3_prepare_v2(kdb.db, qtext.c_str(), qtext.size(), &query, NULL);
            sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
            int qres = sqlite3_step(query);
            switch(qres) {
            case SQLITE_DONE:
                result = true;
                break;
            default:
                std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(kdb.db) << std::endl;
            }
            sqlite3_finalize(query);
        }

        closeDatabase(kdb, user, result);
        return result;
    }

    //------------------------------------------------------------------------------

    int getKeyIdsCount(const std::string &user, const std::string &password) {
        static const std::string qtext = "SELECT count(KeyID) FROM Keys";
        int icount = -1;

        DB kdb = openDatabase(user, password);
        if(kdb.db) {
            sqlite3_stmt *query = 0;
            sqlite3_prepare_v2(kdb.db, qtext.c_str(), qtext.size(), &query, NULL);
            int qres = sqlite3_step(query);
            switch(qres) {
            case SQLITE_ROW:
                icount = sqlite3_column_int(query, 0);
                break;
            default:
                std::cerr << "Unexpected query result: " << qres << " | " << sqlite3_errmsg(kdb.db) << std::endl;
            }
            sqlite3_finalize(query);
        }

        closeDatabase(kdb, user, false);
        return icount;
    }

    //------------------------------------------------------------------------------

    std::vector<std::string> getKeyIds(const std::string &user, const std::string &password) {
        static const std::string qtext = "SELECT KeyID FROM Keys";
        std::vector<std::string> ids;

        DB kdb = openDatabase(user, password);
        if(kdb.db) {
            sqlite3_stmt *query = 0;
            sqlite3_prepare_v2(kdb.db, qtext.c_str(), qtext.size(), &query, NULL);
            while(sqlite3_step(query) == SQLITE_ROW) {
                ids.push_back((const char*)sqlite3_column_text(query, 0));
            }
            sqlite3_finalize(query);
        }

        closeDatabase(kdb, user, false);
        return ids;
    }

    //------------------------------------------------------------------------------

    bool getPrivateKey(const std::string &user, const std::string &password, const std::string &keyID, std::string &pkey) {
        static const std::string qtext = "SELECT Key FROM Keys WHERE KeyID = ?";
        bool result = false;

        DB kdb = openDatabase(user, password);
        if(kdb.db) {
            sqlite3_stmt *query = 0;
            sqlite3_prepare_v2(kdb.db, qtext.c_str(), qtext.size(), &query, NULL);
            sqlite3_bind_text(query, 1, keyID.c_str(), keyID.size(), SQLITE_STATIC);
            if(sqlite3_step(query) == SQLITE_ROW) {
                pkey = std::string((const char *)sqlite3_column_blob(query, 0), sqlite3_column_bytes(query, 0));
                result = true;
            } else {
                std::cerr << "Key with id " << keyID << " not found" << std::endl;
            }
            sqlite3_finalize(query);
        }

//        std::cout << "Extracted key: " << base64(pkey) << std::endl;

        closeDatabase(kdb, user, false);
        return result;
    }

    //------------------------------------------------------------------------------

    bool checkKey(const std::string &name, const std::string &password) const {
        PKDFInfo info;
        if(!loadPKDFOptions(root + name + "/pkdf", info)) return false;

        std::string derivedKey = getDerivedKey(info, password);
        std::cout << base64(derivedKey) << std::endl;

        return true;
    }

private:
    std::string root;
    mutable CryptoPP::AutoSeededRandomPool rnd;

    struct PKDFInfo {
        std::vector<char> salt;
        unsigned int iters;
        unsigned char purpose;
    };

    struct DB {
        DB() : db(0), key("") {}
        //maybe we should reset key's buffer in destructor

        sqlite3 *db;
        std::string key;
    };

    //------------------------------------------------------------------------------

    DB openDatabase(const std::string &user, const std::string &password) const {
        DB db;
        std::string basePath = root + user;
        std::string tmpdb = basePath + "/kdb.tmp";

        PKDFInfo info;
        if(!loadPKDFOptions(basePath + "/pkdf", info)) return db;
        db.key = getDerivedKey(info, password);

        if(decryptFile(basePath + "/kdb", tmpdb, db.key)) {
            if(sqlite3_open(tmpdb.c_str(), &db.db) != SQLITE_OK) {
                std::cerr << sqlite3_errmsg(db.db) << std::endl;
                sqlite3_close(db.db);
                db.key.clear();
            }
        } else db.key.clear();

        return db;
    }

    void closeDatabase(DB &db, const std::string &user, bool reencrypt) {
        if(db.db) {
            sqlite3_close(db.db);
            if(reencrypt) {
                //need to create backup
                encryptFile(root + user + "/kdb.tmp", root + user + "/kdb", db.key);
            }
        }
        FSUtils::removeFile(root + user + "/kdb.tmp");
    }

    //------------------------------------------------------------------------------

    std::string getDerivedKey(const PKDFInfo &info, const std::string &password) const {
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

    bool encrypt(const std::string &data, const Key &key, std::string &result) const {
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

    bool decrypt(const std::string &data, const Key &key, std::string &result) const {
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

    bool proccessFile(const std::string &inPath, const std::string &outPath, const Key &key, bool enc) const {
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

    bool inline encryptFile(const std::string &inPath, const std::string &outPath, const Key &key) const {
        return proccessFile(inPath, outPath, key, true);
    }

    bool inline decryptFile(const std::string &inPath, const std::string &outPath, const Key &key) const {
        return proccessFile(inPath, outPath, key, false);
    }

    //------------------------------------------------------------------------------

    bool initKeyDatabase(const std::string &path) {
        sqlite3 *kdb;
        if(sqlite3_open(path.c_str(), &kdb) != SQLITE_OK) {
            sqlite3_close(kdb);
            FSUtils::removeFile(path);
            return false;
        }

        static const std::string qtext = "CREATE TABLE Keys (KeyID CHAR(32) not null,"
                                        "Key BLOB not null,"
                                        "Purpose INT4 not null,"
                                        "ImportDate DATETIME not null,"
                                        "CONSTRAINT PK_KEYS primary key (KeyID)"
                                        ");"
                                        "CREATE UNIQUE INDEX Keys_PK on Keys (KeyID);";

        bool result = false;
        sqlite3_stmt *query = 0;
        if(sqlite3_prepare_v2(kdb, qtext.c_str(), qtext.size(), &query, NULL) != SQLITE_OK) {
            std::cerr << "SQL Error: " << sqlite3_errmsg(kdb) << std::endl;
            goto cleanup;
        }

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

    bool hasKeyId(sqlite3 *db, const std::string &keyID) const {
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

    bool insertKey(sqlite3 *db, const std::string &keyID, const std::string &key, int purpose) {
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

    PKDFInfo generatePKDFOptions(unsigned char purpose = 0) const {
        PKDFInfo info;
        info.iters = 512;
        info.purpose = purpose;
        info.salt.resize(128);

        rnd.GenerateBlock((byte*)info.salt.data(), info.salt.size());

        return info;
    }

    bool loadPKDFOptions(const std::string &path, PKDFInfo &info) const {
        std::ifstream file(path.c_str(), std::ifstream::in | std::ifstream::binary);
        if(!file.is_open()) return false;

        size_t saltsz;
        file >> info.iters >> info.purpose >> saltsz;
        info.salt.resize(saltsz);
        file.read(info.salt.data(), saltsz);
        file.close();
        return true;
    }

    bool savePKDFOptions(const std::string &path, const PKDFInfo &info) const {
        std::ofstream file(path.c_str(), std::ofstream::out | std::ofstream::binary);
        if(!file.is_open()) return false;
        std::string salt(info.salt.data(), info.salt.size());
        file << info.iters << info.purpose << salt.size() << salt;
        file.close();
        return true;
    }

    //------------------------------------------------------------------------------

    std::string generateBlock(size_t size) const {
        std::vector<char> b(size);
        rnd.GenerateBlock((byte*)b.data(), b.size());
        return std::string(b.data(), b.size());
    }

    std::string base64(const std::string &str) const {
        std::string bs;
        CryptoPP::StringSource(str, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(bs)));
        return bs;
    }
};

/**********************************************************************************/

int main(int argc, char *argv[]) {
    std::string user = "user";
    std::string password = "password";

    VhsmStorage storage;

    std::string keyID;
    storage.createUser(user, password);
    if(storage.importKey(user, password, "", keyID, 0)) {
        std::cout << "Generated key with keyID: " << keyID << std::endl;
    } else std::cout << "Some error occured" << std::endl;

    keyID = "1111111111111111";
    if(storage.importKey(user, password, "1", keyID, 0)) {
        std::cout << "Imported key with keyID: " << keyID << std::endl;
    } else std::cout << "Some error occured" << std::endl;

    std::cout << "Now db has " << storage.getKeyIdsCount(user, password) << " key ids: ";
    std::vector<std::string> ids = storage.getKeyIds(user, password);
    for(std::vector<std::string>::iterator i = ids.begin(); i != ids.end(); ++i) {
        std::cout << *i << " ";
    }
    std::cout << std::endl;

    std::string pkey;
    if(storage.getPrivateKey(user, password, keyID, pkey)) {
        std::cout << "Extracted pkey with keyID " << keyID << ": " << pkey << std::endl;
    } else std::cout << "Some error occured" << std::endl;

    if(storage.deleteKey(user, password, keyID)) {
        std::cout << "Delete key with keyID: " << keyID << ". Now db has " << storage.getKeyIdsCount(user, password) << " key ids" << std::endl;
    } else std::cout << "Some error occured" << std::endl;

    return 0;
}
