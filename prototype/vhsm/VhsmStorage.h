#ifndef VHSMSTORAGE_H
#define VHSMSTORAGE_H

#include "common.h"
#include <vector>

#include <sqlite3.h>

#include <crypto++/osrng.h>

#define USER_KEY_LENGTH 32
#define KEY_ID_LENGTH 16
#define BUF_SIZE 4096

class VhsmStorage {
public:
    VhsmStorage(const std::string &rootDir = "./data/");
    ~VhsmStorage();

    ErrorCode createUser(const std::string &name, const std::string &password);
    ErrorCode importKey(const VhsmUser &user, const std::string &key, std::string &keyID, int purpose = 0, bool nokeygen = false);
    ErrorCode importKey(const VhsmUser &user, const std::string &key, const std::string &keyID, int purpose = 0, bool nokeygen = false);
    ErrorCode deleteKey(const VhsmUser &user, const std::string &keyID);
    ErrorCode getUserPrivateKey(const VhsmUser &user, const std::string &keyID, std::string &pkey) const;
    int getKeyIdsCount(const VhsmUser &user) const;
    std::vector<std::string> getKeyIds(const VhsmUser &user) const;
    std::vector<VhsmKeyInfo> getKeyInfo(const VhsmUser &user, const std::string &keyID) const;

    bool loginUser(VhsmUser &user) const;

private:
    std::string root;
    mutable CryptoPP::AutoSeededRandomPool rnd;

    struct PKDFInfo {
        std::vector<char> salt;
        unsigned int iters;
        unsigned int purpose;
    };

    struct DB {
        DB() : db(0), key("") {}
        //maybe we should reset key's buffer in destructor

        sqlite3 *db;
        std::string key;
    };

    //------------------------------------------------------------------------------

    DB openDatabase(const std::string &user, const std::string &password) const;
    void closeDatabase(DB &db, const std::string &user, bool reencrypt) const;

    //------------------------------------------------------------------------------

    bool encrypt(const std::string &data, const std::string &key, std::string &result) const;
    bool decrypt(const std::string &data, const std::string &key, std::string &result) const;

    bool proccessFile(const std::string &inPath, const std::string &outPath, const std::string &key, bool enc) const;

    bool inline encryptFile(const std::string &inPath, const std::string &outPath, const std::string &key) const {
        return proccessFile(inPath, outPath, key, true);
    }

    bool inline decryptFile(const std::string &inPath, const std::string &outPath, const std::string &key) const {
        return proccessFile(inPath, outPath, key, false);
    }

    //------------------------------------------------------------------------------

    bool initKeyDatabase(const std::string &path) const;
    bool hasKeyId(sqlite3 *db, const std::string &keyID) const;
    bool insertKey(sqlite3 *db, const std::string &keyID, const std::string &key, int purpose) const;

    //------------------------------------------------------------------------------

    std::string getDerivedKey(const PKDFInfo &info, const std::string &password) const;

    PKDFInfo generatePKDFOptions(int purpose = 0) const;
    bool loadPKDFOptions(const std::string &path, PKDFInfo &info) const;
    bool savePKDFOptions(const std::string &path, const PKDFInfo &info) const;

    std::string generateBlock(size_t size) const;
    std::string base64(const std::string &str) const;

};

#endif // VHSMSTORAGE_H
