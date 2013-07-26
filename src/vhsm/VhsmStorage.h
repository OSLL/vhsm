#ifndef VHSMSTORAGE_H
#define VHSMSTORAGE_H

#include "common.h"
#include <vector>

#include <sqlite3.h>

#include <crypto++/osrng.h>

#include <sys/stat.h>

#define USER_KEY_LENGTH 32
#define KEY_ID_LENGTH 16
#define BUF_SIZE 4096

namespace FSUtils {
    bool getStat(const std::string &path, struct stat *s);
    bool isDirectoryExists(const std::string &path);
    bool isFileExists(const std::string &path);
    bool createDirectory(const std::string &path);
    bool createFile(const std::string &path);
    bool removeDirectory(const std::string &path);
    bool removeFile(const std::string &path);
}

class VhsmStorage {
public:
    VhsmStorage(const std::string &storageRoot = "./data/");
    ~VhsmStorage();

    bool initDatabase();
    ErrorCode createUser(const std::string &name, const std::string &password);
    ErrorCode importKey(const VhsmUser &user, const std::string &key, std::string &keyID, int purpose = 0, bool nokeygen = false);
    ErrorCode importKey(const VhsmUser &user, const std::string &key, const std::string &keyID, int purpose = 0, bool nokeygen = false);
    ErrorCode deleteKey(const VhsmUser &user, const std::string &keyID);
    ErrorCode getUserPrivateKey(const VhsmUser &user, const std::string &keyID, std::string &pkey) const;
    int getKeyIdsCount(const VhsmUser &user) const;
    std::vector<std::string> getKeyIds(const VhsmUser &user) const;
    std::vector<VhsmKeyInfo> getKeyInfo(const VhsmUser &user, const std::string &keyID) const;

    bool loginUser(const VhsmUser &user);
    void logoutUser(const VhsmUser &user);

private:
    std::string dbPath;
    sqlite3 *kdb;
    sqlite3_stmt *createUserQuery, *getUserQuery;
    sqlite3_stmt *hasKeyIdQuery, *insertKeyQuery, *deleteKeyQuery;
    sqlite3_stmt *getKeyIdsCountQuery, *getKeyIdsQuery;
    sqlite3_stmt *getKeyInfoQuery, *getKeysInfoQuery;
    sqlite3_stmt *getUserPrivateKeyQuery;
    mutable CryptoPP::AutoSeededRandomPool rnd;

    struct PKDFInfo {
        PKDFInfo(const std::string &s = "", unsigned int i = 512, unsigned int p = 0) : salt(s), iters(i), purpose(p) {}

        std::string salt;
        unsigned int iters;
        unsigned int purpose;
    };

    typedef std::map<std::string, std::pair<int, std::string> > UserKeyMap;
    UserKeyMap activeUsers;

    //------------------------------------------------------------------------------

    void prepareQueries();
//    bool openDatabase(const std::string &user, const std::string &password);
//    void closeDatabase(const std::string &user);

    //------------------------------------------------------------------------------

    bool encrypt(const std::string &data, const std::string &key, std::string &result) const;
    bool decrypt(const std::string &data, const std::string &key, std::string &result) const;

    //------------------------------------------------------------------------------

//    bool initKeyDatabase(const std::string &path) const;
    bool hasKeyId(const std::string &keyID, int userID) const;
    bool hasUser(const std::string &username) const;
    bool insertKey(const std::string &keyID, int userID, const std::string &key, int purpose);

    //------------------------------------------------------------------------------

    std::string getDerivedKey(const PKDFInfo &info, const std::string &password) const;

    PKDFInfo generatePKDFOptions(int purpose = 0) const;
//    bool loadPKDFOptions(const std::string &path, PKDFInfo &info) const;
//    bool savePKDFOptions(const std::string &path, const PKDFInfo &info) const;

    std::string generateBlock(size_t size) const;
    std::string base64(const std::string &str) const;

};

#endif // VHSMSTORAGE_H
