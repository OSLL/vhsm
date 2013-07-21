#include "VhsmStorage.h"

#include <fstream>

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

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
    if(dbPath.empty() || dbPath.at(dbPath.size() - 1) != '/') dbPath.push_back('/');
    dbPath += "keys.db";
}

VhsmStorage::~VhsmStorage() {
}

void VhsmStorage::prepareQueries() {
}

//------------------------------------------------------------------------------

bool VhsmStorage::initDatabase() {
    return true;
}

bool VhsmStorage::loginUser(const VhsmUser &user) {
    return true;
}

void VhsmStorage::logoutUser(const VhsmUser &user) {
}

ErrorCode VhsmStorage::createUser(const std::string &name, const std::string &password) {
    return ERR_NO_ERROR;
}

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, std::string &keyID, int purpose, bool nokeygen) {
    return ERR_NO_ERROR;
}

ErrorCode VhsmStorage::importKey(const VhsmUser &user, const std::string &key, const std::string &keyID, int purpose, bool nokeygen) {
    std::string copyKeyID(keyID);
    return importKey(user, key, copyKeyID, purpose, nokeygen);
}

ErrorCode VhsmStorage::deleteKey(const VhsmUser &user, const std::string &keyID) {
    return ERR_NO_ERROR;
}

int VhsmStorage::getKeyIdsCount(const VhsmUser &user) const {
    return 1;
}

std::vector<std::string> VhsmStorage::getKeyIds(const VhsmUser &user) const {
    std::vector<std::string> ids;
    ids.push_back("123");
    return ids;
}

std::vector<VhsmKeyInfo> VhsmStorage::getKeyInfo(const VhsmUser &user, const std::string &keyID) const {
    std::vector<VhsmKeyInfo> kinfo;
    kinfo.push_back(VhsmKeyInfo());
    return kinfo;
}

ErrorCode VhsmStorage::getUserPrivateKey(const VhsmUser &user, const std::string &keyID, std::string &pkey) const {
    return ERR_NO_ERROR;
}

//------------------------------------------------------------------------------

std::string VhsmStorage::getDerivedKey(const PKDFInfo &info, const std::string &password) const {
    return "";
}

bool VhsmStorage::encrypt(const std::string &data, const std::string &key, std::string &result) const {
    return true;
}

bool VhsmStorage::decrypt(const std::string &data, const std::string &key, std::string &result) const {
    return true;
}

bool VhsmStorage::hasKeyId(const std::string &keyID, int userID) const {
    return false;
}

bool VhsmStorage::insertKey(const std::string &keyID, int userID, const std::string &key, int purpose) {
    return true;
}

VhsmStorage::PKDFInfo VhsmStorage::generatePKDFOptions(int purpose) const {
    return PKDFInfo(generateBlock(128), 512, purpose);
}

std::string VhsmStorage::generateBlock(size_t size) const {
    return "";
}

std::string VhsmStorage::base64(const std::string &str) const {
    return "";
}
