#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <ctime>

#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/key_mgmt.h"
#include "vhsm_api_prototype/mac.h"
#include "vhsm_api_prototype/digest.h"

#define BUF_SIZE        4096
#define BUF_TIME_SIZE   256

#define HELP_BASE       1
#define HELP_GENERATE   2
#define HELP_IMPORT     4
#define HELP_KEYINFO    8
#define HELP_DELETE     16
#define HELP_HMAC       32

#define EXIT_OK         0
#define EXIT_BAD_ARGS   1
#define EXIT_VHSM_ERR   2

#define CMD_UNKNOWN     0
#define CMD_HELP        1
#define CMD_GENERATE    2
#define CMD_IMPORT      3
#define CMD_KEYINFO     4
#define CMD_DELETE      5
#define CMD_HMAC        6

//------------------------------------------------------------------------------

void showHelp(int sections) {
    std::cout << "VHSM administration tool" << std::endl;
    if(sections & HELP_BASE) {
        std::cout << "List of available commands. Use 'vhsm_admin <command> help' for details." << std::endl;
        std::cout << "generate - generates key with the given key length and optional key purpose" << std::endl;
        std::cout << "           and key id; returns the key id" << std::endl;
        std::cout << "import   - imports key or key-file with the given key length and optional" << std::endl;
        std::cout << "           key purpose and key id; returns the key id" << std::endl;
        std::cout << "delete   - deletes key with the given key id" << std::endl;
        std::cout << "keyinfo  - prints information about user keys" << std::endl;
        std::cout << "hmac     - computes hmac of the given file with the specified vhsm-key" << std::endl;
    }
    if(sections & HELP_GENERATE) {
        std::cout << "vhsm_admin generate <user> <password> <key length> [--purpose=value] [--keyid=id]" << std::endl;
        std::cout << "Generates key with the given key length." << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "purpose - integer key purpose; default value: 0;" << std::endl;
        std::cout << "keyid   - user-defined id for the new key;" << std::endl;
        std::cout << "VHSM generates key id if it's not specified. Returns id of the newly generated key" << std::endl;
    }
    if(sections & HELP_IMPORT) {
        std::cout << "vhsm_admin import <user> <password> <--file=path> [--purpose=value] [--keyid=id]" << std::endl;
        std::cout << "vhsm_admin import <user> <password> <--key=key> [--purpose=value] [--keyid=id]" << std::endl;
        std::cout << "Imports specified key or key-file." << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "purpose - key purpose; default value: 0;" << std::endl;
        std::cout << "keyid   - user-defined id for the new key;" << std::endl;
        std::cout << "VHSM generates key id if it's not specified. Returns id of the imported key" << std::endl;
    }
    if(sections & HELP_KEYINFO) {
        std::cout << "vhsm_admin keyinfo <user> <password> [ids...]" << std::endl;
        std::cout << "Prints information about keys for the specified user." << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "ids - return information only for the specified list of key ids" << std::endl;
    }
    if(sections & HELP_DELETE) {
        std::cout << "vhsm_admin delete <user> <password> <keyid>" << std::endl;
        std::cout << "Deletes key with the given key id" << std::endl;;
    }
    if(sections & HELP_HMAC) {
        std::cout << "vhsm_admin hmac <user> <password> <--file=path> <--keyid=id> [--md=sha1] [-b|-h]" << std::endl;
        std::cout << "Computes hmac for the specified file using specified key stored in vhsm" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "file  - path to the file" << std::endl;
        std::cout << "keyid - id of the key to use in hmac" << std::endl;
        std::cout << "md    - digest algorithm to use in hmac. Only SHA1 is currently supported" << std::endl;
        std::cout << "-b    - output in binary format" << std::endl;
        std::cout << "-h    - output in hex format (default)" << std::endl;
        std::cout << "Prints hmac digest of the file in hex or binary format" << std::endl;
    }
}

//------------------------------------------------------------------------------

/*
void create_user(int argc, char ** argv) {
    if (3 != argc) {
        show_help();
        return;
    }

    VhsmStorage storage(argv[0]);
    if(storage.createUser(argv[1], argv[2])) {
        std::cout << "Unable to create user" << std::endl;
    }
}

void init_root(int argc, char ** argv) {
    if (1 != argc) {
        show_help();
        return;
    }

    std::string path = argv[0];
    mkdir(path.c_str(), 0777);

    std::cout << "Initializing database at: " << path << std::endl;

    VhsmStorage storage(path);
    if(!storage.initDatabase()) {
        std::cout << "Unable to init database" << std::endl;
    }
}
*/

//------------------------------------------------------------------------------

static int commandId(const std::string &str) {
    if(str == "help" || str == "--help" || str == "-h") return CMD_HELP;
    if(str == "generate") return CMD_GENERATE;
    if(str == "import") return CMD_IMPORT;
    if(str == "keyinfo") return CMD_KEYINFO;
    if(str == "delete") return CMD_DELETE;
    if(str == "hmac") return CMD_HMAC;
    return CMD_UNKNOWN;
}

//------------------------------------------------------------------------------

static bool vhsmEnter(vhsm_session &s, const std::string &username, const std::string &password) {
    if(vhsm_start_session(&s) != ERR_NO_ERROR) {
        std::cout << "Error: unable to start vhsm session" << std::endl;
        return false;
    }

    vhsm_credentials user;
    memset(user.username, 0, sizeof(user.username));
    memset(user.password, 0, sizeof(user.password));
    strncpy(user.username, username.c_str(), std::min(username.size(), sizeof(user.username)));
    strncpy(user.password, password.c_str(), std::min(password.size(), sizeof(user.password)));

    if(vhsm_login(s, user) != ERR_NO_ERROR) {
        std::cout << "Error: unable to login user" << std::endl;
        vhsm_end_session(s);
        return false;
    }

    return true;
}

static void vhsmExit(vhsm_session &s) {
    vhsm_logout(s);
    vhsm_end_session(s);
}

static vhsm_key_id vhsmGetKeyID(const std::string &keyID) {
    vhsm_key_id id;
    memset(id.id, 0, sizeof(id.id));
    if(!keyID.empty()) strncpy((char*)id.id, keyID.c_str(), std::min(keyID.size(), sizeof(id.id)));
    return id;
}

static std::string vhsmErrorCode(int ec) {
    switch(ec) {
    case ERR_NO_ERROR: return "no error";
    case ERR_KEY_ID_OCCUPIED: return "key id occupied";
    case ERR_KEY_NOT_FOUND: return "key id not found";
    case ERR_BAD_BUFFER_SIZE: return "bad buffer size";
    case ERR_BAD_SESSION: return "bad session";
    case ERR_NOT_AUTHORIZED: return "user is not authorized";
    case ERR_BAD_CREDENTIALS: return "bad username or password";
    case ERR_BAD_DIGEST_METHOD: return "unsupported digest method requested";
    case ERR_MAC_INIT: return "unable to init mac";
    case ERR_BAD_MAC_METHOD: return "unsupported mac method requested";
    case ERR_MAC_NOT_INITIALIZED: return "mac context is not initialized";
    case ERR_BAD_ARGUMENTS: return "bad arguments";
    default: return "unknown error";
    }
}

//------------------------------------------------------------------------------

static int generateKey(int argc, char **argv) {
    if(argc < 3 || argc > 5) {
        showHelp(HELP_GENERATE);
        return EXIT_BAD_ARGS;
    }

    int keyLength = std::strtol(argv[2], NULL, 10);
    int keyPurpose = 0;
    std::string keyID = "";

    for(int i = 3; i < argc; ++i) {
        std::string arg(argv[i]);
        size_t vpos = arg.find('=');
        if(vpos == std::string::npos && arg.at(0) == '-') {
            std::cout << "Error: value for option \'" << arg << "\' is not specified" << std::endl;
            return EXIT_BAD_ARGS;
        } else if(vpos == std::string::npos) {
            std::cout << "Error: unknown option: " << argv[i] << std::endl;
            return EXIT_BAD_ARGS;
        }
        if(arg.find("--purpose=") == 0) keyPurpose = std::strtol(argv[i] + vpos + 1, NULL, 10);
        else if(arg.find("--keyid=") == 0) keyID = arg.substr(vpos + 1);
        else {
            std::cout << "Error: unknown option: " << argv[i] << std::endl;
            showHelp(HELP_GENERATE);
            return EXIT_BAD_ARGS;
        }
    }

    vhsm_key_id kid = vhsmGetKeyID(keyID);

    vhsm_session s;
    if(!vhsmEnter(s, argv[0], argv[1])) return EXIT_VHSM_ERR;

    int exitCode = EXIT_OK;
    int res = vhsm_key_mgmt_generate_key(s, &kid, keyLength, keyPurpose);
    if(res != ERR_NO_ERROR) {
        std::cout << "Error: unable to generate key: " << vhsmErrorCode(res) << std::endl;
        exitCode = EXIT_VHSM_ERR;
    } else {
        std::cout << kid.id << std::endl;
    }

    vhsmExit(s);
    return exitCode;
}

//------------------------------------------------------------------------------

static int importKey(int argc, char **argv) {
    if(argc < 3 || argc > 5) {
        showHelp(HELP_IMPORT);
        return EXIT_BAD_ARGS;
    }

    int keyPurpose = 0;
    std::string keyID = "";
    std::string realKey = "";
    std::string keyPath = "";

    for(int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        size_t vpos = arg.find('=');
        if(vpos == std::string::npos && arg.at(0) == '-') {
            std::cout << "Error: value for option \'" << arg << "\' is not specified" << std::endl;
            return EXIT_BAD_ARGS;
        } else if(vpos == std::string::npos) {
            std::cout << "Error: unknown option: " << argv[i] << std::endl;
            return EXIT_BAD_ARGS;
        }
        if(arg.find("--purpose=") == 0) keyPurpose = std::strtol(argv[i] + vpos + 1, NULL, 10);
        else if(arg.find("--keyid=") == 0) keyID = arg.substr(vpos + 1);
        else if(arg.find("--key=") == 0) realKey = arg.substr(vpos + 1);
        else if(arg.find("--file=") == 0) keyPath = arg.substr(vpos + 1);
        else {
            std::cout << "Error: unknown argument: " << argv[i] << std::endl;
            showHelp(HELP_IMPORT);
            return EXIT_BAD_ARGS;
        }
    }

    if((!realKey.empty() && !keyPath.empty()) || (realKey.empty() && keyPath.empty())) {
        std::cout << "Error: bad arguments" << std::endl;
        showHelp(HELP_IMPORT);
        return EXIT_BAD_ARGS;
    }

    if(!keyPath.empty()) {
        std::ifstream keyIn(keyPath.c_str(), std::ifstream::in | std::ifstream::binary);
        if(!keyIn.is_open()) {
            std::cout << "Error: unable to open key file: " << keyPath.c_str() << std::endl;
            return EXIT_BAD_ARGS;
        }
        char buf[BUF_SIZE];
        while(!keyIn.eof()) {
            size_t ln = keyIn.readsome(buf, BUF_SIZE);
            if(ln == 0) break;
            realKey.append(std::string(buf, ln));
        }
        keyIn.close();
    }

    if(realKey.size() > VHSM_MAX_DATA_LENGTH) {
        std::cout << "Error: unsupported key length; current max key length: " << VHSM_MAX_DATA_LENGTH << " bytes" << std::endl;
        return EXIT_BAD_ARGS;
    }

    vhsm_session s;
    if(!vhsmEnter(s, argv[0], argv[1])) return EXIT_VHSM_ERR;

    vhsm_key key;
    vhsm_key_id newKeyID;
    key.id = vhsmGetKeyID(keyID);
    key.key_data = const_cast<char*>(realKey.data());
    key.data_size = realKey.size();

    int exitCode = EXIT_OK;
    int res = vhsm_key_mgmt_create_key(s, key, &newKeyID, keyPurpose);
    if(res != ERR_NO_ERROR) {
        std::cout << "Error: unable to generate key: " << vhsmErrorCode(res) << std::endl;
        exitCode = EXIT_VHSM_ERR;
    } else {
        std::cout << newKeyID.id << std::endl;
    }

    vhsmExit(s);
    return exitCode;
}

//------------------------------------------------------------------------------

static std::string timeToString(uint64_t secs) {
    tm *rawTime = gmtime((time_t*)&secs);
    char timeBuf[BUF_TIME_SIZE];
    size_t ln = std::strftime(timeBuf, BUF_TIME_SIZE, "%FT%T%z", rawTime);
    return std::string(timeBuf, ln);
}

static int getKeyInfo(int argc, char **argv) {
    if(argc < 2) {
        showHelp(HELP_KEYINFO);
        return EXIT_BAD_ARGS;
    }

    vhsm_session s;
    if(!vhsmEnter(s, argv[0], argv[1])) return EXIT_VHSM_ERR;

    vhsm_key_info *keyInfo = 0;
    unsigned int keyCount = 0;
    int exitCode = EXIT_VHSM_ERR;
    if(argc == 2) {
        int res = vhsm_key_mgmt_get_key_info(s, NULL, &keyCount);
        if(res != ERR_NO_ERROR) {
            std::cout << "Error: unable to get key count: " << vhsmErrorCode(res) << std::endl;
            goto vhsm_exit;
        }
        if(keyCount == 0) {
            std::cout << "No keys found for user: " << argv[0] << std::endl;
            goto vhsm_exit;
        }
        keyInfo = new vhsm_key_info[keyCount];
        res = vhsm_key_mgmt_get_key_info(s, keyInfo, &keyCount);
        if(res != ERR_NO_ERROR) {
            std::cout << "Error: unable to get key info: " << vhsmErrorCode(res) << std::endl;
            keyCount = 0;
        } else {
            exitCode = EXIT_OK;
        }
    } else {
        keyCount = argc - 2;
        keyInfo = new vhsm_key_info[keyCount];
        unsigned int realKeyCount = 0;
        for(unsigned int i = 0; i < keyCount; ++i) {
            vhsm_key_id keyID;
            memset(keyID.id, 0, sizeof(keyID.id));
            strncpy((char*)keyID.id, argv[i + 2], std::min(strlen(argv[i + 2]), sizeof(keyID.id)));
            if(vhsm_key_mgmt_get_key_info(s, keyID, &keyInfo[realKeyCount]) != ERR_NO_ERROR) {
                std::cout << "Error: key with id \'" << keyID.id << "\' not found" << std::endl;
            } else {
                realKeyCount++;
            }
        }
        keyCount = realKeyCount;
    }

    if(keyCount > 0) std::cout << "Key ID\t\t\tLength\tPurpose\tImport date" << std::endl;

    for(unsigned int i = 0; i < keyCount; ++i) {
        std::cout << keyInfo[i].key_id.id << "\t";
        size_t idLength = strlen((char*)keyInfo[i].key_id.id);
        if(idLength < 16) std::cout << "\t";
        if(idLength < 8) std::cout << "\t";
        std::cout << keyInfo[i].length << "\t";
        std::cout << keyInfo[i].purpose << "\t";
        std::cout << timeToString(keyInfo[i].import_date) << std::endl;
    }

    delete[] keyInfo;
vhsm_exit:
    vhsmExit(s);
    return exitCode;
}

//------------------------------------------------------------------------------

static int deleteKey(int argc, char **argv) {
    if(argc != 3) {
        showHelp(HELP_DELETE);
        return EXIT_BAD_ARGS;
    }

    vhsm_session s;
    if(!vhsmEnter(s, argv[0], argv[1])) return EXIT_VHSM_ERR;

    vhsm_key_id keyId = vhsmGetKeyID(argv[2]);

    int exitCode = EXIT_OK;
    int res = vhsm_key_mgmt_delete_key(s, keyId);
    if(res != ERR_NO_ERROR) {
        std::cout << "Key with id '" << argv[2] << "' not found" << std::endl;
        exitCode = EXIT_VHSM_ERR;
    } else {
        std::cout << "Key with id '" << argv[2] << "' was successfully deleted" << std::endl;
    }

    vhsmExit(s);
    return exitCode;
}

//------------------------------------------------------------------------------

static bool setDigest(vhsm_mac_method &mac, const std::string &digestName) {
    if(digestName == "sha1") {
        vhsm_digest_method *dm = new vhsm_digest_method;
        dm->digest_method = VHSM_DIGEST_SHA1;
        dm->method_params = NULL;
        mac.method_params = dm;
        return true;
    }
    return false;
}

static void freeDigest(vhsm_mac_method &mac, const std::string &digestName) {
    if(digestName == "sha1") {
        delete (vhsm_digest_method*)mac.method_params;
    }
}

static int computeHMAC(int argc, char **argv) {
    if(argc < 4 || argc > 6) {
        showHelp(HELP_HMAC);
        return EXIT_BAD_ARGS;
    }

    std::string keyID = "";
    std::string filePath = "";
    std::string mdAlgName = "sha1";
    bool binOutput = false;

    for(int i = 2; i < argc; ++i) {
        std::string arg(argv[i]);
        if(arg == "-b") {
            binOutput = true;
            continue;
        } else if(arg == "-h") {
            binOutput = false;
            continue;
        }

        size_t vpos = arg.find('=');
        if(vpos == std::string::npos && arg.at(0) == '-') {
            std::cout << "Error: value for option \'" << arg << "\' is not specified" << std::endl;
            return EXIT_BAD_ARGS;
        } else if(vpos == std::string::npos) {
            std::cout << "Error: unknown option: " << arg << std::endl;
            return EXIT_BAD_ARGS;
        }
        if(arg.find("--keyid=") == 0) keyID = arg.substr(vpos + 1);
        else if(arg.find("--file=") == 0) filePath = arg.substr(vpos + 1);
        else if(arg.find("--md=") == 0) mdAlgName = arg.substr(vpos + 1);
        else {
            std::cout << "Error: unknown argument: " << argv[i] << std::endl;
            return EXIT_BAD_ARGS;
        }
    }

    if(filePath.empty() || keyID.empty()) {
        std::cout << "Error one of the required arguments is not specified" << std::endl;
        return EXIT_BAD_ARGS;
    }

    vhsm_key_id vkid = vhsmGetKeyID(keyID);
    vhsm_mac_method macMethod = {VHSM_MAC_HMAC, 0, vkid};
    if(!setDigest(macMethod, mdAlgName)) {
        std::cout << "Error: unsupported digest method: " << mdAlgName << std::endl;
        return EXIT_BAD_ARGS;
    }

    vhsm_session s;
    if(!vhsmEnter(s, argv[0], argv[1])) {
        freeDigest(macMethod, mdAlgName);
        return EXIT_VHSM_ERR;
    }

    std::ifstream fileIn;
    unsigned int md_size = 0;
    unsigned char *md = NULL;
    int exitCode = EXIT_VHSM_ERR;

    int res = vhsm_mac_init(s, macMethod);
    if(res != ERR_NO_ERROR) {
        std::cout << "Error: unable to init mac: " << vhsmErrorCode(res) << std::endl;
        goto cleanup;
    }

    fileIn.open(filePath.c_str(), std::ifstream::in | std::ifstream::binary);
    if(!fileIn.is_open()) {
        std::cout << "Error: unable to open file: " << filePath << std::endl;
        exitCode = EXIT_BAD_ARGS;
        goto cleanup;
    }

    char buf[VHSM_MAX_DATA_LENGTH];
    while(!fileIn.eof()) {
        size_t ln = fileIn.readsome(buf, VHSM_MAX_DATA_LENGTH);
        if(ln == 0) break;
        res = vhsm_mac_update(s, (unsigned char*)buf, ln);
        if(res != ERR_NO_ERROR) {
            std::cout << "Error: vhsm_mac_update: " << vhsmErrorCode(res) << std::endl;
            fileIn.close();
            goto cleanup;
        }
    }
    fileIn.close();

    res = vhsm_mac_end(s, NULL, &md_size);
    if(res != ERR_BAD_BUFFER_SIZE) {
        std::cout << "Error: failed to obtain mac size" << std::endl;
        goto cleanup;
    }

    md = new unsigned char[md_size];
    res = vhsm_mac_end(s, md, &md_size);
    if(res != ERR_NO_ERROR) {
        std::cout << "Error: failed to obtain mac: " << vhsmErrorCode(res) << std::endl;
        delete[] md;
        goto cleanup;
    }

    if(binOutput) {
        for(unsigned int i = 0; i < md_size; ++i) std::cout << md[i];
    } else {
        std::cout << "0x" << std::hex;
        for(unsigned int i = 0; i < md_size; ++i) std::cout << (int)md[i];
        std::cout << std::dec;
    }
    std::cout << std::endl;

    delete[] md;

    exitCode = EXIT_OK;

cleanup:
    freeDigest(macMethod, mdAlgName);
    vhsmExit(s);
    return exitCode;
}

//------------------------------------------------------------------------------

int main(int argc, char **argv) {
    if(argc < 3) {
        showHelp(HELP_BASE);
        return EXIT_BAD_ARGS;
    }

    switch(commandId(argv[1])) {
    case CMD_HELP:
        showHelp(HELP_BASE);
        break;
    case CMD_GENERATE:
        return generateKey(argc - 2, argv + 2);
    case CMD_IMPORT:
        return importKey(argc - 2, argv + 2);
    case CMD_DELETE:
        return deleteKey(argc - 2, argv + 2);
    case CMD_KEYINFO:
        return getKeyInfo(argc - 2, argv + 2);
    case CMD_HMAC:
        return computeHMAC(argc - 2, argv + 2);
    default:
        std::cout << "Unknown command: " << argv[1] << std::endl;
        showHelp(HELP_BASE);
    }

    return EXIT_OK;
}
