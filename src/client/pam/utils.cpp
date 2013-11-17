#include "utils.h"

#include <security/pam_ext.h>

#include <shadow.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include <sys/stat.h>

// this functions taken from pam_unix

#define SH_TMPFILE "/etc/nshadow"

int lock_pwdf() {
    int i = 0;
    int retval;
    while((retval = lckpwdf()) != 0 && i < 100) {
        usleep(1000);
        i++;
    }
    return (retval != 0 ? PAM_AUTHTOK_LOCK_BUSY : PAM_SUCCESS);
}

void unlock_pwdf() {
    ulckpwdf();
}

int unix_update_shadow(pam_handle_t *pamh, const char *forwho, char *towhat) {
    struct spwd spwdent, *stmpent = NULL;
    struct stat st;
    FILE *pwfile, *opwfile;
    int err = 0;
    int oldmask = umask(077);
    int wroteentry = 0;

    if(lock_pwdf() != PAM_SUCCESS) return PAM_AUTHTOK_LOCK_BUSY;

    pwfile = fopen(SH_TMPFILE, "w");
    umask(oldmask);
    if (pwfile == NULL) {
        err = 1;
        goto done;
    }

    opwfile = fopen("/etc/shadow", "r");
    if (opwfile == NULL) {
        fclose(pwfile);
        err = 1;
        goto done;
    }

    if (fstat(fileno(opwfile), &st) == -1) {
        fclose(opwfile);
        fclose(pwfile);
        err = 1;
        goto done;
    }

    if (fchown(fileno(pwfile), st.st_uid, st.st_gid) == -1) {
        fclose(opwfile);
        fclose(pwfile);
        err = 1;
        goto done;
    }
    if (fchmod(fileno(pwfile), st.st_mode) == -1) {
        fclose(opwfile);
        fclose(pwfile);
        err = 1;
        goto done;
    }

    stmpent = fgetspent(opwfile);
    while(stmpent) {
        if(!strcmp(stmpent->sp_namp, forwho)) {
            stmpent->sp_pwdp = towhat;
            stmpent->sp_lstchg = time(NULL) / (60 * 60 * 24);
            wroteentry = 1;
        }

        if(putspent(stmpent, pwfile)) {
            err = 1;
            break;
        }

        stmpent = fgetspent(opwfile);
    }

    fclose(opwfile);

    if (!wroteentry && !err) {
        spwdent.sp_namp = (char*)forwho;
        spwdent.sp_pwdp = towhat;
        spwdent.sp_lstchg = time(NULL) / (60 * 60 * 24);
        spwdent.sp_min = spwdent.sp_max = spwdent.sp_warn = spwdent.sp_inact = spwdent.sp_expire = -1;
        spwdent.sp_flag = (unsigned long)-1l;
        if(putspent(&spwdent, pwfile)) {
            err = 1;
        }
    }

    if(fflush(pwfile) || fsync(fileno(pwfile))) err = 1;
    if(fclose(pwfile)) err = 1;

done:
    if(!err) {
        if (!rename(SH_TMPFILE, "/etc/shadow")) {
            pam_syslog(pamh, LOG_NOTICE, "password changed for %s", forwho);
        }
        else err = 1;
    }

    unlock_pwdf();

    if(!err) {
        return PAM_SUCCESS;
    } else {
        unlink(SH_TMPFILE);
        return PAM_AUTHTOK_ERR;
    }
}

//--------------------------------------------------------------------------------------

#include <vector>
#include <algorithm>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>

std::string generate_block(int size) {
    std::vector<char> b(size);
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock((byte*)b.data(), b.size());
    return std::string(b.data(), b.size());
}

std::string to_base64(const char *str, unsigned int size) {
    std::string bs;
    CryptoPP::StringSource((const byte*)str, size, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(bs)));
    return bs;
}

std::string to_base64(const char *str) {
    std::string bs;
    CryptoPP::StringSource((const byte*)str, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(bs)));
    return bs;
}

char *apply_crypt(const char *raw_key, unsigned int key_size) {
    std::string key = to_base64(raw_key, key_size);
    std::string salt = generate_block(16);
    salt = to_base64(salt.data(), salt.size());
    salt.resize(16);
    salt = "$6$" + salt;
    std::replace(salt.begin(), salt.end(), '=', '.');
    std::replace(salt.begin(), salt.end(), '+', '.');
    return crypt(key.c_str(), salt.c_str());
}

char *apply_crypt(const char *raw_key, unsigned int key_size, const char *hash) {
    std::string key = to_base64(raw_key, key_size);
    return crypt(key.c_str(), hash);
}
