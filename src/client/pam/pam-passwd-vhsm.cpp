#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <syslog.h>
#include <shadow.h>
#include <unistd.h>
#include <security/pam_ext.h>

#include <string.h>
#include <stdlib.h>

#include "vhsm_api_prototype/common.h"
#include "vhsm_api_prototype/digest.h"
#include "vhsm_api_prototype/mac.h"

#include "utils.h"

#define BUF_SIZE 128

static void init_credentials(vhsm_credentials *c) {
    memset(c->username, 0, sizeof(c->username));
    memset(c->password, 0, sizeof(c->password));
}

static inline void set_cred_login(vhsm_credentials *c, const char *user) {
    size_t ulen = strlen(user);
    ulen = ulen < sizeof(c->username) ? ulen : sizeof(c->username);
    strncpy(c->username, user, ulen);
}

static inline void set_cred_passwd(vhsm_credentials *c, const char *passwd) {
    size_t plen = strlen(passwd);
    plen = plen < sizeof(c->password) ? plen : sizeof(c->password);
    strncpy(c->password, passwd, plen);
}

static void set_credentials(vhsm_credentials *c, const char *user, const char *passwd) {
    set_cred_login(c, user);
    set_cred_passwd(c, passwd);
}

//this functionality should be in vhsmapi
static vhsm_mac_method get_mac_method(const char *key_id) {
    vhsm_key_id vkid;
    memset(vkid.id, 0, sizeof(vkid.id));
    strncpy((char*)vkid.id, key_id, sizeof(vkid.id));

    vhsm_digest_method *dm = (vhsm_digest_method*)malloc(sizeof(vhsm_digest_method));
    dm->digest_method = VHSM_DIGEST_SHA1;
    dm->method_params = NULL;

    vhsm_mac_method m = {VHSM_MAC_HMAC, 0, vkid};
    m.method_params = dm;
    return m;
}

static void free_mac_method(vhsm_mac_method *m) {
    free(m->method_params);
}

//--------------------------------------------------------------------------------------

static int parse_module_args(pam_handle_t *pamh, vhsm_credentials *c, char *key_id, int key_id_size, int argc, const char **argv) {
    if(argc != 3) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: wrong number of arguments: expected 3, got %d", argc);
        return PAM_AUTHTOK_ERR;
    }

    char buf[BUF_SIZE];
    for(int i = 0; i < argc; ++i) {
        strncpy(buf, argv[i], 128);
        char *argval = strchr(buf, '=');
        if(argval == 0) {
            pam_syslog(pamh, LOG_ERR, "PAM-VHSM: bad argument: %s", argv[i]);
            return PAM_AUTHTOK_ERR;
        }
        *argval = 0;
        if(strcmp("user", buf) == 0) set_cred_login(c, argval + 1);
        else if(strcmp("password", buf) == 0) set_cred_passwd(c, argval + 1);
        else if(strcmp("key", buf) == 0) strncpy(key_id, argval + 1, key_id_size);
        else {
            pam_syslog(pamh, LOG_ERR, "PAM-VHSM: unknown argument: %s", argv[i]);
            return PAM_AUTHTOK_ERR;
        }
    }
    return PAM_SUCCESS;
}

//--------------------------------------------------------------------------------------

static int vhsm_sign_password(pam_handle_t *pamh, vhsm_credentials cred, char *key_id, const char *passwd, int passwd_size, char **signed_pass, int *signed_size) {
    vhsm_session s;
    if(vhsm_start_session(&s) != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: unable to open vhsm session");
        return PAM_AUTHTOK_ERR;
    }

    vhsm_rv vhsm_res = vhsm_login(s, cred);
    if(vhsm_res != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: VHSM login failed");
        vhsm_end_session(s);
        return PAM_AUTHTOK_ERR;
    }

    int res = PAM_AUTHTOK_ERR;
    vhsm_mac_method m = get_mac_method(key_id);
    vhsm_res = vhsm_mac_init(s, m);
    if(vhsm_res != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: VHSM mac init failed");
        goto cleanup;
    }

    vhsm_res = vhsm_mac_update(s, (unsigned char*)passwd, passwd_size);
    if(vhsm_res != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: VHSM mac update failed");
        goto cleanup;
    }

    vhsm_res = vhsm_mac_end(s, NULL, (unsigned int*)signed_size);
    *signed_pass = (char*)malloc(*signed_size * sizeof(char));
    vhsm_res = vhsm_mac_end(s, (unsigned char*)*signed_pass, (unsigned int*)signed_size);
    if(vhsm_res != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: unable to sign password");
        free(*signed_pass);
    } else {
        res = PAM_SUCCESS;
    }

cleanup:
    free_mac_method(&m);
    vhsm_logout(s);
    vhsm_end_session(s);
    return res;
}

//--------------------------------------------------------------------------------------

static bool is_blank_password(pam_handle_t *pamh, const char *user) {
    setspent();
    spwd *pw = getspnam(user);
    endspent();

    if(pw == NULL) {
        pam_syslog(pamh, LOG_ERR, "unable to get password for current user");
        return true;
    }

    return (strlen(pw->sp_pwdp) == 0 || pw->sp_pwdp[0] == '*' || pw->sp_pwdp[0] == '!');
}

static int verify_password(pam_handle_t *pamh, const char *user, const char *raw_pass, size_t raw_pass_length, bool nullok) {
    setspent();
    spwd *user_pw = getspnam(user);
    endspent();

    if(user_pw == NULL) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: unable to get password info");
        return PAM_AUTHINFO_UNAVAIL;
    }

    char *hash = user_pw->sp_pwdp;
    size_t hash_len = strlen(hash);
    if(hash_len == 0) {
        if(nullok) return PAM_SUCCESS;
        else return PAM_AUTH_ERR;
    } else if (!raw_pass || *hash == '*' || *hash == '!') {
        return PAM_AUTH_ERR;
    }

    char *crypted = apply_crypt(raw_pass, raw_pass_length, hash);
    int retval = (crypted && strcmp(crypted, hash) == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
    free(crypted);
    return retval;
}

//--------------------------------------------------------------------------------------

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    int rv = pam_get_user(pamh, &user, NULL);
    if(rv != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: authentication failed: %s", pam_strerror(pamh, rv));
        return PAM_USER_UNKNOWN;
    }

    vhsm_credentials login_user_cred;
    init_credentials(&login_user_cred);
    char login_user_key[BUF_SIZE];

    rv = parse_module_args(pamh, &login_user_cred, login_user_key, BUF_SIZE, argc, argv);
    if(rv != PAM_SUCCESS) return rv;

    const char *passwd = NULL;
    rv = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, NULL);
    if(rv != PAM_SUCCESS || !passwd) {
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: authentication failed: %s", rv == PAM_SUCCESS ? "unable to get password" : pam_strerror(pamh, rv));
        return PAM_AUTHINFO_UNAVAIL;
    }

    char *signed_passwd = NULL;
    int signed_passwd_size = 0;
    rv = vhsm_sign_password(pamh, login_user_cred, login_user_key, passwd, strlen(passwd), &signed_passwd, &signed_passwd_size);
    if(rv != PAM_SUCCESS) {
        free(signed_passwd);
        pam_syslog(pamh, LOG_ERR, "PAM-VHSM: authentication failed: %s", pam_strerror(pamh, rv));
        return PAM_AUTHINFO_UNAVAIL;
    }

    rv = verify_password(pamh, user, signed_passwd, signed_passwd_size, false);
    free(signed_passwd);
    return rv;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    //check module args first
    vhsm_credentials login_user_cred;
    init_credentials(&login_user_cred);
    char login_user_key[BUF_SIZE];

    int rv = parse_module_args(pamh, &login_user_cred, login_user_key, BUF_SIZE, argc, argv);
    if(rv != PAM_SUCCESS) return rv;

    const char *user = NULL;
    rv = pam_get_user(pamh, &user, NULL);
    if(rv != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "PAM_VHSM: unable to get user name");
        return rv;
    }

    if(flags & PAM_PRELIM_CHECK) {
        pam_syslog(pamh, LOG_DEBUG, "PAM-VHSM: pam_sm_chauthtok prelim_check called");

        if(is_blank_password(pamh, user)) return PAM_SUCCESS;

        //check old password

        return PAM_SUCCESS;
    } else if(flags & PAM_UPDATE_AUTHTOK) {
        pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_chauthtok update_authtok called");

        const char *old_passwd = NULL;
        rv = pam_get_item(pamh, PAM_OLDAUTHTOK, (const void**)&old_passwd);
        if(rv != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: unable to get old password");
        }
        if(old_passwd == NULL) {
            pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: old password is empty");
        }

        //now we need the user password
        const char *real_passwd = NULL;
        rv = pam_get_authtok(pamh, PAM_AUTHTOK, &real_passwd, NULL);
        if(rv != PAM_SUCCESS || !real_passwd) {
            pam_syslog(pamh, LOG_ERR, "PAM-VHSM: Unable to get user password: %s", rv == PAM_SUCCESS ? "unknown error" : pam_strerror(pamh, rv));
            return PAM_AUTHTOK_ERR;
        }

        char *signed_passwd = NULL;
        int signed_passwd_size = 0;
        rv = vhsm_sign_password(pamh, login_user_cred, login_user_key, real_passwd, strlen(real_passwd), &signed_passwd, &signed_passwd_size);
        if(rv != PAM_SUCCESS) {
            free(signed_passwd);
            return rv;
        }

        char *new_passwd = apply_crypt(signed_passwd, signed_passwd_size);
        rv = unix_update_shadow(pamh, user, new_passwd);
        free(signed_passwd);
        free(new_passwd);

        if(rv != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: unable to update shadow file");
            return rv;
        }

        //password hashed with vhsm - now hash it with crypt
//        rv = pam_set_item(pamh, PAM_AUTHTOK, result.c_str());
//        if(rv != PAM_SUCCESS) {
//            pam_syslog(pamh, LOG_ERR, "PAM-VHSM: unable to set authtok: %s", pam_strerror(pamh, rv));
//            return PAM_AUTHTOK_ERR;
//        }

        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_chauthtok called with unsupported flag");
    return PAM_AUTHTOK_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_setcred called");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_acct_mgmt is not implemented");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_open_session is not implemented");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "PAM-VHSM: pam_sm_close_session is not implemented");
    return PAM_SERVICE_ERR;
}
