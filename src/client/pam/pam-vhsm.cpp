#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <syslog.h>
#include <security/pam_ext.h>

#include <math.h>
#include <string.h>

#include "vhsm_api_prototype/common.h"

static void init_credentials(vhsm_credentials *c) {
    memset(c->username, 0, sizeof(c->username));
    memset(c->password, 0, sizeof(c->password));
}

static void set_credentials(vhsm_credentials *c, const char *user, const char *passwd) {
    size_t ulen = strlen(user);
    ulen = ulen < sizeof(c->username) ? ulen : sizeof(c->username);
    size_t plen = strlen(passwd);
    plen = plen < sizeof(c->password) ? plen : sizeof(c->password);

    strncpy(c->username, user, ulen);
    strncpy(c->password, passwd, plen);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL;
    int rv = pam_get_user(pamh, &user, NULL);
    if(rv != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Authentication failed: %s", pam_strerror(pamh, rv));
        return PAM_USER_UNKNOWN;
    }

    vhsm_session s;
    if(vhsm_start_session(&s) != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "Unable to open vhsm session");
        return PAM_AUTHINFO_UNAVAIL;
    }

    const char *passwd = NULL;
    rv = pam_get_authtok(pamh, PAM_AUTHTOK, &passwd, NULL);
    if(rv != PAM_SUCCESS || !passwd) {
        pam_syslog(pamh, LOG_ERR, "Authentication failed: %s", rv == PAM_SUCCESS ? "unable to get password" : pam_strerror(pamh, rv));
        vhsm_end_session(s);
        return PAM_AUTHINFO_UNAVAIL;
    }

    vhsm_credentials c;
    init_credentials(&c);
    set_credentials(&c, user, passwd);

    vhsm_rv auth_res = vhsm_login(s, c);
    init_credentials(&c);
    if(auth_res != VHSM_RV_OK) {
        pam_syslog(pamh, LOG_ERR, "VHSM Login failed");
        vhsm_end_session(s);
        return PAM_AUTH_ERR;
    }

    vhsm_end_session(s);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "pam_sm_acct_mgmt is not implemented");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "pam_sm_chauthtok is not implemented");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "pam_sm_open_session is not implemented");
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_syslog(pamh, LOG_WARNING, "pam_sm_close_session is not implemented");
    return PAM_SERVICE_ERR;
}
