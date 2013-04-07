#include "pkcs11types.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static char const * PKCS11_SO_NAME = "/usr/lib/pkcs11/PKCS11_API.so";

CK_UTF8CHAR_PTR PKCS11_TOKEN_PIN = "12345678";
CK_ULONG PKCS11_TOKEN_PIN_LENGTH = 8;



static void * pkcs11_so;
//list of all pkcs#11 functions
static CK_FUNCTION_LIST_PTR pkcs11;

CK_RV load_symbol(void ** target, char const * sym_name) {
  dlerror(); //clear any old error conditions
  *target = dlsym(pkcs11_so, sym_name);
  if (!*target) {
    char const * err = dlerror();
    if (0 != err) {
      fprintf(stderr, "Error loading '%s' symbol: %s\n", sym_name, err);
      return CKR_GENERAL_ERROR;
    }
  }
  return CKR_OK;
}

CK_RV load_pkcs11() {
  CK_RV rv = CKR_OK;
  CK_RV (*C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR) = 0;
  
  pkcs11_so = dlopen(PKCS11_SO_NAME, RTLD_NOW);
  if (!pkcs11_so) {
    fprintf(stderr, "Error loading pkcs#11 so: %s\n", dlerror());
    return CKR_GENERAL_ERROR;
  }
  
  rv = load_symbol((void **)&C_GetFunctionList, "C_GetFunctionList");
  if (CKR_OK != rv) {
    return rv;
  }
  
  rv = C_GetFunctionList(&pkcs11);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetFunctionList call failed: 0x%.8lX", rv);
    return rv;
  }
  
  return CKR_OK;
}

CK_RV print_mechanisms(CK_SLOT_ID slot) {
  CK_RV rv = CKR_OK;
  CK_MECHANISM_TYPE_PTR mechanisms = 0;
  CK_ULONG mechanisms_count = 0, i = 0;
  
  rv = pkcs11 -> C_GetMechanismList(slot, 0, &mechanisms_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetMechanismList call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  mechanisms = (CK_MECHANISM_TYPE_PTR) malloc(sizeof(CK_MECHANISM_TYPE) * mechanisms_count);
  if (0 == mechanisms) {
    fprintf(stderr, "Memory allocation failed");
    return errno;
  }
  
  rv = pkcs11 -> C_GetMechanismList(slot, mechanisms, &mechanisms_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetMechanismList call failed: 0x%.8lX\n", rv);
    goto cleanup;
  }
  
  printf("Mechanisms available:\n");
  
  for (i = 0; i != mechanisms_count; ++i) {
    printf("0x%.8lX ", mechanisms[i]);
  }
  
  printf("\n");
  
  cleanup:
  free(mechanisms);
  
  return rv;
}

CK_RV print_tokens() {
  CK_RV rv = CKR_OK;
  CK_ULONG slots_count = 0, i = 0;
  CK_SLOT_ID_PTR slots = 0;
  
  rv = pkcs11 -> C_GetSlotList(TRUE, 0, &slots_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetSlotList call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  slots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots_count);
  if (0 == slots) {
    fprintf(stderr, "Memory allocation failed");
    return CKR_HOST_MEMORY;
  }
  
  rv = pkcs11 -> C_GetSlotList(TRUE, slots, &slots_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetSlotList call failed: 0x%.8lX\n", rv);
    goto free_slots;
  }
  
  printf("PKCS#11 tokens count: %lu\n", slots_count);
  for (i = 0; i != slots_count; ++i) {
    CK_TOKEN_INFO token_info = {};
    
    rv = pkcs11 -> C_GetTokenInfo(slots[i], &token_info);
    if (CKR_OK != rv) {
      fprintf(stderr, "C_GetTokenInfo call failed: 0x%.8lX\n", rv);
      goto free_slots;
    }
    
    printf("Token label: %.32s\n", token_info.label);
    
    rv = print_mechanisms(slots[i]);
    if (CKR_OK != rv) {
      fprintf(stderr, "Mechanisms print failed: 0x%.8lX\n", rv);
      goto free_slots;
    }
  }
  
  free_slots:
  free(slots);
  
  return rv;
}

CK_RV get_first_slot(CK_SLOT_ID_PTR slot_id) {
  CK_RV rv = CKR_OK;
  CK_ULONG slots_count = 0;
  CK_SLOT_ID_PTR slots = 0;
  
  rv = pkcs11 -> C_GetSlotList(TRUE, 0, &slots_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetSlotList call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  if (0 == slots_count) {
    fprintf(stderr, "No token slots found\n");
    return CKR_SLOT_ID_INVALID;
  }
  
  slots = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots_count);
  if (0 == slots) {
    fprintf(stderr, "Memory allocation failed\n");
    return CKR_HOST_MEMORY;
  }
  
  rv = pkcs11 -> C_GetSlotList(TRUE, slots, &slots_count);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_GetSlotList call failed: 0x%.8lX\n", rv);
    goto free_slots;
  }
  
  *slot_id = *slots;
  
  free_slots: free(slots);
  
  return rv;
}

CK_RV open_session(CK_SESSION_HANDLE_PTR session_ptr) {
  CK_RV rv = CKR_OK;
  CK_SLOT_ID slot_id;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  
  rv = get_first_slot(&slot_id);
  if (CKR_OK != rv) {
    fprintf(stderr, "Unable to get first slot.\n");
    return CKR_CANCEL;
  }
  
  rv = pkcs11 -> C_OpenSession(slot_id, flags, NULL_PTR, NULL_PTR, session_ptr);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_OpenSession call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  return rv;
}

CK_RV close_session(CK_SESSION_HANDLE session) {
  CK_RV rv = CKR_OK;
  
  rv = pkcs11 -> C_CloseSession(session);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_CloseSession call failed: 0x%.8lX\n", rv);
  }
  
  return rv;
}

CK_RV login(CK_SESSION_HANDLE session) {
  CK_RV rv = CKR_OK;
  
  rv = pkcs11 -> C_Login(session, CKU_USER, PKCS11_TOKEN_PIN, PKCS11_TOKEN_PIN_LENGTH);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_Login call failed: 0x%.8lX\n", rv);
  }
  
  return rv;
}

CK_RV logout(CK_SESSION_HANDLE session) {
  CK_RV rv = CKR_OK;
  
  rv = pkcs11 -> C_Logout(session);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_Logout call failed: 0x%.8lX\n", rv);
  }
  
  return rv;
}

CK_RV create_secret_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR key_ptr) {
  CK_RV rv = CKR_OK;
  
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
  CK_BBOOL true = 1;
  CK_BYTE key_value[] = ""; //TODO empty key for test purposes only
  CK_ULONG key_length = sizeof(key_value) - 1;
  
  CK_ATTRIBUTE keyTemplate[] = {
    {CKA_CLASS, &key_class, sizeof(key_class)},
    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
// see ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-11/v2-20/pkcs-11v2-20a4d2.pdf for details on next two commented lines
//    {CKA_SIGN, &true, sizeof(true)}, //can't use these either as CKK_GENERIC_SECRET does not support sign/verify ops
//    {CKA_VERIFY, &true, sizeof(true)}, //can't use these either as CKK_GENERIC_SECRET does not support sign/verify ops
    {CKA_VALUE, key_value, key_length},
  };
  
  rv = pkcs11 -> C_CreateObject(session, keyTemplate, 3, key_ptr);
  if (CKR_OK != rv) {
    fprintf(stderr, "C_CreateObject call failed: 0x%.8lX\n", rv);
  } else {
    printf("Created an empty secret key.\n");
  }
  
  return rv;
}

void print_bytes(CK_BYTE_PTR data, CK_ULONG n_bytes) {
  CK_ULONG i = 0;
  
  printf("0x");
  
  if (0 == n_bytes) {
    printf("0");
    return;
  }
  
  for (i = 0; i != n_bytes; ++i) {
    printf("%.2x", (int) data[i]);
  }
}

void try_hmac_sha1() {
  CK_SESSION_HANDLE session;
  CK_OBJECT_HANDLE key_handle;
  CK_MECHANISM mechanism = {CKM_SHA_1_HMAC, NULL_PTR, 0};
  CK_BYTE data[] = "";
  CK_BYTE signature[20] = {};
  CK_ULONG signature_length = 20;
  
  if (CKR_OK != open_session(&session)) {
    fprintf(stderr, "Failed to open session.\n");
    return;
  }
  
  if (CKR_OK != login(session)) {
    fprintf(stderr, "Login failed.\n");
    goto close_session;
  }
  
  //session opened and we're logged in.
  
  if (CKR_OK != create_secret_key(session, &key_handle)) {
    fprintf(stderr, "Secret key creation failed.\n");
    goto logout;
  }
  printf("Secret key creation succeeded.\n");
  if (CKR_OK != pkcs11 -> C_SignInit(session, &mechanism, key_handle)) {
    fprintf(stderr, "C_SignInit call failed.\n");
    goto logout;
  }
    printf("Computing HMAC-SHA1 for empty string.\n");
  if (CKR_OK != pkcs11 -> C_Sign(session, data, sizeof(data) - 1, signature, &signature_length)) {
    fprintf(stderr, "C_Sign call failed\n");
    goto logout;
  }
  printf("Ok, we got the mac: ");
  print_bytes(signature, signature_length);
  printf("\n");
  
  //ok, we're done here, let's do some cleanup
  
  logout:
  if (CKR_OK != logout(session)) {
    fprintf(stderr, "Logout failed.\n");
    goto close_session;
  }
  
  close_session:
  if (CKR_OK != close_session(session)) {
    fprintf(stderr, "Failed to close session.\n");
  }
}

int main(int argc, char *argv[]) {
  CK_RV rv = CKR_OK;
  
  if (CKR_OK != (rv = load_pkcs11())) {
    return rv;
  }
  
  if (CKR_OK != (rv = pkcs11 -> C_Initialize(0))) {
    fprintf(stderr, "C_Initialize call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  printf("Tokens available:\n");
  print_tokens();
  printf("\n\n");
  
  printf("Trying to compute HMAC-SHA1 with first token:\n");
  try_hmac_sha1();
  printf("\n\n");
  
  if (CKR_OK != (rv = pkcs11 -> C_Finalize(0))) {
    fprintf(stderr, "C_Finalize call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  if (pkcs11_so) {
    rv = dlclose(pkcs11_so);
  }
  
  return (int)rv;
}
