#include "pkcs11types.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static char const * PKCS11_SO_NAME = "/usr/lib/pkcs11/PKCS11_API.so";
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
    return errno;
  }
  
  rv = pkcs11 -> C_GetSlotList(TRUE, slots, &slots_count);
  
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

int main(int argc, char *argv[]) {
  CK_RV rv = CKR_OK;
  
  if (CKR_OK != (rv = load_pkcs11())) {
    return rv;
  }
  
  if (CKR_OK != (rv = pkcs11 -> C_Initialize(0))) {
    fprintf(stderr, "C_Initialize call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  print_tokens();
  
  if (CKR_OK != (rv = pkcs11 -> C_Finalize(0))) {
    fprintf(stderr, "C_Finalize call failed: 0x%.8lX\n", rv);
    return rv;
  }
  
  if (pkcs11_so) {
    rv = dlclose(pkcs11_so);
  }
  
  return (int)rv;
}
