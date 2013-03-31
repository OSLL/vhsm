#include <pkcs11types.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

static char const * PKCS11_SO_NAME = "/usr/local/lib/opencryptoki/PKCS11_API.so";
static void * pkcs11_so;

/*
 * pkcs#11 functions
 */
static CK_RV (*C_Initialize)(CK_VOID_PTR);
static CK_RV (*C_Finalize)(CK_VOID_PTR);

CK_RV load_symbol(void * target, char const * sym_name) {
  dlerror(); //clear any old error conditions
  target = dlsym(pkcs11_so, sym_name);
  if (!target) {
    char const * err = dlerror();
    if (0 != err) {
      fprintf(stderr, "Error loading '%s' symbol: %s\n", sym_name, err);
      return CKR_GENERAL_ERROR;
    }
  }
  return CKR_OK;
}

CK_RV load_c_initialize() {
  return load_symbol(C_Initialize, "C_Initialize");
}

CK_RV load_c_finalize() {
  return load_symbol(C_Finalize, "C_Finalize");
}

CK_RV load_pkcs11() {
  CK_RV rv;
  
  pkcs11_so = dlopen(PKCS11_SO_NAME, RTLD_LAZY);
  if (!pkcs11_so) {
    fprintf(stderr, "Error loading pkcs#11 so: %s\n", dlerror());
    return CKR_GENERAL_ERROR;
  }
  
  if (CKR_OK != (rv = load_c_initialize())) {
    return rv;
  }
  
  if (CKR_OK != (rv = load_c_finalize())) {
    return rv;
  }
}

int main(int argc, char *argv[]) {
  CK_RV rv = CKR_OK;
  
  if (CKR_OK != (rv = load_pkcs11())) {
    return rv;
  }
  
  if (CKR_OK != (rv = C_Initialize(0))) {
    fprintf(stderr, "C_Initialize call failed: 0x%lX\n", rv);
    return rv;
  }
  
  if (CKR_OK != (rv = C_Finalize(0))) {
    fprintf(stderr, "C_Finalize call failed: 0x%lX\n", rv);
    return rv;
  }
  
  return (int)rv;
}
