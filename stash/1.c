#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "firefox.h"

#define BUFFER_SZ 8192

#define TRUE 1
#define FALSE 0

#define SUCCESS 0
#define FAILURE -1

#define DEBUG

void handle_error() {
  int err = PORT_GetError();
  char* name = PR_ErrorToName(err);
  char* str = PR_ErrorToString(err, 0);
  printf("handle_error(): CODE(%d): %s, %s\n", err, name, str);
}

void* get_symbol(void* hLib, const char* name) {
  if (hLib == NULL || name == NULL) {
    return NULL;
  }

  // dlerror();
  void* addr = GetProcAddress((HMODULE)hLib, (LPCSTR)name);
  // void *addr = dlsym(hLib, name);
  // char *err = dlerror();
  return addr;
}

int load_symbols(void* hLib) {
  NSS_Init = get_symbol(hLib, "NSS_Init");
  PK11_GetInternalKeySlot = get_symbol(hLib, "PK11_GetInternalKeySlot");
  PK11_Authenticate = get_symbol(hLib, "PK11_Authenticate");
  PK11SDR_Decrypt = get_symbol(hLib, "PK11SDR_Decrypt");
  PL_Base64Decode = get_symbol(hLib, "PL_Base64Decode");
  PK11_CheckUserPassword = get_symbol(hLib, "PK11_CheckUserPassword");
  NSS_Shutdown = get_symbol(hLib, "NSS_Shutdown");
  PK11_FreeSlot = get_symbol(hLib, "PK11_FreeSlot");
  SECITEM_AllocItem = get_symbol(hLib, "SECITEM_AllocItem");
  SECITEM_FreeItem = get_symbol(hLib, "SECITEM_FreeItem");
  PORT_GetError = get_symbol(hLib, "PORT_GetError");
  PR_ErrorToName = get_symbol(hLib, "PR_ErrorToName");
  PR_ErrorToString = get_symbol(hLib, "PR_ErrorToString");
  if (NSS_Init == NULL || PK11_GetInternalKeySlot == NULL ||
      PK11_Authenticate == NULL || PK11SDR_Decrypt == NULL ||
      PL_Base64Decode == NULL || PK11_CheckUserPassword == NULL ||
      NSS_Shutdown == NULL || PK11_FreeSlot == NULL ||
      SECITEM_AllocItem == NULL || SECITEM_FreeItem == NULL) {
    return -1;
  }
  return 0;
}

// init initialises NSS library.  Profile path must be provided.
// returns SUCCESS or FAILURE.
int init(char* profile_path) {
  if (NSS_Init(profile_path) != SECSuccess) {
    printf("%s\n", profile_path);
    return FAILURE;
  }
  return SUCCESS;
}

// shuts down the NSS library.
int finish() {
  if (NSS_Shutdown() != SECSuccess) {
    return FAILURE;
  }
  return SUCCESS;
}

int maxb64Size(int size) { return ((size * 3) / 4); }

int PK11Decrypt(const char* cipheredBuffer, char** plaintext) {
  int rv = FAILURE;
  unsigned int len = strlen(cipheredBuffer);
  unsigned int ctLen = 512;
  SECItem* pIn = SECITEM_AllocItem(NULL, NULL, ctLen);
  SECItem pOut = {siBuffer, NULL, 0};

  // pIn = NSSBase64_DecodeBuffer(NULL, NULL, cipheredBuffer, len);
  char* ct = malloc(ctLen);
  memset(ct, 0, ctLen);
  PL_Base64Decode(cipheredBuffer, strlen(cipheredBuffer), ct);
  pIn->data = (unsigned char*)ct;
  pIn->len = ctLen;

  if (PK11SDR_Decrypt(pIn, &pOut, NULL) == SECSuccess) {
    *plaintext = malloc(pOut.len + 1);
    strncpy(*plaintext, (const char*)pOut.data, pOut.len);
    (*plaintext)[pOut.len] = '\0';
    rv = SUCCESS;
  };
  handle_error();
  SECITEM_FreeItem(pIn, TRUE);
  SECITEM_FreeItem(&pOut, FALSE);
  return rv;
}

char* decrypt(const char* pass_str) {
  void* slot_info = PK11_GetInternalKeySlot();
  if (slot_info == NULL) {
    handle_error();
    return NULL;
  }
  if (PK11_CheckUserPassword(slot_info, "") != SECSuccess) {
    handle_error();
    return NULL;
  }
  if (PK11_Authenticate(slot_info, TRUE, NULL) != SECSuccess) {
    handle_error();
    return NULL;
  }
  char* output = NULL;
  int ret = PK11Decrypt(pass_str, &output);
  if (ret == FAILURE) {
    return NULL;
  }
  PK11_FreeSlot(slot_info);
  return output;
}

#ifdef DEBUG
int main(int argc, char** argv) {
  void* lib = LoadLibrary("nss3.dll");
  if (lib == NULL) {
    printf("error loading library\n");
    return 1;
  }

  if (load_symbols(lib) != SUCCESS) {
    printf("error loading symbols\n");
    return 1;
  };

  int rv = NSS_Init(
      "C:/Users/rusq/AppData/Roaming/Mozilla/Firefox/Profiles/"
      "thatdsnb.default-release");
  if (rv != SECSuccess) {
    handle_error();
    return 1;
  }

    char* dec = decrypt("PMvF07RrlpaYce2hGN7VcmahQEPUElBpdx8TbAXpuJeGcYRfW1E4XGBIzFMdQchrHiuTmN5CFU1p2+Ow");
    if (dec == NULL) {
        printf("failed to decode\n");
        return 1;
    }
    printf("decoded: %s\n", dec);
    finish();
    

  FreeLibrary(lib);
  return 0;
}

#endif
