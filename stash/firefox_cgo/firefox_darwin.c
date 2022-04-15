#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "firefox.h"

#define BUFFER_SZ 8192

#define TRUE 1
#define FALSE 0

#define SUCCESS 0
#define FAILURE -1

#define DEBUG

void *get_symbol(void *hLib, const char *name)
{
    if (hLib == NULL || name == NULL)
    {
        return NULL;
    }

    dlerror();
    void *addr = dlsym(hLib, name);
    char *err = dlerror();
    if (err != NULL)
    {
        return NULL;
    }
    return addr;
}

int load_symbols(void *hLib)
{
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
    if (NSS_Init == NULL ||
        PK11_GetInternalKeySlot == NULL ||
        PK11_Authenticate == NULL ||
        PK11SDR_Decrypt == NULL ||
        PL_Base64Decode == NULL ||
        PK11_CheckUserPassword == NULL ||
        NSS_Shutdown == NULL ||
        PK11_FreeSlot == NULL ||
        SECITEM_AllocItem == NULL ||
        SECITEM_FreeItem == NULL)
    {
        return -1;
    }
    return 0;
}

// init initialises NSS library.  Profile path must be provided.
// returns SUCCESS or FAILURE.
int init(char *profile_path)
{
    if (NSS_Init(profile_path) != SECSuccess)
    {
        printf("%s\n",profile_path);
        return FAILURE;
    }
    return SUCCESS;
}

// shuts down the NSS library.
int shutdown()
{
    if (NSS_Shutdown() != SECSuccess)
    {
        return FAILURE;
    }
    return SUCCESS;
}

int maxb64Size(int size)
{
    return ((size * 3) / 4);
}


int PK11Decrypt(const char *cipheredBuffer, char **plaintext)
{
    int rv = FAILURE;
    unsigned int len = strlen(cipheredBuffer);
    unsigned int ctLen = 512;
    SECItem *pIn = SECITEM_AllocItem(NULL, NULL, ctLen);
    SECItem pOut = { siBuffer, NULL, 0 };

    // pIn = NSSBase64_DecodeBuffer(NULL, NULL, cipheredBuffer, len);
    char *ct = malloc(ctLen);
    memset(ct,0,ctLen);
    PL_Base64Decode(cipheredBuffer, strlen(cipheredBuffer), ct);
    pIn->data = (unsigned char *)ct;
    pIn->len = ctLen;

    if (PK11SDR_Decrypt(pIn, &pOut, NULL) == SECSuccess)
    {
        *plaintext = malloc(pOut.len + 1);
        strncpy(*plaintext, (const char *)pOut.data, pOut.len);
        (*plaintext)[pOut.len] = '\0';
        rv = SUCCESS;
    };
    SECITEM_FreeItem(pIn, TRUE);
    SECITEM_FreeItem(&pOut, FALSE);
    return rv;
}

char *decrypt(const char *pass_str)
{
    void *slot_info = PK11_GetInternalKeySlot();
    if (slot_info == NULL)
    {
        return NULL;
    }
    if (PK11_CheckUserPassword(slot_info, "") != SECSuccess)
    {
        printf("PK11_CheckUserPassword fails\r\n");
        return NULL;
    }
    if (PK11_Authenticate(slot_info, TRUE, NULL) != SECSuccess)
    {
        printf("PK11_Authenticate fails\r\n");
        return NULL;
    }
    char *output = NULL;
    int ret = PK11Decrypt(pass_str, &output);
    if (ret == FAILURE) {
        return NULL;
    }
    PK11_FreeSlot(slot_info);
    return output;
}


#ifdef DEBUG
int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("usage: %s <firefox profile path>\n", argv[0]);
        return 1;
    }

    void *lib = dlopen("libnss3.dylib", RTLD_LAZY);
    if (lib == NULL)
    {
        printf("error: %s\n", dlerror());
        return 1;
    }

    if (load_symbols(lib) != SUCCESS)
    {
        printf("failed to load symbols\n");
        return 1;
    }
    char *profile = argv[1];
    if (init(profile) != SUCCESS)
    {
        printf("failed to init\n");
        return 1;
    }

    char *dec = decrypt("5QjdGOG9SlgDSXW6L2zWLpemg/ZGAgDT5Z1Lz8/d1FugVI6WtXuRiq8t2lUVP8YUT0ciQFkFD2CgprRa");
    if (dec == NULL)
    {
        printf("failed to decode\n");
        return 1;
    }
    printf("decoded: %s\n", dec);
    shutdown();
    return 0;
}

#endif
