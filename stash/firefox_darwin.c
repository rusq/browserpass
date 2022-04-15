#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#define NULLPTR 0

void *nss;

char *load(char *path)
{
    printf("env: ", getenv("DYLD_LIBRARY_PATH"));

    void *lib = dlopen(path, RTLD_LAZY);
    if (lib == NULLPTR)
    {
        return dlerror();
    }
    return "";
}

int main()
{
    char *nss3 = "libnss3.dylib";
    char *result;


    result = load(nss3);
    if (strlen(result) != 0)
    {
        printf("library failed to load: %s", result);
        return 1;
    };

    return 0;
}

// char * data_uncrypt(std::string pass_str) {
//     // Объявляем переменные
//     SECItem crypt;
//     SECItem decrypt;
//     PK11SlotInfo *slot_info;

//     // Выделяем память для наших данных
//     char *char_dest = (char *)malloc(8192);
//     memset(char_dest, NULL, 8192);
//     crypt.data = (unsigned char *)malloc(8192);
//     crypt.len = 8192;
//     memset(crypt.data, NULL, 8192);

//     // Непосредственно расшифровка функциями NSS
//     PL_Base64Decode(pass_str.c_str(), pass_str.size(), char_dest);
//     memcpy(crypt.data, char_dest, 8192);
//     slot_info = PK11_GetInternalKeySlot();
//     PK11_Authenticate(slot_info, TRUE, NULL);
//     PK11SDR_Decrypt(&crypt, &decrypt, NULL);
//     PK11_FreeSlot(slot_info);

//     // Выделяем память для расшифрованных данных
//     char *value = (char *)malloc(decrypt.len);
//     value[decrypt.len] = 0;
//     memcpy(value, decrypt.data, decrypt.len);

//     return value;
// }