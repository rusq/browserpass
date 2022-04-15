#include <stdlib.h>
#include "nss.h"

typedef SECStatus (*NSSInit)(char*);
typedef SECStatus (*NSSShutdown)();
typedef void* (*PK11GetInternalKeySlot)();
typedef void (*PK11FreeSlot)(void*);
typedef SECStatus (*PK11CheckUserPassword)(void*, char*);
typedef SECStatus (*PK11SDRDecrypt)(SECItem*, SECItem*, void*);
typedef void (*SECITEMZfreeItem)(SECItem*, PRBool);

typedef int (*PORTGetError)();
typedef char* (*PRErrorToName)(int);
typedef char* (*PRErrorToString)(int, unsigned int);

/* Wrapper functions for dynamic calls */

SECStatus _NSS_Init(void* f, char* path)
{
    NSSInit func = (NSSInit)f;
    return func(path);
}

SECStatus _NSS_Shutdown(void* f)
{
    NSSShutdown func = (NSSShutdown)f;
    return func();
}

void* _PK11_GetInternalKeySlot(void* f)
{
    PK11GetInternalKeySlot func = (PK11GetInternalKeySlot)f;
    return func();
}

void _PK11_FreeSlot(void* f, void* slot)
{
    PK11FreeSlot func = (PK11FreeSlot)f;
    return func(slot);
}

SECStatus _PK11_CheckUserPassword(void* f, void* slot, char* passwd)
{
    PK11CheckUserPassword func = (PK11CheckUserPassword)f;
    return func(slot, passwd);
}

SECStatus _PK11SDR_Decrypt(void* f, SECItem* data, SECItem* result, void* cx)
{
    PK11SDRDecrypt func = (PK11SDRDecrypt)f;
    return func(data, result, cx);
}

void _SECITEM_ZfreeItem(void* f, SECItem* si, PRBool freeItem)
{
    SECITEMZfreeItem func = (SECITEMZfreeItem)f;
    return func(si, freeItem);
}

int _PORT_GetError(void* f)
{
    PORTGetError func = (PORTGetError)f;
    return func();
}

char* _PR_ErrorToName(void* f, int code)
{
    PRErrorToName func = (PRErrorToName)f;
    return func(code);
}

char* _PR_ErrorToString(void* f, int code, unsigned int unused)
{
    PRErrorToString func = (PRErrorToString)f;
    return func(code, unused);
}

void alterme(SECItem* si)
{
    unsigned char* blah = (unsigned char*)"blah";
    si->data = blah;
    si->len = 4;
}

SECItem* new_SECItem(SECItemType type, unsigned char* data, unsigned int len)
{
    SECItem* rv = malloc(sizeof(SECItem));
    rv->type = type;
    rv->data = data;
    rv->len = len;
    return rv;
}