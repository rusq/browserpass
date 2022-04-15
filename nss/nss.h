/* nss.h : some NSS definitions */
#ifndef _NSS_H
#define _NSS_H

typedef enum {
    siBuffer,
    siClearDataBuffer,
    siCipherDataBuffer,
    siDERCertBuffer,
    siEncodedCertBuffer,
    siDERNameBuffer,
    siEncodedNameBuffer,
    siAsciiNameString,
    siAsciiString,
    siDEROID
} SECItemType;

struct SECItemStr {
    SECItemType type;
    unsigned char* data;
    unsigned int len;
};

typedef struct SECItemStr SECItem;

typedef enum {
    PR_FALSE = 0,
    PR_TRUE = 1
} PRBool;

typedef enum {
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;

/* Wrapper functions that take address of real function in dynamic library
and then make a call*/
SECStatus _NSS_Init(void* f, char* path);
SECStatus _NSS_Shutdown(void* f);
void* _PK11_GetInternalKeySlot(void* f);
void _PK11_FreeSlot(void* f, void* slot);
SECStatus _PK11_CheckUserPassword(void* f, void* slot, char* passwd);
SECStatus _PK11SDR_Decrypt(void* f, SECItem* data, SECItem* result, void* cx);
void _SECITEM_ZfreeItem(void* f, SECItem* si, PRBool freeItem);

int _PORT_GetError(void* f);
char* _PR_ErrorToName(void* f, int code);
char* _PR_ErrorToString(void* f, int code, unsigned int unused);

void alterme(SECItem* si);
SECItem* new_SECItem(SECItemType type, unsigned char* data, unsigned int len);

#endif /*_NSS_H*/