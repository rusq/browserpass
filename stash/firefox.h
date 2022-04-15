/* Header file for firefox definitions */
#ifndef FIREFOX_H
#define FIREFOX_H

typedef enum
{
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

typedef enum
{
    PR_FALSE = 0,
    PR_TRUE = 1
} PRBool;

struct SECItemStr
{
    SECItemType type;
    unsigned char *data;
    unsigned int len;
};

typedef enum
{
    SECWouldBlock = -2,
    SECFailure = -1,
    SECSuccess = 0
} SECStatus;

typedef struct SECItemStr SECItem;

typedef SECStatus (*NSSInit)(char *);
typedef void *(*PK11GetInternalKeySlot)();
typedef SECStatus (*PK11SDRDecrypt)(SECItem *, SECItem *, void *);
typedef SECStatus (*PK11Authenticate)(void *, int, void *);
typedef SECStatus (*PK11CheckUserPassword)(void *, char *);
typedef SECStatus (*NSSShutdown)();
typedef SECStatus (*PLBase64Decode)(const char *, unsigned int, char *);
typedef void (*PK11FreeSlot)(void *);
typedef SECItem *(*SECITEMAllocItem)(void *, void *, unsigned int);
typedef void (*SECITEMFreeItem)(SECItem *, PRBool);
typedef int (*PORTGetError)();
typedef char* (*PRErrorToName)(int);
typedef char* (*PRErrorToString)(int, unsigned int);

NSSInit NSS_Init;
PK11GetInternalKeySlot PK11_GetInternalKeySlot;
PK11SDRDecrypt PK11SDR_Decrypt;
PK11Authenticate PK11_Authenticate;
PK11CheckUserPassword PK11_CheckUserPassword;
NSSShutdown NSS_Shutdown;
PK11FreeSlot PK11_FreeSlot;
PLBase64Decode PL_Base64Decode;
SECITEMAllocItem SECITEM_AllocItem;
SECITEMFreeItem SECITEM_FreeItem;
PORTGetError PORT_GetError;
PRErrorToName PR_ErrorToName;
PRErrorToString PR_ErrorToString;


#endif //FIREFOX_H