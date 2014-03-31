//  @snowytoxa (c) 2013
#include <sspi.h>
#include <Secext.h>
#include <Security.h>


#define SEC_SUCCESS(Status) ((Status) >= 0)

extern void PrintHexDump(DWORD length, PBYTE buffer);
extern void PrintHex(DWORD length, PBYTE buffer);
extern void MyHandleError(char *s);

