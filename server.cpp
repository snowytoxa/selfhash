//#include "stdafx.h"
#define SECURITY_WIN32
#define SEC_SUCCESS(Status) ((Status) >= 0)

#include <windows.h>
#include <stdio.h>
#include "mysecurity.h"

BOOL GenServerContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, BOOL fNewCredential, CredHandle *hcred, struct _SecHandle *hctxt);
BOOL GenClientContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, SEC_CHAR *pszTarget, CredHandle *hCred, struct _SecHandle *hCtxt);
BOOL DoAuthentication (void);

void main ()
{
	DoAuthentication();
} 

BOOL DoAuthentication (void)
{
	SECURITY_STATUS   	ss;
	DWORD 			  	cbIn;
	DWORD		      	cbOut;
	DWORD 			  	g_cbMaxMessage;
	BOOL              	done = FALSE;
	BOOL		      	fDone = FALSE;
	BOOL              	fNewConversation = TRUE;
	TimeStamp         	Lifetime;
	PSecPkgInfoA	  	pkgInfo;
	CredHandle        	hcred;
	CredHandle 	      	hCcred;
	struct _SecHandle 	hctxt;
	struct _SecHandle 	hCctxt;
	PBYTE 			  	g_pInBuf = NULL;
	PBYTE 			  	g_pOutBuf = NULL;
	SEC_CHAR          	g_lpPackageName[1024];
	PBYTE				nonce, clientnonce, lmhash, nthash;
	PCHAR pUserName = NULL;
	DWORD cbUserName = 0;



	lstrcpynA (g_lpPackageName, "NTLM",5);
	ss = QuerySecurityPackageInfoA ( g_lpPackageName, &pkgInfo);
	if (!SEC_SUCCESS(ss)) MyHandleError("Could not query package");

	g_cbMaxMessage = pkgInfo->cbMaxToken;
	FreeContextBuffer(pkgInfo);
	g_pInBuf = (PBYTE) malloc (g_cbMaxMessage);
	g_pOutBuf = (PBYTE) malloc (g_cbMaxMessage);
   
	if (NULL == g_pInBuf || NULL == g_pOutBuf) MyHandleError("Memory allocation");

	ss = AcquireCredentialsHandleA (NULL, g_lpPackageName, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hcred, &Lifetime);

	if (!SEC_SUCCESS (ss)) MyHandleError("AcquireCreds failed");
	cbOut = g_cbMaxMessage;

	if (!GenClientContext ( NULL, 0, g_pOutBuf, &cbOut, &fDone, "NTLM", &hCcred, &hCctxt))
		MyHandleError("Cant't generate client context");

	printf ("Type%hhd message (%lu bytes):\n",g_pOutBuf[8], cbOut);//type1
	PrintHexDump (cbOut, (PBYTE)g_pOutBuf);

	memcpy(g_pInBuf,g_pOutBuf, cbOut);
	cbIn = cbOut;
	cbOut = g_cbMaxMessage;


	if (!GenServerContext (g_pInBuf, cbIn, g_pOutBuf, &cbOut, &done, fNewConversation, &hcred, &hctxt))
		MyHandleError("GenServerContext failed");

	fNewConversation = FALSE;

	printf ("Type%hhd message (%lu bytes):\n",g_pOutBuf[8], cbOut); //type2
	PrintHexDump (cbOut, (PBYTE)g_pOutBuf);
	
	memcpy(g_pInBuf,g_pOutBuf, cbOut);
	cbIn = cbOut;
	cbOut = g_cbMaxMessage;

	nonce = (PBYTE) malloc (16);
	memcpy (nonce, (void *)&g_pOutBuf[24], 8);
	
	if (!GenClientContext (g_pInBuf, cbIn, g_pOutBuf, &cbOut, &fDone, "NTLM", &hCcred, &hCctxt))
		MyHandleError("GenClientContext failed");

	printf ("Type%hhd message (%lu bytes):\n",g_pOutBuf[8], cbOut);//type3
	PrintHexDump (cbOut, (PBYTE)g_pOutBuf);

	GetUserNameExA(NameSamCompatible, pUserName, &cbUserName);
	pUserName = (PCHAR) malloc (cbUserName);
	GetUserNameExA(NameSamCompatible, pUserName, &cbUserName);
	cbUserName = (DWORD)((int)strchr(pUserName,'\\'));
	*(char *)cbUserName = 0;

	printf("g_pOutBuf[22]=%d\n",g_pOutBuf[22]);

	if (g_pOutBuf[22] == 224 || g_pOutBuf[22] == 100) 
	{
		printf("NTLMv2\n");
		nthash = (PBYTE) malloc (16);
		cbIn = g_pOutBuf[24] + (g_pOutBuf[25] << 8);
		memcpy (nthash, (void *)&g_pOutBuf[cbIn], 16);

		cbIn += 16;
		clientnonce = (PBYTE) malloc (cbOut - cbIn - 16);
		//memcpy (clientnonce, (void *)&g_pOutBuf[cbIn], 84);
		memcpy (clientnonce, (void *)&g_pOutBuf[cbIn], cbOut - cbIn - 16);

		printf("Nonce:  ");
		PrintHex (8, nonce);
		printf("\nClientNonce: ");
		PrintHex (cbOut - cbIn - 16, clientnonce);
		printf("\nNThash: ");
		PrintHex (16, nthash);
		printf("\n");
		
		printf("\nJTR: %s::%s", (unsigned char *)((int)cbUserName+1), (unsigned char *)pUserName);
		printf(":");
		PrintHex (8, nonce);
		printf(":");
		PrintHex (16, nthash);
		printf(":");
		PrintHex (cbOut - cbIn - 16, clientnonce);

		printf("\n");
	}
	else if (g_pOutBuf[22] == 24)
	{
		printf("NTLM\n");
		lmhash = (PBYTE) malloc (24);
		cbIn = g_pOutBuf[16] + (g_pOutBuf[17] << 8);
		memcpy (lmhash, (void *)&g_pOutBuf[cbIn], 24);

		nthash = (PBYTE) malloc (24);
		cbIn = g_pOutBuf[24] + (g_pOutBuf[25] << 8);
		memcpy (nthash, (void *)&g_pOutBuf[cbIn], 24);

		printf("\nNonce:  ");
		PrintHex (8, nonce);
		printf("\nLMhash: ");
		PrintHex (24, lmhash);
		printf("\nNThash: ");
		PrintHex (24, nthash);

		printf("\nJTR: %s::%s", (unsigned char *)((int)cbUserName+1), (unsigned char *)pUserName);
		printf(":");
		PrintHex (24, lmhash);
		printf(":");
		PrintHex (24, nthash);
		printf(":");
		PrintHex (8, nonce);
		printf("\n");
		
	}
	else
	{
		printf("Unknown hashtype");
	}


	return(TRUE);
}

BOOL GenServerContext ( BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, BOOL fNewConversation,  CredHandle *hcred, struct _SecHandle *hctxt)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             Attribs = 0;
	 
	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn;
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn;

	ss = AcceptSecurityContext (hcred, fNewConversation ? NULL : hctxt, &InBuffDesc, Attribs, SECURITY_NATIVE_DREP, hctxt, &OutBuffDesc, &Attribs, &Lifetime);

	if (!SEC_SUCCESS (ss))  
	{
	    fprintf (stderr, "AcceptSecurityContext failed: 0x%08x\n", ss);
	    return FALSE;
	}
	*pcbOut = OutSecBuff.cbBuffer;
	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss)    || (SEC_I_COMPLETE_AND_CONTINUE == ss));
	return TRUE;
}


BOOL GenClientContext (BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut, BOOL *pfDone, SEC_CHAR *pszTarget, CredHandle *hCred, struct _SecHandle *hCtxt)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             ContextAttributes;
	SEC_CHAR	      lpPackageName[1024];
	_SEC_WINNT_AUTH_IDENTITY	auth_data;
	PCHAR pUserName = NULL;
	DWORD cbUserName = 0;
	DWORD dw;


	if( NULL == pIn )  
	{   
		GetUserNameExA(NameSamCompatible, pUserName, &cbUserName);
		pUserName = (PCHAR) malloc (cbUserName);
		GetUserNameExA(NameSamCompatible, pUserName, &cbUserName);

		cbUserName = (DWORD)((int)strchr(pUserName,'\\'));
		*(char *)cbUserName = 0;
		auth_data.Domain = (unsigned char *)pUserName;
		auth_data.User = (unsigned char *)((int)cbUserName+1);
		printf("%s@%s\n",(char *)auth_data.User,(char *)auth_data.Domain);

		auth_data.UserLength = strlen((char *)auth_data.User);
		auth_data.DomainLength = strlen((char *)auth_data.Domain);
		auth_data.Password = NULL;
		auth_data.PasswordLength = 0;
		auth_data.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

	   	lstrcpynA (lpPackageName, "NTLM", 5);
	   	ss = AcquireCredentialsHandleA (NULL, lpPackageName, SECPKG_CRED_OUTBOUND, NULL, &auth_data, NULL, NULL, hCred, &Lifetime);
	   	if (!(SEC_SUCCESS (ss))) MyHandleError("AcquireCreds failed ");
	}

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers  = 1;
	OutBuffDesc.pBuffers  = &OutSecBuff;

	OutSecBuff.cbBuffer   = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer   = pOut;

	if (pIn)
	{
		 InBuffDesc.ulVersion = 0;
		 InBuffDesc.cBuffers  = 1;
		 InBuffDesc.pBuffers  = &InSecBuff;

		 InSecBuff.cbBuffer   = cbIn;
		 InSecBuff.BufferType = SECBUFFER_TOKEN;
		 InSecBuff.pvBuffer   = pIn;
		ss = InitializeSecurityContextA (hCred,	hCtxt,	pszTarget,	ISC_REQ_CONFIDENTIALITY, 0,	SECURITY_NATIVE_DREP,	&InBuffDesc,	0, 	hCtxt,	&OutBuffDesc, &ContextAttributes,	&Lifetime);
	}
	else
	{
		 ss = InitializeSecurityContextA (hCred, NULL, pszTarget, ISC_REQ_CONFIDENTIALITY, 0, SECURITY_NATIVE_DREP, NULL, 0, hCtxt, &OutBuffDesc, &ContextAttributes, &Lifetime);
	}

	if (!SEC_SUCCESS (ss)) MyHandleError ("InitializeSecurityContext failed " );

	*pcbOut = OutSecBuff.cbBuffer;
	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||(SEC_I_COMPLETE_AND_CONTINUE == ss));
	return TRUE;
}
