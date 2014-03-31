//#include "stdafx.h"
#define SECURITY_WIN32
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "mysecurity.h"


void PrintHexDump(DWORD length, PBYTE buffer)
{
	DWORD i,count,index;
	CHAR rgbDigits[]="0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;

	for(index = 0; length;   length -= count, buffer += count, index += count) 
	{
	   count = (length > 16) ? 16:length;

	   sprintf_s(rgbLine, 100, "%4.4x  ",index);
	   cbLine = 6;

	   for(i=0;i<count;i++) 
	   {
	      rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
	      rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
	      if(i == 7) 
	      {
	         rgbLine[cbLine++] = ':';
	      } 
	      else 
	      {
	         rgbLine[cbLine++] = ' ';
	      }
	   }
	   for(; i < 16; i++) 
	   {
	      rgbLine[cbLine++] = ' ';
	      rgbLine[cbLine++] = ' ';
	      rgbLine[cbLine++] = ' ';
	   }

	   rgbLine[cbLine++] = ' ';

	   for(i = 0; i < count; i++) 
	   {
	      if(buffer[i] < 32 || buffer[i] > 126) 
	      {
	         rgbLine[cbLine++] = '.';
	      } 
	      else 
	      {
	         rgbLine[cbLine++] = buffer[i];
	      }
	   }

	   rgbLine[cbLine++] = 0;
	   printf("%s\n", rgbLine);
	}
}

void MyHandleError(char *s)
{
	fprintf(stderr,"%s error. Exiting.\n",s);
	exit (EXIT_FAILURE);
}

void PrintHex(DWORD length, PBYTE buffer)
{
	DWORD i,count,index;

	for (i=0; i<length; i++)
	{
		printf("%02x", buffer[i]);
	}
}
