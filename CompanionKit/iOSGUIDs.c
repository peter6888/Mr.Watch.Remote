//--------------------------------------------------------------------------
// <copyright file="iOSGUIDs.c" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Helper functions for minimal iOS GUID support.
// </summary>
//--------------------------------------------------------------------------

#include "iOSGUIDS.h"
#include <stdio.h>
#include <string.h>

int hexToNibble(const char hexChar, unsigned char* pByte)
{
	if ('0' <= hexChar && hexChar <= '9')
    {
		*pByte = (unsigned char)(hexChar - '0');
        return 0;
    }
	else if ('a' <= hexChar && hexChar <= 'f')
    {
		*pByte = (unsigned char)(10 + hexChar - 'a');
        return 0;
	}
    else if ('A' <= hexChar && hexChar <= 'F')
    {
		*pByte = (unsigned char)(10 + hexChar - 'A');
        return 0;
    }
	else
		return -1;
    
}

int hexToByte(const char* pHexChar, unsigned char* pByte)
{
    unsigned char tmp;
    if (hexToNibble(*pHexChar, &tmp) == 0)
    {
        *pByte = tmp << 4;
        if (hexToNibble(*(pHexChar + 1), &tmp) == 0)
        {
            *pByte |= tmp;
            return 0;
        }
    }
    return -1;
}

int GuidFromString(const char* string, GUID* guid)
{
    // validate string format
    if (guid != NULL && string != NULL && strlen(string) >= (GUID_AS_STR_LENGTH - 1))
    {
        if (string[8] == '-' && string[13] == '-' && string[18] =='-' && string[23] == '-')
        {
            int rc = 0;
            if (rc == 0)
                rc += hexToByte(&string[0], &guid->Data[3]);
            if (rc == 0)
                rc += hexToByte(&string[2], &guid->Data[2]);
            if (rc == 0)
                rc += hexToByte(&string[4], &guid->Data[1]);
            if (rc == 0)
                rc += hexToByte(&string[6], &guid->Data[0]);
            if (rc == 0)
                rc += hexToByte(&string[9], &guid->Data[5]);
            if (rc == 0)
                rc += hexToByte(&string[11], &guid->Data[4]);
            if (rc == 0)
                rc += hexToByte(&string[14], &guid->Data[7]);
            if (rc == 0)
                rc += hexToByte(&string[16], &guid->Data[6]);
            if (rc == 0)
                rc += hexToByte(&string[19], &guid->Data[8]);
            if (rc == 0)
                rc += hexToByte(&string[21], &guid->Data[9]);
            if (rc == 0)
                rc += hexToByte(&string[24], &guid->Data[10]);
            if (rc == 0)
                rc += hexToByte(&string[26], &guid->Data[11]);
            if (rc == 0)
                rc += hexToByte(&string[28], &guid->Data[12]);
            if (rc == 0)
                rc += hexToByte(&string[30], &guid->Data[13]);
            if (rc == 0)
                rc += hexToByte(&string[32], &guid->Data[14]);
            if (rc == 0)
                rc += hexToByte(&string[34], &guid->Data[15]);
            return (rc == 0? 0:-1);
        }
    }
    return -1;
}

int GuidToString(const GUID* guid, char* string)
{
    if (guid != NULL && string != NULL)
    {
        snprintf(string, GUID_AS_STR_LENGTH, "%02hhx%02hhx%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                 guid->Data[3], guid->Data[2], guid->Data[1], guid->Data[0], 
                 guid->Data[5], guid->Data[4],
                 guid->Data[7], guid->Data[6],
                 guid->Data[8], guid->Data[9], guid->Data[10], guid->Data[11], guid->Data[12], guid->Data[13], guid->Data[14], guid->Data[15]);
        return 0;
    }
    return -1;
}
