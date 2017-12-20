//--------------------------------------------------------------------------
// <copyright file="iOSGUIDs.h" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Helper functions for minimal iOS GUID support.
// </summary>
//--------------------------------------------------------------------------

#ifndef __IOSGUIDS_H__
#define __IOSGUIDS_H__

//----------------------------------------------
// GUID definitions
//----------------------------------------------
typedef struct _GUID {
    unsigned char Data[16];
} GUID;

// Functions for conversion from strings to GUID and vice versa
// String format of GUID is defined as:
//   b4 b3 b2 b1 - b6 b5 - b8 b7 - b9 b10 - b11 b12 b13 b14 b15 b16
//   - where bn is the nth byte of the guid Data array in hex format left padded with 0s to 2 digits
//     there are no spaces in the string.

#ifdef __cplusplus
extern "C"
{
#endif

// return 0 if successful, otherwise -1
int GuidFromString(const char* string, GUID* pGuid);

#define GUID_AS_STR_LENGTH 37
int GuidToString(const GUID* guid, char* string);

int hexToNibble(const char hexChar, unsigned char* pByte);

int hexToByte(const char* pHexChar, unsigned char* pByte);
#ifdef __cplusplus
}
#endif

#endif // __IOSGUIDS_H__

