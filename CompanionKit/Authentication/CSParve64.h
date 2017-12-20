//--------------------------------------------------------------------------
// <copyright file="CSParve64.h" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// An implementation of 64-Bit Chain-And-Sum Checksum and Encryption.
// </summary>
//--------------------------------------------------------------------------

/*
 Using the CSParve64 support:
 The interface is adapted from the original CSParve64 code by factoring out the origin of
 the keys and the various constants used during hash computation, allowing them to be supplied at different stages.
 Ordinarily there are 5 32-bit numbers used as keys, 16 constants used in the word-swap code, and a 256-byte substitution box (SBox).
 3 of the 32-bit values, the word-swap table, and sBox are used to initialize a context for future use by instances created from the context.
 The other 2 32-bit numbers are passed in as an 8-byte array when creating a specific instance for hashing/encryption/decryption.
 The 3 32-bit keys, sBox, and word-swap factors could be unique for different purposes.
 The 8-byte 'instance' key could represent a particular identity.
 */

#ifndef CSPARVE64_H
#define CSPARVE64_H

// When compiling as a DLL, CSPARVE64_EXPORTS should be defined on the command-line.
// This symbol should not be defined on any project that uses this DLL.
// Any project whose source files include this file see CSPARVE64_API functions as being imported from a DLL,
// whereas this DLL sees symbols defined with this macro as being exported.

#ifndef __APPLE__

#ifdef CSPARVE64_EXPORTS
#define CSPARVE64_API __declspec(dllexport)
#else
#define CSPARVE64_API __declspec(dllimport)
#endif
#define UINT64 __uint64

#else

#define CSPARVE64_API

typedef int                    INT32;
typedef unsigned int           UINT32;
typedef unsigned long long int UINT64;

#ifndef memcpy_s
#define memcpy_s( dptr, dsize, sptr, ssize ) memcpy( dptr, sptr, ((dsize)<(ssize)?(dsize):(ssize)) )
#endif

#endif


typedef unsigned char BYTE;
typedef long          CSPARVE64_RESULT;

#define	CSPARVE64_OK	0L
#define	CSPARVE64_FAIL	-1L

#ifdef __cplusplus
extern "C" {
#endif
    
    /// <summary>
    /// Creates a context for the authentication library.
    /// The context copies the configuration and the substitution sbox.
    /// </summary>
    /// <param name="context">output context reference</param>
    /// <param name="config20">20 UINT32 elements used for configuration.</param>
    /// <param name="sbox">256-byte substitution box of sufficient entropy used during hashing and encryption. This array is copied.</param>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_OpenContext(void** context, const UINT32* config20, const BYTE* sbox);
    
    /// <summary>
    /// Destroy a context for the authentication library.
    /// </summary>
    /// <param name="context"></param>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_CloseContext(void* context);
    
    /// <summary>
    /// Creates a helper that can be used for computing a checksum, encryption, and decryption.
    /// After creation, the hash of the data used to create the key is available.
    /// A typical use would be to create the helper specifying an 8-BYTE inputKey specific to a particular use.
    /// 3 constants, a substitution sbox, and a block on which to compute the hash.
    /// </summary>
    /// <param name="context">context reference</param>
    /// <param name="inputKey">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
    /// <param name="data">Data on which to compute an initial hash that is later used for encryption.</param>
    /// <param name="dataLength">The data length MUST be a multiple of 8-bytes.</param>
    /// <param name="hiHash">pointer to 32 MSB of hash computed for the context</param>
    /// <param name="loHash">pointer to 32 LSB of hash computed for the context</param>
    /// <param name="instance">pointer to receive the instance.</param>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_Create(void* context, const BYTE* inputKey, const BYTE* data, UINT32 dataLength, UINT32* hiHash, UINT32* loHash, void** instance);
    
    /// <summary>
    /// Destroy an instance
    /// </summary>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_Destroy(void* instance);
    
    /// <summary>
    /// Encrypt a byte array.
    /// </summary>
    /// <param name="data">Data to be decrypted. </param>
    /// <param name="length">Length of data to be decrypted. The length MUST be a multiple of 8-bytes.</param>
    /// <param name="hiMAC">pointer to receive 32 MSB of MAC</param>
    /// <param name="loMAC">pointer to receive 32 LSB of MAC</param>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_Encode(void* instance, BYTE* data, UINT32 length, UINT32* hiMAC, UINT32* loMAC);
    
    /// <summary>
    /// Decrypt range of a byte array.
    /// </summary>
    /// <param name="data">Data to be decrypted.
    /// <param name="length">the length of data to be decrypted. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
    /// <param name="hiMAC">pointer to receive 32 MSB of MAC</param>
    /// <param name="loMAC">pointer to receive 32 LSB of MAC</param>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_Decode(void* instance, BYTE*  data, UINT32 length, UINT32* hiMAC, UINT32* loMAC);
    
    /// <summary>
    /// Compute a combined hash on the data using both Chain&Sum and Parve.
    /// </summary>
    /// <param name="inputKey">Array of at least 8 bytes unique to the instance. Only the first 8 bytes are used.</param>
    /// <param name="data">Data on which to compute hash.</param>
    /// <param name="dataLength">The data length MUST be a multiple of 8-bytes.</param>
    /// <param name="hi">pointer to 32 MSB of hash</param>
    /// <param name="lo">pointer to 32 LSB of hash</param>
    /// <returns>success</returns>
    CSPARVE64_API CSPARVE64_RESULT CSParve64_ComputeHash(void* context, const BYTE* inputKey, const BYTE* data, UINT32 dataLength, UINT32* hi, UINT32* lo);
    
#ifdef __cplusplus
} // used by C++ source code
#endif

#endif
