//--------------------------------------------------------------------------
// <copyright file="CSParve64.cpp" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// An implementation of 64-Bit Chain-And-Sum Checksum and Encryption.
// </summary>
//--------------------------------------------------------------------------

// This is the main support file.
// CSParve64.cpp : Defines the exported functions

#include "stdafx.h"
#include "CSParve64.h"
#include <string.h>

/* CS64Crypt Implementation
 * This program includes the following main components:
 *
 *   - CS64Hash(): A 64-bit hash function that combines a chain-&-sum MAC
 *     and a CBC MAC based on Parve cipher;
 *
 *   - CSParve64::Encrypt() and CSParve64::Decrypt(): Encryption and decryption with embedded
 *     MAC.  This uses the chain-&-sum technique with BV4 for the stream cipher,
 *     Parve for the block cipher, and operations mod 2^32 for the chaining.  The
 *     last two 32-bit blocks of the ciphertext comprise a MAC.
 *
 * Important: Input to these functions must be in multiples of 8 bytes.
 *
 * The following patents are relevant:
 *
 *   Chain-&-sum and related areas:
 *
 *     "Simple technique for implementing a cryptographic primitive
 *     using elementary register operations,"
 *     US Patent No. 6,570,988, May 27, 2003.
 *
 *     "Technique for producing a parameter, such as a checksum,
 *     through a primitive that uses elementary register operations,"
 *     US Patent No. 6,483,918, Nov. 19, 2002.
 *
 *     "Cryptographic technique that provides fast encryption and decryption
 *     and assures integrity of a ciphertext message through use of a message
 *     authentication code formed through cipher block chaining of the
 *     plaintext message,"
 *     US Patent No. 6,226,742, May 1, 2001.
 *
 *     "Method and apparatus for producing a message authentication code in a
 *     cipher block chaining operation by using linear combinations of an
 *     encryption key,"
 *     US Patent No. 6,128,737, Oct. 3, 2000.
 *
 *   Parve:
 *
 *     "Implementation efficient encryption and message authentication,"
 *     US Patent No. 5,956,405, Sep. 21, 1999.
 *
 *   BV4:
 *
 *     "Lightweight word-oriented technique for generating a pseudo-random
 *     sequence for use in a keystream of a stream cipher,"
 *     US Patent No. 6,490,354, Dec. 3, 2002.
 */

#ifdef _DEBUG
#define ASSERT(assertion) { if(!(assertion)) {throw 1;} }
#else
#define ASSERT(assertion) { }
#endif

class CS64Defs
{
public:
    
	static const INT32 SBOX_SIZE = 256; // size of sbox array used during encryption
	static const INT32 BLK_SIZE = 8;     // size of blocks for encryption and hash.
	static const INT32 KEY_SIZE = 8;     // 8 BYTE key + 4 bytes each for C, D, E
	static const INT32 NUM_ROUNDS = 8;
	static const INT32 CS_BLOCK_SIZE = sizeof(INT32);
	static const UINT32 MODULUS = 0x7FFFFFFF;
};

class Context
{
public:
	Context(const UINT32* config20, const BYTE* sbox);
    
	UINT32 Flags;
    
	UINT32 Key1;
	UINT32 Key2;
	UINT32 Key3;
    
	// App-specific odd numbers used for CS64_WordSwap
	UINT32 WS_B1;
	UINT32 WS_C1;
	UINT32 WS_D1;
	UINT32 WS_E1;
	UINT32 WS_B2;
	UINT32 WS_C2;
	UINT32 WS_D2;
	UINT32 WS_E2;
    
	// App-specific odd numbers used for CS64_Reversible
	UINT32 REV_B1;
	UINT32 REV_C1;
	UINT32 REV_D1;
	UINT32 REV_E1;
	UINT32 REV_B2;
	UINT32 REV_C2;
	UINT32 REV_D2;
	UINT32 REV_E2;
    
	BYTE SBox[256]; // Substitution Box for Encrypt
};

class Utils
{
public:
    
	static inline void WriteUInt64(UINT64 n, BYTE* dest, UINT32 offset)
	{
		dest[offset++] = (BYTE)(n >> 56);
		dest[offset++] = (BYTE)(n >> 48);
		dest[offset++] = (BYTE)(n >> 40);
		dest[offset++] = (BYTE)(n >> 32);
		dest[offset++] = (BYTE)(n >> 24);
		dest[offset++] = (BYTE)(n >> 16);
		dest[offset++] = (BYTE)(n >> 8);
		dest[offset] = (BYTE)n;
	}
    
	static inline UINT64 ReadUInt64(const BYTE*  buffer, UINT32 offset)
	{
		UINT64 result = (UINT64)buffer[offset++] << 56;
		result |= (UINT64)buffer[offset++] << 48;
		result |= (UINT64)buffer[offset++] << 40;
		result |= (UINT64)buffer[offset++] << 32;
		result |= (UINT64)buffer[offset++] << 24;
		result |= (UINT64)buffer[offset++] << 16;
		result |= (UINT64)buffer[offset++] << 8;
		result |= (UINT64)buffer[offset];
        
		return result;
	}
    
	static inline void WriteUInt32(UINT32 n, BYTE*  dest, UINT32 offset)
	{
		dest[offset++] = (BYTE)(n >> 24);
		dest[offset++] = (BYTE)(n >> 16);
		dest[offset++] = (BYTE)(n >> 8);
		dest[offset] = (BYTE)n;
	}
    
	static inline UINT32 ReadUInt32(const BYTE* buffer, UINT32 offset)
	{
		UINT32 result = (UINT32)buffer[offset++] << 24;
		result |= (UINT32)buffer[offset++] << 16;
		result |= (UINT32)buffer[offset++] << 8;
		result |= (UINT32)buffer[offset++];
        
		return result;
	}
    
	static inline UINT32 Hi(UINT64 n)
	{
		return (UINT32)(n >> 32);
	}
    
	static inline UINT32 Lo(UINT64 n)
	{
		return (UINT32)n;
	}
    
	static inline UINT64 MakeUInt64(UINT32 hi, UINT32 lo)
	{
		return (((UINT64)hi) << 32) | lo;
	}
};

class BV4Key
{
public:
    
	/// <summary>
	/// Set up a BV4 key.  This must be called prior to BV4 usage.
	/// </summary>
	BV4Key(const BYTE* keyData, UINT32 keyDataOffset, UINT32 keyDataLength);
    
	/// <summary>
	/// XOR input buffer with BV4 keystream, thus performing both encryption and decryption.
	/// </summary>
	/// <param name="inputBufBytes">Size of buffer to be encrypted or decrypted</param>
	/// <param name="inputBuf">buffer to be encrypted or decrypted</param>
	void BV4Crypt(UINT32 inputBufBytes, BYTE* inputBuf);
    
private:
    
	/// <summary>
	/// Fill buffer with RC4 keystream.  Needed for BV4 key setup.
	/// </summary>
	void RC4Fill();
    
private:
    
	static const INT32 RC4_TABLESIZE = 256;
	static const INT32 BV4_Y_TABLESIZE = 32;
    
	BYTE _i;
	BYTE _j;
	UINT32 _h;
	BYTE _s[RC4_TABLESIZE];
	UINT32 _y[BV4_Y_TABLESIZE];
};

/// <summary>
/// Set up a BV4 key.  This must be called prior to BV4 usage.
/// </summary>
BV4Key::BV4Key(const BYTE* keyData, UINT32 keyDataOffset, UINT32 keyDataLength)
{
	UINT32 i, j = 0, k = 0;
	BYTE* s = _s;
    
	// RC4 key setup
	_i = 0;
	_j = 0;
    
	for (i = 0; i < RC4_TABLESIZE; i++)
		s[i] = (BYTE)i;
    
	for (i = 0; i < RC4_TABLESIZE; i++)
	{
		j = (j + s[i] + keyData[k + keyDataOffset]) & (RC4_TABLESIZE - 1);
        
		BYTE tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
        
		if (++k == keyDataLength)
			k = 0;
	}
    
	// BV4 key setup.
	RC4Fill();
}

/// <summary>
/// Fill buffer with RC4 keystream.  Needed for BV4 key setup.
/// </summary>
void BV4Key::RC4Fill()
{
	UINT32 i = 0;
	UINT32 j = 0;
	BYTE* s = _s;
    
	const UINT32 bufferLength = (1 + BV4_Y_TABLESIZE) * (sizeof(UINT32));
	BYTE buffer[bufferLength]; // set _h and _y[]
    
	for (UINT32 k = 0; k < bufferLength; ++k)
	{
		i = ((i + 1) & (RC4_TABLESIZE - 1));
		BYTE tmp = s[i];
		j = ((j + tmp) & (RC4_TABLESIZE - 1));
		s[i] = s[j];
		s[j] = tmp;
		buffer[k] = s[(s[i] + tmp) & (RC4_TABLESIZE - 1)];
	}
    
	_i = (BYTE)i;
	_j = (BYTE)j;
	_h = Utils::ReadUInt32(buffer, 0);
	for (UINT32 k = 0; k < BV4_Y_TABLESIZE; ++k)
		_y[k] = Utils::ReadUInt32(buffer, (k + 1) * sizeof(UINT32));
}

/// <summary>
/// XOR input buffer with BV4 keystream, thus performing both encryption and decryption.
/// </summary>
/// <param name="inputBufBytes">Size of buffer to be encrypted or decrypted</param>
/// <param name="inputBuf">buffer to be encrypted or decrypted</param>
void BV4Key::BV4Crypt(UINT32 inputBufBytes, BYTE* inputBuf)
{
	UINT32 i = _i;
	UINT32 j = _j;
	BYTE* s = _s;
    
	UINT32* y = _y;
	UINT32 h = _h;
	// pBuf = (DWORD *) inputBuf;   // A
	inputBufBytes >>= 2;
    
	UINT32 index = 0;
	while (inputBufBytes-- > 0)
	{
		i = ((i + 1) & (RC4_TABLESIZE - 1));   // C1
		BYTE tmp = s[i];
		j = ((j + tmp) & (RC4_TABLESIZE - 1));  // C2
		s[i] = s[j];           // C3 (2)
		s[j] = tmp;             // C3 (3)
		BYTE t = (BYTE)(s[i] + s[j]);
        
		// *pBuf++ ^= _h*(DWORD)(pS[t & (RC4_TABLESIZE-1) ]);  // C5, D, E
		UINT32 dword = Utils::ReadUInt32(inputBuf, index << 2);
		dword ^= h * s[t & (RC4_TABLESIZE - 1)];  // C5, D, E
		Utils::WriteUInt32(dword, inputBuf, (index++) << 2);
        
		h += y[t & (BV4_Y_TABLESIZE - 1)];      // C6 (modified)
		s[t] += (BYTE)y[t & (BV4_Y_TABLESIZE - 1)];  // C7 (added)
	}
    
	_i = (BYTE)i;
	_j = (BYTE)j;
	_h = h;
}

class WordSwapHelper
{
public:
    
	/// <summary>
	/// C&S implementation using word swaps and arithmetic to create pairwise-independent functions
	/// Chain-&-sum MAC based on arithmetic and word swaps
	/// </summary>
	/// <remarks>
	/// In Claims 13, 24 and 27 of US Patent No. 6,483,918, this code
	/// implicitly sets all the y_i values to 1.
	/// </remarks>
	/// <returns>64-bit output hash</returns>
	static UINT64 CS64_WordSwap(Context* context, const BYTE* data, UINT32 length, UINT64 inHash);
    
	/// <summary>
	/// Chain-&-sum MAC based on arithmetic and word swaps.
	/// C&S implementation using word swaps and arithmetic to create
	/// pairwise-independent functions (reversible version)
	/// </summary>
	/// <returns>64-bit MAC (hash)</returns>
	static UINT64 CS64_Reversible(Context* context, const BYTE* const data, UINT32 length, UINT64 inHash);
    
private:
    
	static inline UINT32 WordSwap(UINT32 d)
	{
		return ((d >> 16) | (d << 16));
	}
    
	// pairwise-independent function and summing step
	static inline void Iteration(UINT32 a, UINT32 b, UINT32 c, UINT32 d, UINT32 e, const BYTE* data, UINT32& t, UINT32& t2, UINT32& index, UINT32& sum)
	{
		t = t2;
		t += Utils::ReadUInt32(data, (index++) << 2);
		t = t * a + WordSwap(t) * b;
		t2 = WordSwap(t) * c + t * d;
		t2 += WordSwap(t) * e;
		sum += t2;
	}
    
	// padding step invoked if dwNumBlocks is odd
	static inline void FinalIteration(UINT32 a, UINT32 b, UINT32 c, UINT32 d, UINT32 e, UINT32& t, UINT32& t2, UINT32& sum)
	{
		t = t2;
		t = t * a + WordSwap(t) * b;
		t2 = WordSwap(t) * c + t * d;
		t2 += WordSwap(t) * e;
		sum += t2;
	}
    
	// pairwise-independent function and summing step
	static inline void ReversibleIteration(UINT32 a, UINT32 b, UINT32 c, UINT32 d, UINT32 e, UINT32 l, const BYTE* data, UINT32& t, UINT32& u, UINT32& index, UINT32& sum)
	{
		t += Utils::ReadUInt32(data, (index++) << 2);
		t *= a;
		u = WordSwap(t);
		t = u * b;
		t = WordSwap(t) * c;
		t = WordSwap(t) * d;
		t = WordSwap(t) * e;
		t += u * l;
		sum += t;
	}
    
	// padding step invoked if dwNumBlocks is odd
	static inline void ReversibleFinalIteration(UINT32 a, UINT32 b, UINT32 c, UINT32 d, UINT32 e, UINT32 l, UINT32& t, UINT32& u, UINT32& sum)
	{
		t *= a;
		u = WordSwap(t);
		t = u * b;
		t = WordSwap(t) * c;
		t = WordSwap(t) * d;
		t = WordSwap(t) * e;
		t += u * l;
		sum += t;
	}
};

UINT64 WordSwapHelper::CS64_WordSwap(Context* context, const BYTE* data, UINT32 length, UINT64 inHash)
{
	UINT32 numBlocks = length / CS64Defs::CS_BLOCK_SIZE;    // number of 32-bit input words
	UINT32 key1 = Utils::Lo(inHash) | 1, key2 = Utils::Hi(inHash) | 1;
    
	UINT32 sum = 0, t = 0, t2 = 0;
	UINT32 index = 0;
	while (numBlocks > 1)
	{
		Iteration(key1, context->WS_B1, context->WS_C1, context->WS_D1, context->WS_E1, data, t, t2, index, sum);
		Iteration(key2, context->WS_B2, context->WS_C2, context->WS_D2, context->WS_E2, data, t, t2, index, sum);
		numBlocks -= 2;
	}
    
	if (numBlocks == 1)
	{
		Iteration(key1, context->WS_B1, context->WS_C1, context->WS_D1, context->WS_E1, data, t, t2, index, sum);
		FinalIteration(key2, context->WS_B2, context->WS_C2, context->WS_D2, context->WS_E2, t, t2, sum);
	}
	return Utils::MakeUInt64(sum, t2);
}

UINT64 WordSwapHelper::CS64_Reversible(Context* context, const BYTE* const data, UINT32 length, UINT64 inHash)
{
	const UINT32 REV_L1 = 0x0;
	const UINT32 REV_L2 = 0x0;
    
	UINT32 numBlocks = length / CS64Defs::CS_BLOCK_SIZE;    // number of 32-bit input words
	UINT32 key1 = Utils::Lo(inHash) | 1, key2 = Utils::Hi(inHash) | 1;
    
	UINT32 sum = 0, t = 0, u = 0;
	UINT32 index = 0;
	while (numBlocks > 1)
	{
		ReversibleIteration(key1, context->REV_B1, context->REV_C1, context->REV_D1, context->REV_E1, REV_L1, data, t, u, index, sum);
		ReversibleIteration(key2, context->REV_B2, context->REV_C2, context->REV_D2, context->REV_E2, REV_L2, data, t, u, index, sum);
		numBlocks -= 2;
	}
    
	if (numBlocks == 1)
	{
		ReversibleIteration(key1, context->REV_B1, context->REV_C1, context->REV_D1, context->REV_E1, REV_L1, data, t, u, index, sum);
		ReversibleFinalIteration(key2, context->REV_B2, context->REV_C2, context->REV_D2, context->REV_E2, REV_L2, t, u, sum);
	}
    
	return Utils::MakeUInt64(sum, t);
}

class CS64Key
{
private:
	UINT32 _a, _b, _c, _d, _e;        // key components
	UINT32 _invA, _invC, _invE;  // Inverses (mod 2^32) may be precomputed for speed.
    
public:
    
	CS64Key();
    
	/// <summary>
	/// Build a C&S Key
	/// </summary>
	/// <param name="inHash">64-bit input hash for key derivation</param>
	void Init(UINT64 inHash, UINT32 key1, UINT32 key2, UINT32 key3);
    
	/// <summary>
	/// C# version of chain-&-sum MAC over 32-bit words.  The MAC key
	///   is derived from an input "random" hash.
	///   Limitations:
	///     numBlocks must be even and >= 2.
	/// </summary>
	/// <param name="data">input data buffer</param>
	/// <param name="numBlocks">number of 32-bit input words</param>
	/// <returns>64-bit output hash</returns>
	UINT64 CS64ComputeMAC(const BYTE* data, UINT32 numBlocks) const;
    
	/// <summary>
	/// Invert chain-&-sum computation.
	///   Limitations:
	///     numBlocks must be nonzero, even, and >= 2.
	/// </summary>
	/// <param name="data">input data buffer</param>
	/// <param name="hash">64-bit input hash to be "decrypted"</param>
	/// <returns>"Decrypted" MAC</returns>
	UINT64 CS64InvertMAC(const BYTE* data, UINT32 dataLength, UINT64 hash) const;
    
private:
    
	/// <summary>
	/// Invert n mod 2^32 without using 64-bit arithmetic.
	/// </summary>
	/// <param name="n">number to be inverted</param>
	/// <returns>n^(-1) mod 2^32</returns>
	static UINT32 ModInvert32_32(UINT32 n);
    
	/// <summary>
	/// Run extended Euclidean algorithm to compute gcd(a, b) = x*a + y*b.
	/// </summary>
	/// <returns>gcd(a, b), x, y</returns>
	static void Egcd32(UINT32 a, UINT32 b, UINT32& outx, UINT32& outy);
};

UINT64 CS64Key::CS64ComputeMAC(const BYTE* data, UINT32 numBlocks) const
{
	UINT32 sum;
    
	UINT32 index = 0;
	// Multiply block 0 by _e and reduce.
	UINT32 exn = (_e * Utils::ReadUInt32(data, (index++) << 2));
    
	// Do ax+_b on block 0 and reduce.
	UINT32 chain = sum = (_a * exn + _b);
    
	// Do cx+_d on block 1 and reduce.
	chain = (_c * (chain + Utils::ReadUInt32(data, (index++) << 2)) + _d);
	sum += chain;
    
	// Process remaining blocks.
	for (UINT32 i = 1; i < numBlocks / 2; i++)
	{
		// Multiply even-indexed block by _e and reduce.
		exn = (_e * Utils::ReadUInt32(data, (index++) << 2));
        
		// Do ax+_b on even-indexed block and reduce.
		chain = (_a * (chain + exn) + _b);
		sum += chain;
        
		// Do cx+_d on odd-indexed block and reduce.
		chain = (_c * (chain + Utils::ReadUInt32(data, (index++) << 2)) + _d);
		sum += chain;
	}
    
	return (sum + (((UINT64)chain) << 32));
}

/// <summary>
/// Init a C&S Key
/// </summary>
CS64Key::CS64Key()
{
	_a = 0;
	_b = 0;
	_c = 0;
	_d = 0;
	_e = 0;
    
	_invA = 0;
	_invC = 0;
	_invE = 0;
}

/// <summary>
/// Build a C&S Key
/// </summary>
/// <param name="inHash">64-bit input hash for key derivation</param>
void CS64Key::Init(UINT64 inHash, UINT32 key1, UINT32 key2, UINT32 key3)
{
	UINT32 hi = Utils::Hi(inHash);
	UINT32 lo = Utils::Lo(inHash);
    
	_a = 1 | lo;
	_b = 1 | hi;
	_c = 1 | (key1 ^ lo);
	_d = 1 | (key2 ^ hi);
	_e = 1 | (key3 ^ lo);
    
	// Compute inverses of key multipliers.
	// These are used only for decrypt.
	_invA = ModInvert32_32(_a);
	_invC = ModInvert32_32(_c);
	_invE = ModInvert32_32(_e);
}

/// <summary>
/// Invert chain-&-sum computation.
///   Limitations:
///     numBlocks must be nonzero, even, and >= 2.
/// </summary>
/// <param name="data">input data buffer</param>
/// <param name="hash">64-bit input hash to be "decrypted"</param>
/// <returns>"Decrypted" MAC</returns>
UINT64 CS64Key::CS64InvertMAC(const BYTE* data, UINT32 dataLength, UINT64 hash) const
{
	UINT32 numBlocks = dataLength / sizeof(UINT32);    // number of 32-bit input words
    
	UINT32 sum = Utils::Lo(hash);
	UINT32 yn = Utils::Hi(hash);
	UINT32 yn2 = 0;
	UINT32 sumPrev = 0;
    
	// Get the chain & sum of all blocks except the last two.
	if (numBlocks > 2)
	{
		UINT64 aHashPrev = CS64ComputeMAC(data, numBlocks - 2);
		sumPrev = Utils::Lo(aHashPrev);
		yn2 = Utils::Hi(aHashPrev);
	}
    
	// y_{n-1} = sum(y_1..y_n) - sum(y_1..y_{n-2}) - y_n;
	UINT32 yn1 = sum - sumPrev - yn;
    
	// x_n = c_inv (y_n - _d) - y_{n-1}
	UINT32 xn = _invC * (yn - _d) - yn1;
    
	// x_{n-1} = e_inv [a_inv (y_{n-1} - _b) - y_{n-2}]
	UINT32 xn1 = _invE * (_invA * (yn1 - _b) - yn2);
    
	return Utils::MakeUInt64(xn1, xn);
}

/// <summary>
/// Invert n mod 2^32 without using 64-bit arithmetic.
/// </summary>
/// <param name="n">number to be inverted</param>
/// <returns>n^(-1) mod 2^32</returns>
UINT32 CS64Key::ModInvert32_32(UINT32 n)
{
	ASSERT((n & 1) != 0);
    
	UINT32 inv, x;
    
	if (1 == n)
		return 1;
    
	// Note:
	// - egcd(2^32, n, gcd, x, inv) = egcd(n, 2^32 mod n, gcd, x, inv)
	// - 2^32 mod n = 1 + (2^32-1) mod n
	Egcd32(n, 1 + (0xffffffff % n), x, inv);
    
	// n is odd and > 1, so 2^32/n = (2^32-1)/n
	inv = x - inv * (0xffffffff / n);
    
	return inv;
}

/// <summary>
/// Run extended Euclidean algorithm to compute gcd(a, b) = x*a + y*b.
/// </summary>
/// <returns>gcd(a, b), x, y</returns>
void CS64Key::Egcd32(UINT32 a, UINT32 b, UINT32& outx, UINT32& outy)
{
	UINT32 x = 0;
	UINT32 y = 1;
	UINT32 lastx = 1;
	UINT32 lasty = 0;
    
	while (b != 0)
	{
		UINT32 q = a / b;
        
		UINT32 temp = b;
		b = a % b;
		a = temp;
        
		temp = x;
		x = lastx - q * x;
		lastx = temp;
        
		temp = y;
		y = lasty - q * y;
		lasty = temp;
	}
    
	outx = lastx;
	outy = lasty;
	//return a; a is gcd.
}

class MACHelper
{
public:
    
	static UINT64 ParveCBCMAC(const BYTE* key, const BYTE*  sbox, const BYTE*  inText, UINT32 inTextLength);
	static void ParveEncryptBlock(const BYTE* key, const BYTE*  sbox, BYTE*  text);
	static void ParveDecryptBlock(const BYTE* key, const BYTE*  sbox, BYTE*  text);
	static UINT64 CS64_Modular(UINT64 inHash, UINT32 keyC, UINT32 keyD, UINT32 keyE, const BYTE* data, UINT32 dataLength);
	static UINT64 CS64Mod(UINT64 ui);
};

/// <summary>
/// Reduce a 64-bit intermediate C&S result mod 2^31 - 1.
/// </summary>
/// <returns>reduced value in argument</returns>
inline UINT64 MACHelper::CS64Mod(UINT64 ui)
{
	UINT32 hi = Utils::Hi(ui);
	UINT32 lo = Utils::Lo(ui);
    
	// Let qw = (2^32 * hi + lo), where hi and lo are 32-bit.
	// Then we have
	//
	//   r = qw mod (2^31 - 1)
	//     = 2*hi + lo
	//
	// We need to avoid overflow and wrap-around mod 2^32, which
	// cause 'r' to be off by 2.
    
	UINT32 r = hi << 1; // Note: hi < 2^30 if qw is an intermediate C&S result.
    
	if (r >= CS64Defs::MODULUS)
		r -= CS64Defs::MODULUS;
    
	if (lo >= CS64Defs::MODULUS)
		lo -= CS64Defs::MODULUS;
    
	r += lo;
    
	if (r >= CS64Defs::MODULUS)
		r -= CS64Defs::MODULUS;
    
	return r;
}


/// <summary>
/// Encrypt one block in place with Parve.
/// </summary>
void MACHelper::ParveEncryptBlock(const BYTE*  key, const BYTE*  sbox, BYTE*  block)
{
	for (INT32 r = CS64Defs::NUM_ROUNDS; r > 0; r--)
	{
		BYTE tmp;
		INT32 i;
		for (i = 0; i < CS64Defs::BLK_SIZE - 1; i++)
		{
			tmp = (BYTE)(block[i + 1] + sbox[(key[i] + block[i] + r) & 255]);
			tmp = (BYTE)((tmp << 1) | (tmp >> 7));  // asm rol tmp, 1;
			block[i + 1] = tmp;
		}
        
		// Assume block[] does not have an extra work BYTE at the end.
		tmp = (BYTE)(block[0] + sbox[(key[i] + block[i] + r) & 255]);
		tmp = (BYTE)((tmp << 1) | (tmp >> 7));  // asm rol tmp, 1;
		block[0] = tmp;
	}
}

/// <summary>
/// Decrypt one block in place with Parve.
/// </summary>
void MACHelper::ParveDecryptBlock(const BYTE*  key, const BYTE*  sbox, BYTE*  block)
{
	for (INT32 r = 1; r <= CS64Defs::NUM_ROUNDS; r++)
	{
		// Need to have block[0] decrypted first for the loop below.
		INT32 i = CS64Defs::BLK_SIZE - 1;
		BYTE tmp = block[0];
		tmp = (BYTE)((tmp >> 1) | (tmp << 7));  // asm ror tmp, 1;
		block[0] = (BYTE)(tmp - sbox[(key[i] + block[i] + r) & 255]);
        
		for (--i; i >= 0; i--)
		{
			tmp = block[i + 1];
			tmp = (BYTE)((tmp >> 1) | (tmp << 7));  // asm ror tmp, 1;
			block[i + 1] = (BYTE)(tmp - sbox[(key[i] + block[i] + r) & 255]);
		}
	}
}

/// <summary>
/// C# version of chain-&-sum MAC over Z^{2^31 -1}.
///   The MAC key is derived from an input "random" hash.
///   Limitations:
///     numBlocks must be nonzero, even, and >= 2.
///     Data words have range 0 to 2^31 - 2, not 0 to 2^32 - 1.  The high
///       bits of 32-bit words will be ignored.
/// </summary>
/// <param name="inHash">64-bit input hash for key derivation</param>
/// <param name="keyC">32-bit key</param>
/// <param name="keyD">32-bit key</param>
/// <param name="keyE">32-bit key</param>
/// <param name="data">input data buffer</param>
/// <param name="dataLength">significant length of buffer</param>
/// <returns>64-bit MAC (~62 bits of security)</returns>
UINT64 MACHelper::CS64_Modular(UINT64 inHash, UINT32 keyC, UINT32 keyD, UINT32 keyE, const BYTE*  data, UINT32 dataLength)
{
	UINT32 numBlocks = dataLength / CS64Defs::CS_BLOCK_SIZE;
	ASSERT(numBlocks >= 2 && (numBlocks & 1) == 0);
    
	UINT64 sum = 0;
	// key data
	// Generate key from input hash.
	UINT64 cs64A = CS64Mod(Utils::Lo(inHash));
	UINT64 cs64B = CS64Mod(Utils::Hi(inHash));
	UINT64 cs64C = keyC;
	UINT64 cs64D = keyD;
	UINT64 cs64E = keyE;
    
	UINT32 index = 0;
	// Multiply block 0 by e and reduce.
	UINT64 tmp = cs64E * Utils::ReadUInt32(data, (index++) << 2);
	tmp = CS64Mod(tmp);
    
	// Do ax+b on block 0 and reduce.
	UINT64 mac = cs64A * tmp + cs64B;
	mac = CS64Mod(mac);
	sum = sum + mac;
    
	// Do cx+d on block 1 and reduce.
	tmp = mac + Utils::ReadUInt32(data, (index++) << 2);
	tmp = CS64Mod(tmp);
	mac = cs64C * tmp + cs64D;
	mac = CS64Mod(mac);
	sum = sum + mac;
    
	// Process remaining blocks.
	for (UINT32 i = 1; i < (numBlocks >> 1); i++)
	{
		// Multiply even-indexed block by e, add chaining variable, and reduce.
		tmp = cs64E * Utils::ReadUInt32(data, (index++) << 2) + mac;
		tmp = CS64Mod(tmp);
        
		// Do ax+b on even-indexed block and reduce.
		mac = cs64A * tmp + cs64B;
		mac = CS64Mod(mac);
		sum = sum + mac;
        
		// Do cx+d on odd-indexed block and reduce.
		tmp = mac + Utils::ReadUInt32(data, (index++) << 2);
		tmp = CS64Mod(tmp);
		mac = cs64C * tmp + cs64D;
		mac = CS64Mod(mac);
		sum = sum + mac;
	}
    
	mac = mac + cs64B;
	mac = CS64Mod(mac);
	sum = sum + cs64D;
	sum = CS64Mod(sum);
    
	return Utils::MakeUInt64(Utils::Lo(sum), Utils::Lo(mac));
}

class CSParve64
{
public:
    
	/// <summary>
	/// Creates a helper that can be used for computing one checksum, and encryption/decryption.
	/// After creation, the hash of the data used to create the key is available.
	/// A typical use would be to create the helper specifying an 8-BYTE inputKey specific to a particular use.
	/// 3 constants, a substitution sbox, and a block on which to compute the hash.
	/// </summary>
	/// <param name="inputKey">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
	/// <param name="sbox">substitution block used during hashing and encryption</param>
	/// <param name="key1">key used to generate hash</param>
	/// <param name="key2">key used to generate hash</param>
	/// <param name="key3">key used to generate hash</param>
	/// <param name="data">Data on which to compute an initial hash that is later used for encryption.
	/// The data length MUST be a multiple of 8-bytes.</param>
	CSParve64(const BYTE* inputKey, const BYTE* sbox, UINT32 key1, UINT32 key2, UINT32 key3, const BYTE* data, UINT32 dataLength);
    
	/// <summary>
	/// Encrypt a BYTE array.
	/// </summary>
	/// <param name="data">Data to be decrypted.
	/// <param name="length">the length of data to be decrypted. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
	CSPARVE64_RESULT Encrypt(BYTE* data, UINT32 length, UINT64* mac);
    
	/// <summary>
	/// Decrypt a BYTE array.
	/// </summary>
	/// <param name="data">Data to be decrypted.
	/// <param name="length">the length of data to be decrypted. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
	CSPARVE64_RESULT Decrypt(BYTE*  data, UINT32 length, UINT64* mac);
    
	/// <summary>
	/// Generate a hash using the data.
	/// Parve_Combined is independent of CS64Hash
	/// </summary>
	/// <param name="inputKey">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
	/// <param name="sbox">substitution block used during hashing and encryption</param>
	/// <param name="key1">key used to generate hash</param>
	/// <param name="key2">key used to generate hash</param>
	/// <param name="key3">key used to generate hash</param>
	/// <param name="data">Data on which to compute an initial hash that is later used for encryption.
	/// <param name="length">the length of data on which to compute the hash. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
	/// <param name="hash">pointer to 64-bit hash code buffer</param>
	/// <returns>success</returns>
	static CSPARVE64_RESULT CSH64_ParveCombined(Context* context, const BYTE* inputKey, const BYTE* data, UINT32 length, UINT64* hash);
    
	UINT64 Hash; // generated when computing CsKey, so cached here.
    
private:
    
	UINT64 CS64Hash(const BYTE* inText, UINT32 inTextLength);
    
	UINT32 C;
	UINT32 D;
	UINT32 E;
	CS64Key CsKey;
	BYTE ParveKey[CS64Defs::KEY_SIZE]; // copy of the Parve key initialized from the context
	BYTE SBox[CS64Defs::SBOX_SIZE]; // copy of the SBox initialized from the context
};

CSParve64::CSParve64(const BYTE* parveKey, const BYTE* sbox, UINT32 inKey1, UINT32 inKey2, UINT32 inKey3, const BYTE* data, UINT32 dataLength)
{
	memcpy_s(ParveKey, CS64Defs::KEY_SIZE, parveKey, CS64Defs::KEY_SIZE);
	memcpy_s(SBox, CS64Defs::SBOX_SIZE, sbox, CS64Defs::SBOX_SIZE);
    
	C = inKey1 | 1; // make odd
	D = inKey2 | 1; // make odd
	E = inKey3 | 1; // make odd
    
	// US Patent No. 6,128,737 [Claims 1-5, 8-13]
	// US Patent No. 5,956,405 [Claims 1-3, 5-8, 26]
	Hash = CSParve64::CS64Hash(data, dataLength);
}

/// <summary>
/// C&S-based encryption and authentication, using BV4 as
///   the stream cipher and Parve as the block cipher.
///   The plaintext is encrypted in place.  The last two blocks of the
///   ciphertext comprise a reversible MAC (64-bit).
///   Note: Input must be in multiples of 8 bytes (Parve block size).
/// </summary>
/// <param name="data">Data to be decrypted.
/// <param name="length">the length of data to be decrypted. The length MUST be a multiple of 8-bytes.</param>
CSPARVE64_RESULT CSParve64::Encrypt(BYTE* data, UINT32 length, UINT64* mac)
{
	ASSERT((length & (CS64Defs::BLK_SIZE - 1)) == 0); // must be multiple of block size
    
	UINT32 MACLength = 2 * CS64Defs::CS_BLOCK_SIZE;
	UINT32 MACOffset = length - 2 * CS64Defs::CS_BLOCK_SIZE;
    
	// C&S MAC/pre-MAC is the last two blocks of the plaintext.
	// Run C&S over the plaintext and replace last two blocks with the pre-MAC.
	*mac = CsKey.CS64ComputeMAC(data, length / CS64Defs::CS_BLOCK_SIZE);
    
	Utils::WriteUInt64(*mac, data, MACOffset);
    
	// Encrypt the last two blocks (pre-MAC) with Parve to create the MAC.
	MACHelper::ParveEncryptBlock(ParveKey, SBox, data + MACOffset);
    
	// Generate BV4 key from the encrypted MAC.
    
	// Normally the BV4 key would be generated from the pre-MAC.
	BV4Key bv4Key(data, MACOffset, MACLength);
    
	// Encrypt all but the last two blocks with BV4.
	bv4Key.BV4Crypt(MACOffset, data);
    
	return CSPARVE64_OK;
}

/// <summary>
/// C&S-based encryption and authentication, using BV4 as the
///   stream cipher and Parve as the block cipher.
///   Note: Input must be in multiples of 8 bytes (Parve block size).
/// </summary>
/// <param name="data">Data to be decrypted.
/// <param name="length">the length of data to be decrypted. The length MUST be a multiple of 8-bytes.</param>
CSPARVE64_RESULT CSParve64::Decrypt(BYTE*  data, UINT32 length, UINT64* mac)
{
	ASSERT((length & (CS64Defs::BLK_SIZE - 1)) == 0); // must be multiple of block size
    
	// Encrypted MAC is the last two blocks of the plaintext.
    
	UINT32 MACLength = 2 * CS64Defs::CS_BLOCK_SIZE;
	UINT32 MACOffset = length - 2 * CS64Defs::CS_BLOCK_SIZE;
    
	// Generate BV4 key from the encrypted MAC.
	BV4Key bv4Key(data, MACOffset, MACLength);
    
	// Decrypt all but the last two blocks with BV4.
	bv4Key.BV4Crypt(MACOffset, data);
    
	// Decrypt the last two blocks (MAC) with Parve to retrieve the C&S pre-MAC.
	MACHelper::ParveDecryptBlock(ParveKey, SBox, data + MACOffset);
    
	*mac = Utils::ReadUInt64(data, MACOffset);
    
	// Decrypt the last two blocks by reversing the pre-MAC.
	UINT64 lastBlock = CsKey.CS64InvertMAC(data, length, *mac);
    
	// copy the decrypted checksum to the end of the block
	Utils::WriteUInt64(lastBlock, data, MACOffset);
    
	return CSPARVE64_OK;
}

/// <summary>
/// Combined C&S hashes and Parve MAC-based 64-bit hash.
/// Note: Input must be in multiples of 8 bytes (Parve block size).
/// This is independent of CS64Hash
/// </summary>
/// <param name="inputKey">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
/// <param name="data">Data on which to compute an initial hash that is later used for encryption.
/// <param name="length">the length of data on which to compute the hash. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
/// <param name="hash">64-bit hash code</param>
/// <returns>success</returns>
CSPARVE64_RESULT CSParve64::CSH64_ParveCombined(Context* context, const BYTE* inputKey, const BYTE* data, UINT32 length, UINT64* hash)
{
	ASSERT((length & (CS64Defs::BLK_SIZE - 1)) == 0); // must be multiple of block size
    
	// US Patent No. 6,128,737 [Claims 1-5, 8-13]
	// US Patent No. 6,483,918 [Claims 1-27]
	// US Patent No. 6,570,988 [Claims 1-9]
	// US Patent No. 5,956,405 [Claims 1-3, 5-8, 26]
    
	// Compute Parve hash.
	UINT64 outHash = MACHelper::ParveCBCMAC(inputKey, context->SBox, data, length);
    
	// Compute C&S hash (key derived from Parve CBC MAC).
	UINT64 aTempHash = MACHelper::CS64_Modular(outHash, context->Key1, context->Key2, context->Key3, data, length);
    
	// Combine the hashes into intermediate hash.
	outHash ^= aTempHash;
    
	// Compute C&S hash (key derived from intermediate hash).
	aTempHash = WordSwapHelper::CS64_WordSwap(context, data, length, outHash);
    
	// Combine the hashes into intermediate hash.
	outHash ^= aTempHash;
    
	// Compute C&S hash (key derived from intermediate hash).
	aTempHash = WordSwapHelper::CS64_Reversible(context, data, length, outHash);
    
	// Combine the hashes into final hash.
	outHash ^= aTempHash;
    
	*hash = outHash;
    
	return CSPARVE64_OK;
}

/// <summary>
/// Compute a CBC MAC using Parve as the block cipher.
/// </summary>
/// <returns>64-bit output MAC</returns>
UINT64 MACHelper::ParveCBCMAC(const BYTE*  key, const BYTE*  sbox, const BYTE*  inText, UINT32 inTextLength)
{
	UINT32 numBlocks = inTextLength / CS64Defs::BLK_SIZE;
	BYTE aBlock[CS64Defs::BLK_SIZE] = {0};
    
	for (UINT32 i = 0; i < numBlocks; ++i)
	{
		// Ci = Ek( C_{i-1} ^ Mi )
		for (INT32 j = 0; j < CS64Defs::BLK_SIZE; ++j)
			aBlock[j] ^= inText[i * CS64Defs::BLK_SIZE + j];
        
		MACHelper::ParveEncryptBlock(key, sbox, aBlock);
	}
    
	UINT64 result = Utils::ReadUInt64(aBlock, 0);
	return result;
}

/// <summary>
/// Combined C&S and Parve MAC-based 64-bit hash.
/// Note: Input must be in multiples of 8 bytes (Parve block size).
/// </summary>
/// <param name="inText">input data to hash</param>
/// <param name="myCSKey">computed CS64Key for encryption</param>
/// <returns>64-bit output hash</returns>
UINT64 CSParve64::CS64Hash(const BYTE* inText, UINT32 inTextLength)
{
	ASSERT((inTextLength & (CS64Defs::BLK_SIZE - 1)) == 0);
    
	// Compute Parve hash.
	UINT64 aParveHash = MACHelper::ParveCBCMAC(ParveKey, SBox, inText, inTextLength);
    
	// randomly fixed odd 32-bit constant
	CsKey.Init(aParveHash, C, D, E);
    
	// Compute C&S hash.
	UINT64 outHash = CsKey.CS64ComputeMAC(inText, inTextLength / CS64Defs::CS_BLOCK_SIZE);
    
	// Combine the hashes.
	outHash ^= aParveHash;
	return outHash;
}

Context::Context(const UINT32* config20, const BYTE* sbox)
{
	int i = 0;
    
	// Note: the "| 1" is to ensure the numbers are odd.
    
	Flags = config20[i++];
    
	// keys for hash
	Key1 = config20[i++] | 1;
	Key2 = config20[i++] | 1;
	Key3 = config20[i++] | 1;
    
	// numbers 8-15 for CS64_WordSwap
	WS_B1 = config20[i++] | 1;
	WS_C1 = config20[i++] | 1;
	WS_D1 = config20[i++] | 1;
	WS_E1 = config20[i++] | 1;
	WS_B2 = config20[i++] | 1;
	WS_C2 = config20[i++] | 1;
	WS_D2 = config20[i++] | 1;
	WS_E2 = config20[i++] | 1;
    
	// 16-24 for CS64_Reversible
	REV_B1 = config20[i++] | 1;
	REV_C1 = config20[i++] | 1;
	REV_D1 = config20[i++] | 1;
	REV_E1 = config20[i++] | 1;
	REV_B2 = config20[i++] | 1;
	REV_C2 = config20[i++] | 1;
	REV_D2 = config20[i++] | 1;
	REV_E2 = config20[i++] | 1;
    
	memcpy_s(SBox, CS64Defs::SBOX_SIZE, sbox, CS64Defs::SBOX_SIZE);
}

/// <summary>
/// Creates a context with a specific substitution box and keys.
/// </summary>
/// <param name="context">substitution block used during hashing and encryption</param>
/// <param name="config20">20 uints used for configuration of context</param>
/// <param name="sbox">substitution block used during hashing and encryption</param>
CSPARVE64_API CSPARVE64_RESULT CSParve64_OpenContext(void** pContext, const UINT32* config, const BYTE* sbox)
{
	Context* authContext = NULL;
	CSPARVE64_RESULT result = CSPARVE64_FAIL;
    
	if (pContext && sbox)
	{
		authContext = new Context(config, sbox);
        
		if (authContext->Flags == 0) // currently not supported.
		{
			result = CSPARVE64_OK;
		}
		else
		{
			delete authContext;
			authContext = NULL;
		}
	}
    
	*pContext = reinterpret_cast<void*>(authContext);
    
	return result;
}

/// <summary>
/// Free all memory associated with the context.
/// </summary>
CSPARVE64_API CSPARVE64_RESULT CSParve64_CloseContext(void* context)
{
	if (!context)
		return CSPARVE64_FAIL;
    
	Context* authContext = reinterpret_cast<Context*>(context);
    
	delete authContext;
    
	return CSPARVE64_OK;
}

/// <summary>
/// Creates a helper that can be used for computing a checksum, encryption, and decryption.
/// After creation, the hash of the data used to create the key is available.
/// A typical use would be to create the helper specifying an 8-BYTE inputKey specific to a particular use.
/// 3 constants, a substitution sbox, and a block on which to compute the hash.
/// </summary>
/// <param name="inputKey8">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
/// <param name="data">Data on which to compute an initial hash that is later used for encryption.
/// The data length MUST be a multiple of 8-bytes. It need not be the data that will be encrypted.</param>
CSPARVE64_API CSPARVE64_RESULT CSParve64_Create(void* context, const BYTE* inputKey8, const BYTE* data, UINT32 dataLength, UINT32* hiHash, UINT32* loHash, void** auth)
{
	if (!context)
		return CSPARVE64_FAIL;
    
	if (!data || !inputKey8 || dataLength < CS64Defs::BLK_SIZE || (dataLength & (CS64Defs::BLK_SIZE - 1)) != 0)
		return CSPARVE64_FAIL;
    
	Context* authContext = reinterpret_cast<Context*>(context);
    
	CSParve64* cs64 = new CSParve64(inputKey8, authContext->SBox, authContext->Key1, authContext->Key2, authContext->Key3, data, dataLength);
    
	*auth = reinterpret_cast<void*>(cs64);
    
	*hiHash = Utils::Hi(cs64->Hash);
	*loHash = Utils::Lo(cs64->Hash);
    
	return CSPARVE64_OK;
}

/// <summary>
/// Destroy an authentication context
/// </summary>
CSPARVE64_API CSPARVE64_RESULT CSParve64_Destroy(void* auth)
{
	if (!auth)
		return CSPARVE64_FAIL;
    
	CSParve64* cs64 = reinterpret_cast<CSParve64*>(auth);
    
	delete cs64;
    
	return CSPARVE64_OK;
}

/// <summary>
/// Encrypt a BYTE array.
/// </summary>
/// <param name="data">Data to be decrypted.
/// <param name="dataLength">the length of data to be decrypted in bytes. The length MUST be a multiple of 8-bytes.</param>
/// <param name="hiMAC">32 MSB of the 64-bit MAC that can be used as an integrity check after decode</param>
/// <param name="loMAC">32 LSB of the 64-bit MAC that can be used as an integrity check after decode</param>
CSPARVE64_API CSPARVE64_RESULT CSParve64_Encode(void* auth, BYTE* data, UINT32 dataLength, UINT32* hiMAC, UINT32* loMAC)
{
	if (NULL == auth)
		return CSPARVE64_FAIL;
    
	if (!data || dataLength < CS64Defs::BLK_SIZE || (dataLength & (CS64Defs::BLK_SIZE - 1)) != 0)
		return CSPARVE64_FAIL;
    
	CSParve64* cs64 = reinterpret_cast<CSParve64*>(auth);
    
	UINT64 mac;
	CSPARVE64_RESULT result = cs64->Encrypt(data, (UINT32)dataLength, &mac);
    
	if (result != CSPARVE64_OK)
		mac = 0;
    
	*hiMAC = Utils::Hi(mac);
	*loMAC = Utils::Lo(mac);
    
	return result;
}

/// <summary>
/// Decrypt a BYTE array.
/// </summary>
/// <param name="data">Data to be decrypted.
/// <param name="length">the length of data to be decrypted in bytes. The length MUST be a multiple of 8-bytes.</param>
/// <param name="hiMAC">32 MSB of the 64-bit MAC that can be used to compare with MAC after encode</param>
/// <param name="loMAC">32 LSB of the 64-bit MAC that can be used to compare with MAC after encode</param>
CSPARVE64_API CSPARVE64_RESULT CSParve64_Decode(void* auth, BYTE*  data, UINT32 length, UINT32* hiMAC, UINT32* loMAC)
{
	if (NULL == auth)
		return CSPARVE64_FAIL;
    
	if (!data || length < CS64Defs::BLK_SIZE || (length & (CS64Defs::BLK_SIZE - 1)) != 0)
		return CSPARVE64_FAIL;
    
	CSParve64* cs64 = reinterpret_cast<CSParve64*>(auth);
    
	UINT64 mac;
	CSPARVE64_RESULT result = cs64->Decrypt(data, (UINT32)length, &mac);
    
	if (result != CSPARVE64_OK)
		mac = 0;
    
	*hiMAC = Utils::Hi(mac);
	*loMAC = Utils::Lo(mac);
    
	return result;
}

/// <summary>
/// Generate a hash using the data.
/// Combined C&S hashes and Parve MAC-based 64-bit hash.
/// CSParve64_ComputeHash is independent of CS64Hash
/// </summary>
/// <param name="inputKey8">Array of at least 8 bytes used for the checksum calculation. Only the first 8 bytes are used.</param>
/// <param name="data">Data on which to compute an initial hash that is later used for encryption.
/// <param name="length">the length of data on which to compute the hash. Usually would be data.Length. The length MUST be a multiple of 8-bytes.</param>
/// <param name="hash">pointer to 64-bit hash code buffer</param>
/// <returns>success</returns>
CSPARVE64_API CSPARVE64_RESULT CSParve64_ComputeHash(void* context, const BYTE* inputKey8, const BYTE* data, UINT32 dataLength, UINT32* hi, UINT32* lo)
{
	UINT64 hash;
    
	if (!context)
		return CSPARVE64_FAIL;
    
	if (!data || !inputKey8 || dataLength < CS64Defs::BLK_SIZE || (dataLength & (CS64Defs::BLK_SIZE - 1)) != 0)
		return CSPARVE64_FAIL;
    
	Context* authContext = reinterpret_cast<Context*>(context);
    
	CSParve64::CSH64_ParveCombined(authContext, inputKey8, data, dataLength, &hash);
    
	*hi = Utils::Hi(hash);
	*lo = Utils::Lo(hash);
    
	return CSPARVE64_OK;
}
