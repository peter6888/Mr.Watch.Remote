//--------------------------------------------------------------------------
// <copyright file="MRPairing.h" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Pairing and encryption interface class.
// </summary>
//--------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#include "iOSGUIDS.h"

#define COMPANION_KEY_LENGTH_IN_BYTES 8

typedef unsigned char          BYTE;
typedef unsigned int           UINT32;
typedef unsigned long long int UINT64;

static void   UInt32ToBytes(UINT32 n, BYTE* data);
static void   UInt64ToBytes(UINT64 n, BYTE* dest);
static UINT32 BytesToUInt32(BYTE* data);

#define pairDeviceId @"E7AAEC8C-F035-488a-AB39-C9A40547459F"
#define testDeviceId @"AB72527A-582D-4d6d-98DD-3DDCD4E00EC4"

#define COMPANION_PORT 53208

@interface MRPairing : NSObject<NSXMLParserDelegate,NSCoding> {

                                // Request fields ...
    NSString* _targetIPAddr;    // Theoretically, this could change.  If so, need SSDP discovery to determine new address.
    NSString* _deviceId;        // Assigned by the STB, or a fixed value when pairing.
    NSString* _deviceKey;       // Assigned by the STB.  Pairing value is 8 chars.  Assigned value for a pairing is 16.

                                // Response fields ...
    NSString* _targetUsn;       // STB client id.
    NSString* _targetName;      // STB friendly name.
    NSString* _targetApiVers;   // Version of API, starting with 2.1 (which returns a 1).
    NSString* _tags;            // Round-trip value, when pairing, can be set.  Is also returned by "hello" and "devices".
    NSInteger _seqNum;          // Not enforced at all starting in 2.1.  Otherwise, must be somewhat greater than previous value.
                                // Not enforced for "pair" and "hello", so if out of sync, you can issue "hello"and get current.
    
    NSString* _pairUid;         // Newly added pairing unique id for mairing management
    NSString* _cbUid;           // Callback uid
    id returnTarget;            // webview
    SEL returnMessage;          // methods in webview
    
@private
    BytePtr   _companionKey;    // Working values for encryption.
    UINT64    _contextHash;
    void*     _boxContext;
    void*     _impContext;
}

@property (nonatomic, retain)    NSString* targetIPAddr;
@property (nonatomic, retain)    NSString* deviceId;
@property (nonatomic, retain)    NSString* deviceKey;

@property (nonatomic, retain)    NSString* targetUsn;
@property (nonatomic, retain)    NSString* targetName;
@property (nonatomic, retain)    NSString* targetApiVers;
@property (nonatomic, retain)    NSString* tags;
@property (nonatomic, readwrite) NSInteger seqNum;

@property (nonatomic, readwrite) NSString* pairUid;
@property (nonatomic, readwrite) NSString* cbUid;
                                                            
+ (MRPairing*) currentTarget;
+ (void)setCurrentTarget:(MRPairing*)target;
+ (MRPairing*) pairingAtUid:(NSString *)pairingUid;

// - (id)initWithData:(NSString*)ipAddress DeviceId:(NSString*)deviceId Key:(NSString*)key;
// the change is that I add friendlyName == targetName to it
- (id)initWithData:(NSString*)ipAddress DeviceId:(NSString*)deviceId Key:(NSString*)key Name:(NSString*)name;
- (id)initWithBase25String:(NSString *)base25String friendlyName:(NSString*)name;

- (NSMutableURLRequest*)encryptRequest:(NSString*)request;
- (BOOL)decryptResponse:(NSMutableData*)response Headers:(NSDictionary*)headers;

- (BytePtr)makeCompanionKey;
- (void)formatSignature:(BytePtr)signature SequenceNumber:(uint)seqNum Length:(uint)len;

- (void)pairingCompletion:(NSData*)xmlData;
- (void)resultParsing:(NSData *)xmlData;
- (void)resultParsingFail:(NSData *)xmlData;
- (void)deletePair:(NSData *)xmlData;
- (void)deletePairFail:(NSData *)xmlData;

- (void)encodeWithCoder:(NSCoder*)coder;
- (id)initWithCoder:(NSCoder*)coder;

// similar to MRCOmpanion, set response handler
- (void)response:(id)target message:(SEL)message;

@end

//-------------------------------------------------------------------------------------------

@interface MRPairingResponse : NSObject<NSXMLParserDelegate>
{
@private
    NSString* _targetUsn;
    NSString* _targetName;
    NSString* _targetApiVers;
    NSString* _deviceId;
    NSString* _deviceKey;
    NSString* _tags;
    NSInteger _seqNum;
}

-(id)initWithData:(NSData*)xmlData;

@property (nonatomic, retain)    NSString* targetUsn;
@property (nonatomic, retain)    NSString* targetName;
@property (nonatomic, retain)    NSString* targetApiVers;
@property (nonatomic, retain)    NSString* deviceId;
@property (nonatomic, retain)    NSString* deviceKey;
@property (nonatomic, retain)    NSString* tags;
@property (nonatomic, readwrite) NSInteger seqNum;

@end

