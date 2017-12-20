//--------------------------------------------------------------------------
// <copyright file="MRPairing.mm" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Pairing and encryption interface class.  Is of type mm to directly call
// CSParve64 C++ standard encryption support.
// </summary>
//--------------------------------------------------------------------------

#include "MRPairing.h"
#include "CSParve64.h"

//------------------------------------------------------------------------------------------------------

#define OrigLengthSize 4
#define HashSize       8
#define OverheadSize   (OrigLengthSize + HashSize)

static UINT32 CompanionConfig[] = 
{
    0,
    0x47e83bd5, // Key1
    0x9028abf7, // Key2
    0xe6577c0d, // Key3
    
    0x30b31464, // WordSwap
    0x3914a7b2,
    0x77b1c677,
    0xa18a09cb,
    0x58ba62e5,
    0x5ae810ce,
    0x0d60f6aa,
    0xe05e24f8,
    0xacbb966d, // Reversible
    0x9d8bccf1,
    0x792c913c,
    0xb0d4e493,
    0x65daf8ee,
    0x18a13319,
    0x6cc3629c,
    0x40837197
};      // The values above for Key1, Key2, Key3 are the defaults for the STB.

static BYTE CompanionSBox[] = { 
    0x30, 0xb3, 0x66, 0x64, 0x00, 0x01, 0x00, 0x00, 0x12, 0x70, 0x59, 0xff, 0x9e, 0xed, 0x97, 0x07,
    0xc9, 0xf9, 0xfe, 0x98, 0xe8, 0x15, 0x5a, 0x60, 0xb7, 0xd2, 0xbb, 0x0c, 0xa5, 0xec, 0xc8, 0x87,
    0x08, 0xe2, 0x9b, 0xef, 0x5d, 0x6e, 0x79, 0x23, 0x87, 0x5f, 0xef, 0xa5, 0xaa, 0x2f, 0x9c, 0x63,
    0x87, 0x2b, 0x77, 0xc4, 0x7e, 0xc7, 0xe2, 0x86, 0xa0, 0xbe, 0x35, 0x88, 0x17, 0x31, 0xc3, 0xd3,
    0xba, 0x8c, 0x58, 0x92, 0x68, 0xda, 0xf9, 0xb2, 0x95, 0x87, 0xd3, 0x0b, 0x6b, 0x83, 0x9b, 0xaf,
    0x8f, 0x7d, 0x11, 0x6f, 0xc9, 0x95, 0x0d, 0xb1, 0x5b, 0x7d, 0xbb, 0x68, 0xef, 0x5e, 0xf3, 0x7c,
    0x21, 0x2e, 0x24, 0xd6, 0x00, 0x82, 0x37, 0x48, 0x2d, 0x37, 0x04, 0xb7, 0x27, 0xfa, 0x78, 0x61,
    0xe1, 0x0d, 0xd6, 0x71, 0xd8, 0xe5, 0x0c, 0x03, 0x34, 0xfb, 0xa4, 0x21, 0x71, 0x75, 0x39, 0x43,
    0x55, 0xf9, 0x29, 0x0a, 0x04, 0xad, 0x46, 0x1f, 0x14, 0x9f, 0x6e, 0x54, 0xc7, 0x8d, 0x10, 0xe0,
    0xb0, 0xfa, 0x88, 0x00, 0x48, 0x23, 0x55, 0xd2, 0x75, 0x0f, 0x79, 0x24, 0x81, 0x83, 0x56, 0x4c,
    0x2e, 0xf3, 0x35, 0xa1, 0x85, 0xcc, 0x03, 0xa4, 0x76, 0x2a, 0xeb, 0xde, 0x46, 0xfa, 0x19, 0x99,
    0x51, 0xa2, 0xb4, 0x9e, 0xa2, 0x20, 0x29, 0x9e, 0xad, 0xd2, 0x6a, 0x20, 0x28, 0x47, 0x6d, 0x70,
    0x04, 0x68, 0xbb, 0xc8, 0x88, 0x29, 0x51, 0xd2, 0x52, 0x8b, 0xc5, 0x40, 0x73, 0xde, 0xd8, 0x57,
    0xbf, 0xae, 0xae, 0x96, 0xee, 0x0a, 0x28, 0x77, 0x0d, 0x76, 0xf4, 0x52, 0xfa, 0x98, 0x44, 0x70,
    0xfa, 0x11, 0x32, 0xc6, 0x4d, 0xfe, 0xfc, 0x3b, 0x45, 0x78, 0x59, 0x1c, 0x6d, 0x3a, 0x88, 0x52,
    0x1a, 0x42, 0x81, 0x0d, 0xe8, 0x67, 0xaf, 0x05, 0x14, 0xc0, 0x07, 0xc2, 0xe9, 0x80, 0xad, 0x21
};

//------------------------------------------------------------------------------------------------------

@implementation MRPairing

@synthesize targetIPAddr  = _targetIPAddr;
@synthesize deviceId      = _deviceId;
@synthesize deviceKey     = _deviceKey;

@synthesize targetUsn     = _targetUsn;         // This is returned for the pairing case.
@synthesize targetName    = _targetName;
@synthesize targetApiVers = _targetApiVers;
@synthesize tags          = _tags;
@synthesize seqNum        = _seqNum;

@synthesize pairUid = _pairUid;
@synthesize cbUid = _cbUid;

//------------------------------------------------------------------------------------------------------

// A static property/helper for the current pairing target.  App demonstrates use of this.
// This is not required, but many apps will have a concept of a current paired target.

static MRPairing* _currentTarget;
+ (MRPairing*) currentTarget
{
    return _currentTarget;
}

+ (void)setCurrentTarget:(MRPairing*)target
{
    if (_currentTarget != target)
    {
        _currentTarget = target;
    }
}

static NSMutableDictionary *allPairings;
+ (MRPairing*) pairingAtUid:(NSString *)pairingUid
{
    return [allPairings valueForKey:pairingUid];
}
//------------------------------------------------------------------------------------------------------

// This creates a pairing with the minimum amount of data.  For the pairing case, an 8 character key is
// supplied.  The protocol however requires a 16 character key.  The convention is to duplicate the
// pairing key.  On a successful pairing, a 16 character key (and deviceId) will be returned, as well
// as other fields.

- (id)initWithData:(NSString*)ipAddress DeviceId:(NSString*)deviceId Key:(NSString*)key Name:(NSString *)name
{
    if ((self = [super init]))
    {
        if (([deviceId caseInsensitiveCompare:pairDeviceId] == NSOrderedSame) && (key.length == 8))
            key = [NSString stringWithFormat:@"%@%@", key, key];
        _targetIPAddr = [ipAddress copy];
        _deviceId     = [deviceId copy];
        _deviceKey    = [key copy];
        _targetName   = [name copy];
    }
    return self;
}

- (id)initWithBase25String:(NSString *)base25String friendlyName:(NSString*)name
{
    NSDictionary *pairInfo = [self decodeInput:base25String];
    _targetIPAddr = [pairInfo valueForKey:@"address"];
    _deviceKey = [NSString stringWithFormat:@"%@%@", [pairInfo valueForKey:@"pairKey"], [pairInfo valueForKey:@"pairKey"]];
    _deviceId = @"E7AAEC8C-F035-488a-AB39-C9A40547459F";
    _targetName = name;
    return self;
}

- (NSDictionary *)decodeInput:(NSString *)base25Sring
{
    NSMutableDictionary *pairInfo = [[NSMutableDictionary alloc]init];
    base25Sring = [base25Sring uppercaseString];
    NSArray *strings = [base25Sring componentsSeparatedByString:@"Z"];
    if([strings count] == 2) {
        
        long long lv = [self DecodeBase25:[strings objectAtIndex:0]];
        long long rv = [self DecodeBase25:[strings objectAtIndex:1]];
        
        int rvTrim = (int)rv;
        NSString *stringfy = [NSString stringWithFormat:@"%X", rvTrim];
        [pairInfo setValue:stringfy forKey:@"pairKey"];
        NSLog(@"%@",stringfy);
        
        BYTE addrBytes[4];
        UInt32ToBytes((int)(lv >> 16), addrBytes);
        NSString *ipAddr = [NSString stringWithFormat:@"%d.%d.%d.%d", addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3]];
        NSLog(@"%@", ipAddr);
        [pairInfo setValue:ipAddr forKey:@"address"];
    }
    return pairInfo;
}

- (long long)DecodeBase25:(NSString *)s
{
    long long v = 0;
    long long m = 1;
    if(s != nil) {
        for(int i = [s length] - 1; i >= 0; i--) {
            int c = (int)[s characterAtIndex:i];
            if(c >= (int)'A' && c <= (int)'Z') {
                c -= (int)'A';
                v += m * (long)c;
                m *= 25;
            }
        }
    }
    return v;
}

//------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------

// Encryption/decryption section.

- (NSMutableURLRequest*)encryptRequest:(NSString*)request
{
    request = (request != nil) ? request : @"";     // Make sure request is not nil.  Empty is okay.

    NSString* urlStr = nil;
    NSData*   data   = nil;

    if ((_deviceKey == nil) || (_deviceKey.length == 0))
    {
        // This case (encoding 0) indicates a "test" pairing is to be used.  This only works for nondebug builds.
        urlStr = [NSString stringWithFormat:@"http://%@:%i/companion?enc=0&cid=%@", _targetIPAddr, COMPANION_PORT, testDeviceId];
        data   = [request dataUsingEncoding:NSUTF8StringEncoding];
    }
    else
    {
        // This case (encoding 1) encrypts.
        uint hi, lo;
        if (_impContext == NULL)    // If we have not created an encryption interface for this pairing yet, do so.
        {
            _companionKey = [self makeCompanionKey];
            long statusCode = CSParve64_OpenContext(&_boxContext, CompanionConfig, CompanionSBox);
            if (statusCode == 0)
            {
                GUID guid;
                if (GuidFromString([_deviceId cStringUsingEncoding:NSASCIIStringEncoding], &guid) != 0)
                    return nil;
                statusCode = CSParve64_Create(_boxContext, _companionKey, (BYTE*)&guid, sizeof(guid), &hi, &lo, &_impContext);
            }
            if (statusCode != 0)
                return nil;
            _contextHash = (((UINT64)hi) << 32) | lo;
        }
        uint utf8Len = [request lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        uint bffrLen = utf8Len + OverheadSize;
        bffrLen = (bffrLen + 0x07) & ~0x07;                                                 // Data must be a multiple of 8 bytes for the encrypt function
        
        NSMutableData* bffr = [[NSMutableData alloc] initWithLength:0];                     // Create buffer to hold encrypted request postData.
        BYTE  chunk[8];
        
        BytePtr debugBffr;
        
        UInt32ToBytes(utf8Len, chunk);                                                      // 4 bytes of length at header.
        [bffr appendBytes:chunk length:4];
        debugBffr = (BytePtr)[bffr bytes];   
        
        [bffr appendBytes:[request UTF8String] length:utf8Len];                            // postData goes after the header.
        memset(chunk, 0, sizeof(chunk));
        debugBffr = (BytePtr)[bffr bytes];   

        [bffr appendBytes:chunk length:(bffrLen - utf8Len - OverheadSize)];
        debugBffr = (BytePtr)[bffr bytes];   
            
        UInt64ToBytes(_contextHash, chunk);                                                 // Write hash at end of buffer.
        [bffr appendBytes:chunk length:8];
        debugBffr = (BytePtr)[bffr bytes];   
        
        CSParve64_Encode(_impContext, (BYTE*)[bffr bytes], bffr.length, &hi, &lo);          // Finally, encode the whole thing.  We now have the postData.
        debugBffr = (BytePtr)[bffr bytes];   
        
        _seqNum |= 1;
        _seqNum += 2;
        Byte signature[16];
        [self formatSignature:signature SequenceNumber:_seqNum Length:bffrLen];
            
        CSParve64_ComputeHash(_boxContext, _companionKey, signature, sizeof(signature), &hi, &lo);
        UINT64 hash = (((UINT64)hi) << 32) | lo;
        NSString* sig = [NSString stringWithFormat:@"%08X%08X%016llX", _seqNum, bffrLen, hash]; 
        
        urlStr = [NSString stringWithFormat:@"http://%@:%i/companion?hash=%@&cid=%@&seq=%08X", _targetIPAddr, COMPANION_PORT, sig, _deviceId, _seqNum];
        data   = [NSData dataWithData:bffr];
    }

    if ((urlStr == nil) || (data == nil))
        return nil;
    NSLog(@"%@", urlStr);
    NSURL*               url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest* req = [NSMutableURLRequest requestWithURL:url];
    [req setHTTPBody:data];
    [req addValue:@"text/xml" forHTTPHeaderField:@"Accept"];
    [req addValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [req addValue:[NSString stringWithFormat:@"%i", [data length]] forHTTPHeaderField:@"Content-Length"];
    req.HTTPMethod = @"POST";
    return req;
}

//------------------------------------------------------------------------------------------------------

// Upon receiving an encrypted response, it needs to be decrypted, using the same signature.

- (BOOL)decryptResponse:(NSMutableData*)response Headers:(NSDictionary*)headers
{
    if (([response length] == 0) || (_impContext == nil))
        return YES;
    
    if (headers == nil)
        return NO;
    
    NSString* rspSig = [headers objectForKey:@"X-Mediaroom-Companion-Signature"];
        
    uint   rspSeq;
    uint   rspLen;
    UINT64 rspHash;
    sscanf([rspSig cStringUsingEncoding:NSUTF8StringEncoding], "%08X%08X%016llX", &rspSeq, &rspLen, &rspHash);
    
    Byte signature[16];
    [self formatSignature:signature SequenceNumber:rspSeq Length:rspLen];

    uint hi, lo;
    CSParve64_ComputeHash(_boxContext, _companionKey, signature, sizeof(signature), &hi, &lo);
    UINT64 hash = (((UINT64)hi) << 32) | lo;
    
    if ([rspSig caseInsensitiveCompare:[NSString stringWithFormat:@"%08X%08X%016llX", rspSeq, rspLen, hash]] != NSOrderedSame)
        return NO;
    
    int seqDelta = _seqNum - rspSeq;
    if ((seqDelta < 0) || (seqDelta >= 1000))   // If returned sequence is bigger than ours, or we are way off ...
        _seqNum = (rspSeq | 1);                 // ... use returned sequence number.
    
    NSString* encoding = [headers objectForKey:@"Content-Encoding"];
    if ([encoding caseInsensitiveCompare:@"X-Mediaroom-Companion-Encoding"] == NSOrderedSame)
    {
        BytePtr b = (BytePtr)[response bytes];
        CSParve64_Decode(_impContext, b, [response length], &hi, &lo);
        UINT32 origLen = BytesToUInt32((BytePtr)[response bytes]);
        [response replaceBytesInRange:NSMakeRange(0, 4) withBytes:nil length:0];
        [response setLength:origLen];
    }    
    
    return YES;
}

- (BytePtr)makeCompanionKey
{
    const char* keyChars = [_deviceKey cStringUsingEncoding:NSASCIIStringEncoding];
    if (strlen(keyChars) != COMPANION_KEY_LENGTH_IN_BYTES * 2)
        return nil;

    BytePtr keyBytes = (BytePtr)malloc(COMPANION_KEY_LENGTH_IN_BYTES);

    for (int i = 0; i < COMPANION_KEY_LENGTH_IN_BYTES; ++i)
    {
        unsigned char hi, lo;
        if (hexToNibble(keyChars[i * 2],     &hi) != 0 
			|| hexToNibble(keyChars[i * 2 + 1], &lo) != 0) {
			free(keyBytes);
			return nil;
		}
        keyBytes[i] = (unsigned char)((hi << 4) | lo);
    }
    return keyBytes;
}

- (void)formatSignature:(BytePtr)signature SequenceNumber:(uint)seqNum Length:(uint)len
{
    UInt32ToBytes(seqNum, signature);
    UInt32ToBytes(len,    signature + 4);
    
    char c;
    unsigned int quads[4];
    sscanf([_targetIPAddr cStringUsingEncoding:NSUTF8StringEncoding], "%u%c%u%c%u%c%u", quads, &c, quads + 1, &c, quads + 2, &c, quads + 3);
    for (int i = 0; i < 4; ++i)
        signature[i + 8] = (Byte)quads[i];

    GUID guid;
    if (GuidFromString([_deviceId cStringUsingEncoding:NSASCIIStringEncoding], &guid) != 0)
        return;
    
    memcpy((void*)(signature + 12), (void *)&guid, 4);
}

//------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------

// When pairing, an initial incomplete pairing is created.  The response has the data to complete it.
// The application should call this after successfully pairing to acquire the other pairing data.
// Also, the "hello" command returns this same format, so easy updating of a pairing can be done by
// using this same method.

- (void)pairingCompletion:(NSData*)xmlData
{
    NSMutableDictionary *params;
    if(xmlData == nil) {
        // in this modularity, no status == 901 happens
        params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:900], @"status", nil];
    } else {
        MRPairingResponse* r = [[MRPairingResponse alloc] initWithData:xmlData];
        self.targetUsn     = r.targetUsn;
        self.targetName    = r.targetName;
        self.targetApiVers = r.targetApiVers;
        self.deviceId      = r.deviceId;
        self.deviceKey     = r.deviceKey;
        NSLog(@"%@", _deviceKey);
        self.tags          = r.tags;
        self.seqNum        = r.seqNum;
        
        _impContext = nil;
    
        if(allPairings == nil)
        allPairings = [[NSMutableDictionary alloc]init];

        bool redundant = false;
        for(NSString *pairingUid in allPairings) {
            MRPairing *pair = [allPairings objectForKey:pairingUid];
            if([pair.targetUsn isEqualToString:self.targetUsn]) {
                redundant = true;
                break;
            }
        }
        
        if(!redundant) {
            // setCurrentTarget:self;
            [allPairings setObject:self forKey:self.pairUid];
            params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:200], @"status", self.pairUid, @"pairingUid", nil];
        } else {
            params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:304], @"status", nil];
        }
        
    }
    
//    NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
//
//    [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
    
}

- (void)resultParsing:(NSData *)xmlData
{
    if(xmlData == nil) {
        NSMutableDictionary *params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:204], @"status", self.pairUid, @"pairingUid", nil];
        NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
        [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
    } else {
        NSString *responseText = [[NSString alloc]initWithData:xmlData encoding:NSUTF8StringEncoding];
        responseText = [responseText stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\\\""];
        NSMutableDictionary *params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:200], @"status", responseText, @"responseText",self.pairUid, @"pairingUid", nil];
        
        NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
        [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
        
    }
}

- (void)resultParsingFail:(NSData *)xmlData
{
    NSMutableDictionary *params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:900], @"status", self.pairUid, @"pairingUid", nil];
    NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
    [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
}

- (void)deletePair:(NSData *)xmlData
{
    [allPairings removeObjectForKey:self.pairUid];
    NSMutableDictionary *params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:204], @"status", self.pairUid, @"pairingUid", nil];
    NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
    [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
    
}

- (void)deletePairFail:(NSData *)xmlData
{
    NSMutableDictionary *params = [NSMutableDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithInt:404], @"status", self.pairUid, @"pairingUid", nil];
    NSMutableDictionary *toSend = [NSMutableDictionary dictionaryWithObjectsAndKeys:self.cbUid, @"cbUid", params, @"params", nil];
    [returnTarget performSelectorOnMainThread:returnMessage withObject:toSend waitUntilDone:NO];
}

- (void)encodeWithCoder:(NSCoder *)coder
{
	[coder encodeObject:self.targetIPAddr forKey:@"targetIPAddr"];
	[coder encodeObject:self.deviceId forKey:@"deviceId"];
	[coder encodeObject:self.deviceKey forKey:@"deviceKey"];

	[coder encodeObject:self.targetUsn forKey:@"targetUsn"];
	[coder encodeObject:self.targetName forKey:@"targetName"];
	[coder encodeObject:self.targetApiVers forKey:@"targetApiVers"];
	[coder encodeObject:self.tags forKey:@"tags"];
	[coder encodeInteger:self.seqNum forKey:@"seqNum"];
}

- (id)initWithCoder:(NSCoder*)coder
{
	self = [[MRPairing alloc] init];
	if (self != nil) {
		self.targetIPAddr = [coder decodeObjectForKey:@"targetIPAddr"];
		self.deviceId = [coder decodeObjectForKey:@"deviceId"];
		self.deviceKey = [coder decodeObjectForKey:@"deviceKey"];
		self.targetUsn = [coder decodeObjectForKey:@"targetUsn"];
		self.targetName = [coder decodeObjectForKey:@"targetName"];
		self.targetApiVers = [coder decodeObjectForKey:@"targetApiVers"];
		self.tags = [coder decodeObjectForKey:@"tags"];
		self.seqNum = [coder decodeIntegerForKey:@"seqNum"];
	}

	return self;
}

- (void)dealloc
{
    if (_companionKey != NULL)
    {
        free(_companionKey);
        _companionKey = nil;
    }
    
    if (_impContext != NULL)
    {
        CSParve64_Destroy(_impContext);
        _impContext = NULL;
    }
    if (_boxContext != NULL)
    {
        CSParve64_CloseContext(_boxContext);
        _boxContext = NULL;
    }
}

- (void)response:(id)target message:(SEL)message
{
    returnTarget = target;
    returnMessage = message;
}

@end

//------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------

// Pairing (and hello) response parsing.

@implementation MRPairingResponse

@synthesize targetUsn     = _targetUsn;
@synthesize targetName    = _targetName;
@synthesize targetApiVers = _targetApiVers;
@synthesize deviceId      = _deviceId;
@synthesize deviceKey     = _deviceKey;
@synthesize tags          = _tags;
@synthesize seqNum        = _seqNum;

-(id)initWithData:(NSData*)xmlData
{
    if ((self = [super init]))
    {
        if (xmlData && [xmlData length] > 0)
        {
            NSXMLParser* parser = [[NSXMLParser alloc] initWithData:xmlData];
            [parser setShouldProcessNamespaces:YES];
            [parser setDelegate:self];
            [parser parse];
        }
    }
    return self;
}

- (void)parser:(NSXMLParser *)parser didStartElement:(NSString *)elementName namespaceURI:(NSString *)namespaceURI qualifiedName:(NSString *)qName attributes:(NSDictionary *)attributeDict
{
    if ([elementName compare:@"response" options:NSCaseInsensitiveSearch] == 0)
    {
        NSString* usn = [attributeDict objectForKey:@"usn"];
        if (usn)
            self.targetUsn = usn;

        NSString* name = [attributeDict objectForKey:@"name"];
        if (name)
            self.targetName = name;
 
        NSString* api = [attributeDict objectForKey:@"api"];
        if (api)
            self.targetApiVers = api;
    }

    if ([elementName compare:@"device" options:NSCaseInsensitiveSearch] == 0)
    {
        NSString* cid = [attributeDict objectForKey:@"cid"];
        if (cid)
            self.deviceId = cid;

        NSString* key = [attributeDict objectForKey:@"key"];
        if (key)
            self.deviceKey = key;

        NSString* tags = [attributeDict objectForKey:@"tags"];
        if (tags)
            self.tags = tags;

        NSString* seq = [attributeDict objectForKey:@"seq"];
        if (seq)
            self.seqNum = [seq integerValue];
    }
}

-(void)dealloc
{
}

@end

//------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------

// Helper functions.

static void UInt32ToBytes(UINT32 n, BYTE* data)
{
    data[0] = (BYTE)(n >> 24);
    data[1] = (BYTE)(n >> 16);
    data[2] = (BYTE)(n >> 8);
    data[3] = (BYTE)(n);
}

static void UInt64ToBytes(UINT64 n, BYTE* dest)
{
    dest[0] = (BYTE)(n >> 56);
    dest[1] = (BYTE)(n >> 48);
    dest[2] = (BYTE)(n >> 40);
    dest[3] = (BYTE)(n >> 32);
    dest[4] = (BYTE)(n >> 24);
    dest[5] = (BYTE)(n >> 16);
    dest[6] = (BYTE)(n >> 8);
    dest[7] = (BYTE)n;
}

static UINT32 BytesToUInt32(BYTE* data)
{
    UINT32 result;
    
    result  = data[0] << 24;
    result |= data[1] << 16;
    result |= data[2] << 8;
    result |= data[3];
    
    return result;
}

