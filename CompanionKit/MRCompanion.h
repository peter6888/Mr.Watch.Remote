//--------------------------------------------------------------------------
// <copyright file="MRCompanion.h" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Companion communication class.
// </summary>
//--------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import "MRPairing.h"

//------------------------------------------------------------------------------------------------------

#define ERR_DOMAIN_MRCOMPANION @"MRCOMPANION"
#define ERR_CODE_CONNECTION_FAILED 1000

//------------------------------------------------------------------------------------------------------

@interface MRCompanion : NSObject <NSURLConnectionDelegate> {
@private
    MRPairing*     _pairing;
    NSString*      _postData;
    NSInteger      _timeout;
    id             _state;
    NSInteger      _lastStatus;
    NSMutableData* _responseData;

    // NSInvocation* _response;
    id _responseTarget;
    SEL _responseMessage;
    // NSInvocation* _error;
    id _errorTarget;
    SEL _errorMessage;
    NSDictionary* _responseHeaders;

    NSURLConnection* _connection;
}
@property (nonatomic, retain)    MRPairing*     pairing;
@property (nonatomic, retain)    NSString*      postData;
@property (nonatomic, readwrite) NSInteger      timeout;        // Connection timeout
@property (nonatomic, retain)    id             state;          // Custom object to retain app-specific state.
@property (nonatomic, readwrite) NSInteger      lastStatus;     // Last status from response
@property (nonatomic, retain)    NSMutableData* responseData;

// enable a pairing for STB use ip address, and specify pairing Uid for it
+ (void) enablePairingWithIp : (NSString*) ipAddress forUid:(NSString *)pairingUid;

// Create companion object with a pairing as the target (STB).
- (MRCompanion*)initWithPairing:(MRPairing*)pairing;

// Bind optional response handler.
- (MRCompanion*)response:(id)target message:(SEL)message;

// Bind optional error handler.
- (MRCompanion*)error:(id)target message:(SEL)message;

// Begin the async request with the specified data.
- (void)send:(NSString*)postData;

- (void)sendThroughSession:(NSString *)postData;

- (void)sendMsg : (NSString *) postData :(NSString*) withUid;

// Cancel a potentially in-progress request.
- (void)cancel;

- (void)pairingCompletion;

@end

//------------------------------------------------------------------------------------------------------

// You may enforce these protocols in your class if you wish.  Do so if you have a single callback method
// that will handle all responses.  If instead you have different handlers for different commands, skip this
// and simply create methods of any name matching the below parameters.

@protocol MRCompanionResponse <NSObject>
@required
// This callback method is invoked when the request to companion API to STB succeeds / responds.
- (void)response:(MRCompanion*)response;
@end

@protocol MRCompanionError <NSObject>
@required
// This callback method is invoked when there is an error making the request to the STB
//- (void)error:(MRCompanion*)response message:(NSError*)error;
- (void)error:(MRCompanion*)response;

@end

