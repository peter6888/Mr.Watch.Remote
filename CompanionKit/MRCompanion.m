//--------------------------------------------------------------------------
// <copyright file="MRCompanion.m" company="Ericsson">
//  Copyright (c) Ericsson, Inc. All rights reserved.
// </copyright>
// <summary>
// Companion communication class.
// </summary>
//--------------------------------------------------------------------------

// NOTE:  The order of responses is not guaranteed to be the same as the order
//        of the requests.  If the application does not wait for either a
//        response or failure for the requests, a request queue should be
//        added to this class, only issuing the next request when the previous
//        request has a response or failure (due to error or timeout).
//        If this support is added, a retry and cancellation mechanism should
//        also be included in the queue management.

#import "MRCompanion.h"

//------------------------------------------------------------------------------------------------------

@implementation MRCompanion
@synthesize pairing      = _pairing;
@synthesize postData     = _postData;
@synthesize timeout      = _timeout;
@synthesize state        = _state;
@synthesize responseData = _responseData;
@synthesize lastStatus   = _status;

// Given a pairing, create a MRCompanion object to issue a command with.
- (id)initWithPairing:(MRPairing*)pairing;
{
    if ((self = [super init]))
    {
        _pairing = pairing;
        _timeout = 5000;
    }
    return self;
}

// Register the response callback, if there is to be one.
// If there is one, it is the callback's responsibility to release the successful response.
// If none is specified, when the response is complete, the object will be released.
- (id)response:(id)target message:(SEL)message
{
    _responseTarget = target;
    _responseMessage = message;
    return self;
}

// Register the error callback, if there is to be one.
// If there is one, it is the callback's responsibility to release the error response.
// If none is specified, if an error is encountered, the object will be released.
- (id)error:(id)target message:(SEL)message
{
    _errorTarget = target;
    _errorMessage = message;
    return self;
}

+ (void) enablePairingWithIp : (NSString*) ipAddress forUid:(NSString *)pairingUid {
    MRPairing* pairing = [[MRPairing alloc] initWithData:ipAddress DeviceId:@"" Key:@"" Name:@""];
    pairing.pairUid = pairingUid;
    pairing.cbUid = @"";
    MRCompanion *mrCompanion = [[MRCompanion alloc] initWithPairing:pairing];
    [mrCompanion sendThroughSession:@"op=hello"];
}

// Begin the async companion request.  This takes a reference.  The application can release.
// The application should also release on any callback.  If one is not specified, then the
// release is automatic.
- (void)send:(NSString*)postData
{
    [self cancel];
    _postData = [postData copy];
    NSURLRequest* req = [_pairing encryptRequest:postData];
    if(req == nil) NSLog(@"encrypt error");
    _connection = [[NSURLConnection alloc] initWithRequest:req delegate:self];

}

- (void) sendThroughSession:(NSString *)postData {
    [self cancel];
    self.lastStatus = 0;
    _postData = [postData copy];
    NSURLRequest* req = [_pairing encryptRequest:postData];
    NSLog(@"postData:%@", _postData);
    
    if(req == nil) NSLog(@"encrypt error");
    
    NSURLSessionConfiguration *sessionConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig];
    NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:req
                                                completionHandler:^(NSData * __nullable data, NSURLResponse * __nullable response, NSError * __nullable error) {
                                                    NSLog(@"----data session----");
                                                    NSLog(@"data length: %u", (unsigned int)[data length]);
                                                    NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse*)response;
                                                    self.lastStatus = [httpResponse statusCode];
                                                    NSLog(@"Http status code: %ld", [httpResponse statusCode]);
                                                    
                                                    if (_responseData == nil)
                                                        _responseData = [data mutableCopy];
                                                    else
                                                        [_responseData appendData:data];
                                                    
                                                    _responseHeaders = [httpResponse allHeaderFields];
                                                    
                                                    if(self.lastStatus < 200 || self.lastStatus > 299) {
                                                        NSLog(@"NSError.FailureReason:%@", error);
                                                    }
                                                    else {
                                                        // "pairing"
                                                        NSRange isRange = [postData rangeOfString:@"op=hello" options:NSCaseInsensitiveSearch];
                                                        
                                                        if(isRange.location==0) {
                                                            NSLog(@"pairing...");
                                                            
                                                            BOOL success = [_pairing decryptResponse:_responseData Headers:_responseHeaders];
                                                            if(success)
                                                            {
                                                                [self pairingCompletion];
                                                            }
                                                        }

                                                        NSLog(@"ip:%@, device:%@, key:%@, name:%@",
                                                              _pairing.targetIPAddr,
                                                              _pairing.deviceId,
                                                              _pairing.deviceKey,
                                                              _pairing.targetName);
                                                    }
                                                    NSLog(@"--------------------");
                                                }];
    [dataTask resume];
}

- (void)cancel
{
    if (_connection)
    {
        [_connection cancel];
        _connection = nil;
    }
}

// A pairing used to issue a companion pairing request is only partially populated.  When a pairing
// response is received, this should be called to complete the pairing structure.  The application
// should then save off the pairing as it sees fit.  There is also a global currentTarget facility
// that an application can use.
- (void)pairingCompletion
{
    MRPairing* newPairing = [[MRPairing alloc] initWithData:_pairing.targetIPAddr DeviceId:_pairing.deviceId Key:_pairing.deviceKey Name:_pairing.targetName];
    newPairing.cbUid = _pairing.cbUid;
    newPairing.pairUid = _pairing.pairUid;
    [newPairing pairingCompletion:_responseData];
    self.pairing = newPairing;
}

- (void)sendMsg:(NSString *)postData :(NSString *)pairingUid {
    MRPairing *pair = nil;
    NSString *cbUid = @"";
    
    if(pairingUid==nil) {
        NSLog(@"pairingUid is nil");
        return;
    }
    
    pair = [MRPairing pairingAtUid:pairingUid];
    
    if(pair ==nil) {
        NSLog(@"no pairing found for Uid %@", pairingUid);
    }

    pair.cbUid = cbUid;
    [self sendThroughSession:postData];
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)urlResponse
{
    NSLog(@"didReceiveResponse");
    NSHTTPURLResponse *response = (NSHTTPURLResponse*)urlResponse;
    _responseHeaders = [response allHeaderFields];
    
    int sc = [response statusCode];
    if ((sc < 200) || (sc > 299))
    {
        [self cancel];

        NSDictionary *userInfo = [NSDictionary dictionaryWithObject:[NSNumber numberWithInt:[response statusCode]] forKey:@"HttpStatus"];
        NSError *error = [NSError errorWithDomain:ERR_DOMAIN_MRCOMPANION code:[response statusCode] userInfo:userInfo];
        [self connection:connection didFailWithError:error];
        
        NSLog(@"Companion request failed with http status code : %d", [response statusCode]);    
    }
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{    
	if (_responseData == nil)
		_responseData = [data mutableCopy];
	else
		[_responseData appendData:data];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"Companion request failed with error : %@", (error != nil) ? [error localizedDescription] : @"unknown");    
    if (_errorMessage && _errorTarget)
    {
        NSDictionary *userInfo = (error != nil) ? [error userInfo] : nil;
        error = [NSError errorWithDomain:ERR_DOMAIN_MRCOMPANION code:ERR_CODE_CONNECTION_FAILED userInfo:userInfo];
        //[_error setArgument:&self  atIndex:2];
        //[_error setArgument:&error atIndex:3];
        //[_error invoke];
        
        [_errorTarget performSelectorOnMainThread:_errorMessage withObject:error waitUntilDone:NO];

        return;
    } else {
        [_responseTarget performSelectorOnMainThread:_responseMessage withObject:_responseData waitUntilDone:NO];
    }
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    NSLog(@"MRCompanion connectionDidFinishLoading");
    
    if (_responseMessage && _responseTarget)
    {
        BOOL success = [_pairing decryptResponse:_responseData Headers:_responseHeaders];
        if (success == YES)
        {
            //[_response setArgument:&self atIndex:2];
            //[_response invoke];

            [_responseTarget performSelectorOnMainThread:_responseMessage withObject:_responseData waitUntilDone:NO];
            
            return;
        }
        // If request encrypted correctly, we would get a response with the same encryption, so should always succeed at decrypt.
    }
}

- (void)dealloc
{
    [self cancel];
}

@end

