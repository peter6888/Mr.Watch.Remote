//
//  InterfaceController.m
//  Mr.Watch.Remote WatchKit Extension
//
//  Created by Peter Li on 6/30/15.
//  Copyright © 2015 Peter Li. All rights reserved.
//

#import "InterfaceController.h"


@interface InterfaceController()

@end


@implementation InterfaceController
- (IBAction)pairMediaroomClient {
    NSString *pairingUid = @"1";
    [MRCompanion enablePairingWithIp:@"172.29.38.212" forUid:pairingUid];
}

- (void)awakeWithContext:(id)context {
    [super awakeWithContext:context];

    // Configure interface objects here.
}

- (void)willActivate {
    // This method is called when watch view controller is about to be visible to user
    [super willActivate];
}

- (void)didDeactivate {
    // This method is called when watch view controller is no longer visible
    [super didDeactivate];
}

@end



