//
//  PublicKeyPinningConnectionDelegate.h
//  PublicKeyPinningExample
//
//  Created by Dan Zinngrabe on 7/22/14.
//  Copyright (c) 2014 Dan Zinngrabe. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 *  Implements a NSURLConnectionDelegate that performs "SSL pinning". The remote certificate will be checked against a local store of certificates.
 */

@interface PublicKeyPinningConnectionDelegate : NSObject<NSURLConnectionDelegate>

@end
