//
//  PublicKeyPinningConnectionDelegate.m
//  PublicKeyPinningExample
//
//  Created by Dan Zinngrabe on 7/22/14.
//  Copyright (c) 2014 Dan Zinngrabe. All rights reserved.
//

#import "PublicKeyPinningConnectionDelegate.h"
#import <Security/Security.h>

@implementation PublicKeyPinningConnectionDelegate

#pragma mark NSURLConnectionDelegate methods

- (void)connection:(NSURLConnection *)__unused connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    NSString                *authenticationMethod       = nil;
    NSURLCredential         *credential                 = nil;
    NSURLProtectionSpace	*protectionSpace            = nil;
    
    authenticationMethod = [[challenge protectionSpace] authenticationMethod];
    protectionSpace = [challenge protectionSpace];
    
    if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]){
        // Perform our customized authentication.
        credential = [self credentialForServerTrustInProtectionSpace:protectionSpace];
        
        if (credential != nil){
            [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
        } else {
            [[challenge sender] cancelAuthenticationChallenge:challenge];
        }
    } else {
        [[challenge sender] performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

#pragma mark Private methods

/**
 *  Returns the credential to use for the given protection space protected by server trust.
 *
 *  @param protectionSpace <#protectionSpace description#>
 *
 *  @return Returns nil if the evaluation of the protection space trust resulted in an untrustable value.
 */

- (NSURLCredential *) credentialForServerTrustInProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
	NSURLCredential			*result				= nil;
	OSStatus 				status 				= errSecSuccess;
	SecTrustResultType		trustResult			= kSecTrustResultFatalTrustFailure;
	SecTrustRef				trust				= NULL;
    
	
    result = [[NSURLCredentialStorage sharedCredentialStorage] defaultCredentialForProtectionSpace:protectionSpace];
    if (result == nil){
		trust = [protectionSpace serverTrust];
		status = SecTrustEvaluate(trust, &trustResult);
		if (status == errSecSuccess){
			switch (trustResult){
			    case kSecTrustResultProceed:
			    case kSecTrustResultUnspecified:{
			        if ([self canAllowServerTrustForProtectionSpace:protectionSpace]){
			            result = [NSURLCredential credentialForTrust:trust];
			            [[NSURLCredentialStorage sharedCredentialStorage] setDefaultCredential:result forProtectionSpace:protectionSpace];
			        }
			    }
			        break;
			    default:
			        break;
			}
		}
	}
	return result;
}

/**
 *  Returns the result of evaluating the server credential against local truth.
 *
 *  @param protectionSpace The protection space.
 *
 *  @return YES if the server credential provided for this protection space evaluates as trusted when compared against local data.
 */

- (BOOL) canAllowServerTrustForProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    BOOL                    result              = NO;
    SecKeyRef               serverKey           = NULL;
    SecCertificateRef       localCertificate    = NULL;
    SecTrustRef             serverTrust         = NULL;
    
    // Extract the public key from the server credential
    serverTrust = [protectionSpace serverTrust];
    serverKey = SecTrustCopyPublicKey(serverTrust);
    
    localCertificate = [self localCertificateForHost:[protectionSpace host]];
    // Compare the server public key against our local public key. This is not a very good way to compare them, but it works.
    if (localCertificate != NULL){
        SecTrustResultType  trustResult;
        SecCertificateRef	localCertificates[1];
        CFArrayRef          anchorCertificates  = NULL;
        OSStatus            status              = errSecSuccess;
        
        localCertificates[0] = localCertificate;
        anchorCertificates = CFArrayCreate(NULL, (void *)localCertificates, 1, &kCFTypeArrayCallBacks);
        SecTrustSetAnchorCertificates(serverTrust, anchorCertificates);
        SecTrustSetAnchorCertificatesOnly(serverTrust, YES);
        
        if (anchorCertificates != NULL){
            CFRelease(anchorCertificates);
        }
        
        status = SecTrustEvaluate(serverTrust, &trustResult);
        result = (status == noErr) && ((trustResult == kSecTrustResultUnspecified) || (trustResult == kSecTrustResultProceed));
        
    } else {
        result = NO;
    }
    return result;
}


/**
 *  Load the certificate from local storage.
 *  This will attempt to find a local DER encoded certificate file for the specified host.
 *
 *  @param host The host
 *
 *  @return The certificate for this host, NULL if none could be found or decoded.
 */

- (SecCertificateRef) localCertificateForHost:(NSString *)host {
    NSData              *certData       = nil;
    SecCertificateRef   result          = NULL;
    
    // This will look for a file within the current bundle named hostname.der
    // i.e. "www.google.com.der"
    // The expectation is that the data is in OpenSSL DER format. This should be the server credential you expect for this host.
    certData = [NSData dataWithContentsOfURL:[[NSBundle bundleForClass:[self class]] URLForResource:host withExtension:@"der" ] ];
    if (certData != nil){
        result = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certData);
    }
    
    return result;
}


@end
