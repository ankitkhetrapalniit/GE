//
//  CertHelper.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/29/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CertHelper : NSObject

+(SecKeyRef)getPublicCertFromX509Data:(NSData *)certData;
+(SecKeyRef)getPublicCertUsingModulus:(NSData*)modulus exponent:(NSData*)exponent;
+(SecKeyRef)getPublicCertFromKeyChainByIssuer:(NSString *)issuer andKID:(NSString *)kid;
+(BOOL)storePublicCertInKeyChain:(SecKeyRef)key issuer:(NSString *)issuer kid:(NSString *)kid;
+(SecKeyRef)getAccessTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid;
+(SecKeyRef)getIDTokenSigningKeyFromIssuer:(NSString *)issuer andKID:(NSString *)kid;

@end
