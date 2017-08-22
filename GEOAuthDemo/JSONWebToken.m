//
//  JSONWebToken.m
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/24/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "JSONWebToken.h"
#import "OIDCHelper.h"
#import "CertHelper.h"
#import "Utils.h"

#import "SHA.h"
#import "HMAC.h"
#import "RSAPKCS1_5.h"

@implementation JSONWebToken

@synthesize jwt = _jwt;
@synthesize header = _header;
@synthesize payload = _payload;
@synthesize signature = _signature;
@synthesize signed_parts = _signed_parts;

@synthesize parsed_header = _parsed_header;
@synthesize parsed_payload = _parsed_payload;

@synthesize type = _type;
@synthesize signing_cert = _signing_cert;

@synthesize signature_comments = _signature_comments;
@synthesize validation_comments = _validation_comments;

@synthesize issuer = _issuer;
@synthesize kid = _kid;
@synthesize signing_alg = _signing_alg;


-(id) initWithToken:(NSString *)jsonWebToken ofType:(NSString *)tokenType
{
    self = [super init];
    
    if (self)
    {
        _signature_comments = @"";
        _validation_comments = [[NSMutableArray alloc] init];
        
        NSError *error = nil;
        
        // Split by dots
        NSArray *idTokenComponents = [jsonWebToken componentsSeparatedByString:@"."];
        
        // base64 decode [0] (header) and [1] (payload)
        
        // Parse the JWT Header - expecting alg, kid
        NSString *idTokenHeaderValue = [idTokenComponents objectAtIndex:0];
        NSData *idTokenHeaderData = [Utils base64DecodeString:idTokenHeaderValue];
        
        _header = idTokenHeaderData;
        _parsed_header = [NSJSONSerialization JSONObjectWithData:idTokenHeaderData options:kNilOptions error:&error];
        _signing_alg = [_parsed_header objectForKey:@"alg"];
        _kid = [_parsed_header objectForKey:@"kid"];
        
        // Parse the JWT Payload - not guaranteed to be JSON but for our OIDC purposes it will be
        NSString *idTokenPayloadValue = [idTokenComponents objectAtIndex:1];
        NSData *idTokenPayloadData = [Utils base64DecodeString:idTokenPayloadValue];
        
        _payload = idTokenPayloadData;
        _parsed_payload = [NSJSONSerialization JSONObjectWithData:idTokenPayloadData options:kNilOptions error:&error];
        _issuer = [_parsed_payload objectForKey:@"iss"];
        _signature = [Utils base64DecodeString:[idTokenComponents objectAtIndex:2]];
        _signed_parts = [NSString stringWithFormat:@"%@.%@", idTokenHeaderValue, idTokenPayloadValue];

        // Storing this value for use later:  id_token or access_token
        _type = tokenType;
        
        if([[_signing_alg substringToIndex:2] isEqualToString:@"RS"]) { // Asymmetric so go and get the cert
            
            // cache the public cert
            if ([_type isEqualToString:@"access_token"]) {
                _signing_cert = [CertHelper getAccessTokenSigningKeyFromIssuer:_issuer andKID:_kid];
            } else {
                // For id_token we get form the JWKS
                _signing_cert = [CertHelper getIDTokenSigningKeyFromIssuer:_issuer andKID:_kid];
            }
            
        }
    }
    
    return self;
}

// Signature Verification
-(BOOL) validateSignature
{
    if ([[_signing_alg substringToIndex:2] isEqualToString:@"HS"]) { // Symmetric (HMAC w/SHA hash)

        return NO; // need to use validateSignatureUsingSymmetricKey
        
    } else if([[_signing_alg uppercaseString] isEqualToString:@"NONE"]) { // No signing
        
        return YES; // nothing to verify - so I guess the signature is good?
        
    } else if([[_signing_alg substringToIndex:2] isEqualToString:@"RS"]) { // Asymmetric (RSA PKCS v1.5 w/ SHA hash)
        
        if (_signing_cert != nil) {
            
            NSInteger SHA_Digest_Length = [[_signing_alg substringFromIndex:2] integerValue];
            
            RSAPKCS1_5 *RSAHelper = [[RSAPKCS1_5 alloc] initWithData:[_signed_parts dataUsingEncoding:NSUTF8StringEncoding] andCert:_signing_cert];
            [RSAHelper setSHA_DigestLength:SHA_Digest_Length];
            return [RSAHelper verifySignature:_signature];
            
        } else {
            _signature_comments = [NSString stringWithFormat:@"Unable to find key: %@", _kid];
            return NO;
        }
        
    } else {
        _signature_comments = [NSString stringWithFormat:@"Unsupported algorithm: %@", _signing_alg];
        return NO;
    }
    
    return NO;
}

-(BOOL) validateSignatureUsingSymmetricKey:(NSString *)symmetricKey
{
    if ([[_signing_alg substringToIndex:2] isEqualToString:@"HS"]) { // Symmetric (HMAC w/SHA hash)
        
        NSInteger HMAC_Digest_Length = [[_signing_alg substringFromIndex:2] integerValue];
        
        HMAC *HMACHelper = [[HMAC alloc] initWithData:[_signed_parts dataUsingEncoding:NSASCIIStringEncoding] andKey:[symmetricKey dataUsingEncoding:NSASCIIStringEncoding]];
        [HMACHelper setSHA_DigestLength:HMAC_Digest_Length];
        return [HMACHelper verifySignature:_signature];
        
    } else if([[_signing_alg uppercaseString] isEqualToString:@"NONE"]) { // No signing
        
        return YES; // nothing to verify - so I guess the signature is good?
        
    } else if([[_signing_alg substringToIndex:2] isEqualToString:@"RS"]) { // Asymmetric (RSA PKCS v1.5 w/ SHA hash)

        return [self validateSignature];
        
    } else {
        _signature_comments = [NSString stringWithFormat:@"Unsupported algorithm: %@", _signing_alg];
        return NO;
    }
    
    return NO;
}

-(id) getValueFromPayload:(NSString *)key
{
    return [_parsed_payload objectForKey:key];
}

-(NSDictionary *) getPayloadAsDictionary
{
    return [[NSDictionary alloc] initWithDictionary:_parsed_payload];
}


@end
