//
//  OIDCHelper.m
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/17/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "OIDCHelper.h"
#import "JSONWebToken.h"
#import "CertHelper.h"
#import "SHA.h"
#import "HMAC.h"
#import "RSAPKCS1_5.h"
#import "Utils.h"

#import <Security/Security.h>


@implementation OIDCHelper

-(id) init
{
    self = [super init];
    
    if (self)
    {
    }
    
    return self;
}

+(BOOL) validateAccessToken:(JSONWebToken *)accessToken forClient:(OAuth2Client *)client
{
    NSLog(@"---[ Validating JWT OAuth2 access token ]------");

    // No defined rules to check the access token.  But we should test to our applications satisfaction, ie:
    // Issuer is trusted
    // Audience is me
    // Token hasn't expired
    // Signature is valid

    // Does the issuer match the issuer (iss) in the token.
    if (![self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[accessToken getPayloadAsDictionary] okayToNotExist:NO]) {
        NSLog(@"Issuer mismatch!");
        [[accessToken validation_comments] addObject:@"Issuer mismatch"];
        return NO;
    }
    
    // client_id SHOULD match the client_id that requested the token
    if (![self checkValue:[client getOAuthParameter:kOAuth2ParamClientId] forKey:@"client_id" inDictionary:[accessToken getPayloadAsDictionary] okayToNotExist:NO]) {
        NSLog(@"Audience mismatch!");
        [[accessToken validation_comments] addObject:@"Audience mismatch"];
        return NO;
    }

    // token MUST not have expired
    if (![self validateTimeClaimForToken:accessToken Claim:@"exp" skewSeconds:0])
    {
        NSLog(@"Token has expired!");
        [[accessToken validation_comments] addObject:@"Token has expired"];
        return NO;
    }

    // validate the signature
    if (![self validateSignatureForToken:accessToken]) {
        NSLog(@"Invalid signature!");
        [[accessToken validation_comments] addObject:@"Invalid signature"];
        return NO;
    }
    
    NSLog(@"---[ Verification Complete ]------");
    return YES;
}

+(BOOL) validateIDTokenUsingBasicClientProfile:(JSONWebToken *)idToken forClient:(OAuth2Client *)client {
    // Basic Client Profile (OIDC Core Section 3.1.3.7)
    
    // #1 - Decrypt the token if encrypted
    // Not Applicable - Token not encrypted
    
    // #2 - Does the issuer match the issuer (iss) in the token.
    if (![self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[idToken getPayloadAsDictionary] okayToNotExist:NO]) {
        NSLog(@"Issuer mismatch!");
        [[idToken validation_comments] addObject:@"Issuer mismatch"];
        return NO;
    }
    
    // #3 - Does the audience (aud) match the OAuth client id.
    // #4 - Does the token contain multiple audiences.
    // #5 - Validate the azp claim if present
    if (![self validateAudienceForToken:idToken Audience:[client getOAuthParameter:kOAuth2ParamClientId]]) {
        NSLog(@"Audience mismatch!");
        [[idToken validation_comments] addObject:@"Audience mismatch"];
        return NO;
    }
    
    // #6, 7 & 8 - Verify the signature (optional)
    // The id_token was received directly from token endpoint over TLS, therefore signature verification is optional.");
    // However, because we may be using a cached token, lets validate the certificate to be sure:
    if (![self validateSignatureForToken:idToken]) {
        NSLog(@"Invalid signature!");
        [[idToken validation_comments] addObject:@"Invalid signature"];
        return NO;
    }
    
    // #9 - Current time before id_token expiry (exp)
    if (![self validateTimeClaimForToken:idToken Claim:@"exp" skewSeconds:0])
    {
        NSLog(@"Token has expired!");
        [[idToken validation_comments] addObject:@"Token has expired"];
        return NO;
    }
    
    // #10 - Was the token issued within acceptable timeframe (iat)
    // Client Specific - We will used a static value of 60 mins skew (ie token must have been issued within the last 60 mins)
    if (![self checkTimeIsSameOrEarlierForClaim:@"iat" inToken:idToken skewSeconds:-3600])
    {
        NSLog(@"Token was issued too long ago!");
        [[idToken validation_comments] addObject:@"Token was issued too long ago"];
        return NO;
    }
    
    // #11 - Does the nonce match the value sent in the authentication request
    // Only REQUIRED if the Nonce parameter is present - should also check the nonce for replays etc
    if(![self checkValue:[client getOAuthParameter:kOAuth2ParamNonce] forKey:@"nonce" inDictionary:[idToken getPayloadAsDictionary] okayToNotExist:YES]) {
        NSLog(@"Nonce was present and does not match!");
        [[idToken validation_comments] addObject:@"Nonce was present and does not match"];
        return NO;
    }
    
    // #12 - Is the acr value appropriate for the requested authentication
    // Client specific - could test this to say - I expected multi-factor authentication and only got single-factor so fail.
    
    // #13 - Is the auth_time within an acceptable range
    // Client specific - if auth_time is present - then user must have authenticated > x mins ago.
    
    NSLog(@"ID Token validation complete");
    return YES;
}

+(BOOL) validateIDTokenUsingImplicitClientProfile:(JSONWebToken *)idToken forClient:(OAuth2Client *)client {
    // Implicit Client Profile (OIDC Core Section 3.1.3.7 + additions for Implicit profile 3.2.2.11)
    
    // #1 - Decrypt the token if encrypted
    // Not Applicable - Token not encrypted
    
    // #2 - Does the issuer match the issuer (iss) in the token.
    if (![self checkValue:[client baseUrl] forKey:@"iss" inDictionary:[idToken getPayloadAsDictionary] okayToNotExist:NO]) {
        NSLog(@"Issuer mismatch!");
        [[idToken validation_comments] addObject:@"Issuer mismatch"];
        return NO;
    }
    
    // #3 - Does the audience (aud) match the OAuth client id.
    // #4 - Does the token contain multiple audiences.
    // #5 - Validate the azp claim if present
    if (![self validateAudienceForToken:idToken Audience:[client getOAuthParameter:kOAuth2ParamClientId]]) {
        NSLog(@"Audience mismatch!");
        [[idToken validation_comments] addObject:@"Audience mismatch"];
        return NO;
    }
    
    // #6, 7 & 8 - Verify the signature (optional)
    // For the Implicit profile, signature verification is REQUIRED
    if (![self validateSignatureForToken:idToken]) {
        NSLog(@"Invalid signature!");
        [[idToken validation_comments] addObject:@"Invalid signature"];
        return NO;
    }
    
    // #9 - Current time before id_token expiry (exp)
    if (![self validateTimeClaimForToken:idToken Claim:@"exp" skewSeconds:0])
    {
        NSLog(@"Token has expired!");
        [[idToken validation_comments] addObject:@"Token has expired"];
        return NO;
    }
    
    // #10 - Was the token issued within acceptable timeframe (iat)
    // Client Specific - We will used a static value of 60 mins skew (ie token must have been issued within the last 60 mins)
    if (![self checkTimeIsSameOrEarlierForClaim:@"iat" inToken:idToken skewSeconds:-3600])
    {
        NSLog(@"Token was issued too long ago!");
        [[idToken validation_comments] addObject:@"Token was issued too long ago"];
        return NO;
    }
    
    // #11 - Does the nonce match the value sent in the authentication request
    // For the Implicit profile, Nonce checking is REQUIRED
    if(![self checkValue:[client getOAuthParameter:kOAuth2ParamNonce] forKey:@"nonce" inDictionary:[idToken getPayloadAsDictionary] okayToNotExist:NO]) {
        NSLog(@"Nonce does not match!");
        [[idToken validation_comments] addObject:@"Nonce does not match"];
        return NO;
    }
    
    // #12 - Is the acr value appropriate for the requested authentication
    // Client specific - could test this to say - I expected multi-factor authentication and only got single-factor so fail.
    
    // #13 - Is the auth_time within an acceptable range
    // Client specific - if auth_time is present - then user must have authenticated > x mins ago.
    
    return YES;
}


+(BOOL) validateIDToken:(JSONWebToken *)idToken forClient:(OAuth2Client *)client
{
    // Determine the validation requirements based on the response_type:
    // - code == Basic Client Profile (scope contains openid)
    // - token == OAuth2 implicit grant (if scope contains openid, then userinfo possible)
    // - id_token == Implicit, no Access Token (no userinfo, just id_token)
    // - token id_token == Implicit Client Profile (scope contains openid)
    // - code token ==
    // - code id_token == Hybrid flow (Uses Implicit rules / has at_hash and c_hash)
    // - code token id_token == Hybrid flow (Uses Implicit rules / has at_hash and c_hash)
    
    if (idToken != nil) {
        
        NSLog(@"Validating id_token for grant type %@", [client getOAuthParameter:kOAuth2ParamResponseType]);
        
        if ([[client getOAuthParameter:kOAuth2ParamResponseType] isEqual:@"code"]) {
            // Validate id_token received via OIDC Basic Client Profile
            
            return [self validateIDTokenUsingBasicClientProfile:idToken forClient:client];
            
        } else if ([[client getOAuthParameter:kOAuth2ParamResponseType] isEqual:@"token id_token"]) {
            // Validate id_token received via OIDC Implicit Client Profile
            
            BOOL idTokenValid = [self validateIDTokenUsingImplicitClientProfile:idToken forClient:client];
            
            if (idTokenValid) {
                
                // Additional test when access_token provided along with id_token
                // As we have also been provided an access_token in this flow, we must verify the at_hash value
                
                if(![self validateHash:(NSString *)[idToken getValueFromPayload:@"at_hash"] forToken:[client getOAuthParameter:kOAuth2ParamAccessToken] usingAlgorithm:idToken.signing_alg]) {
                    NSLog(@"Access token hash does not match!");
                    [[idToken validation_comments] addObject:@"at_hash check failed"];
                    return NO;
                }
            }
            
            NSLog(@"ID Token validation complete");
            return idTokenValid;
            
        } else if ([self isHybridFlow:[client getOAuthParameter:kOAuth2ParamResponseType]]) {
            // Validate id_token received via OIDC Hybrid Client Profile (rules are same as Implicit 3.3.2.12)
            
            BOOL idTokenValid = [self validateIDTokenUsingImplicitClientProfile:idToken forClient:client];
            
            if (idTokenValid) {
                
                // Additional test when access_token provided along with id_token
                // As we have also been provided an access_token in this flow, we must verify the at_hash value
                
                // This test is only to validate that the access_token received along with the id_token is the same
                // In a hybrid flow, the access token would come from the token endpoint after swapping the code (code id_token)
                // or may be a different token if the (code token id_token) is used
                

                // This is optional with "code token" hybrid flow.  But even so, should this not match the access_token that was issued with the id_token? ie that from the token endpoint
                // rather than from the authorization endpoint?
                if(![self validateHash:(NSString *)[idToken getValueFromPayload:@"at_hash"] forToken:[client getOAuthParameter:kOAuth2ParamInitialAccessToken] usingAlgorithm:idToken.signing_alg]) {
                    [[idToken validation_comments] addObject:@"at_hash check failed"];
                    NSLog(@"Access token hash does not match!");
                    return NO;
                }

                // For demonstration sake, lets also verify the c_hash
                if(![self validateHash:(NSString *)[idToken getValueFromPayload:@"c_hash"] forToken:[client getOAuthParameter:kOAuth2ParamCode] usingAlgorithm:idToken.signing_alg]) {
                    [[idToken validation_comments] addObject:@"c_hash check failed"];
                    NSLog(@"Code hash does not match!");
                    return NO;
                }
            
            }
            
            NSLog(@"ID Token validation complete");
            return idTokenValid;
            
        } else {
            NSLog(@"Unsupported response_type - Validation failed!");
            return NO;
        }
        
    } else {

        NSLog(@"No ID Token present");
        return YES;
    }
}

+(BOOL) isHybridFlow:(id)response_type
{
    NSArray *clientResponseTypes = [[(NSString *)response_type lowercaseString] componentsSeparatedByString:@" "];
    
    BOOL hasCode = NO;
    BOOL hasToken = NO;
    BOOL hasIdToken = NO;
    
    for(NSString *responseType in clientResponseTypes) {
        if ([responseType isEqualToString:@"code"]) {
            hasCode = YES;
        }
        if ([responseType isEqualToString:@"token"]) {
            hasToken = YES;
        }
        if ([responseType isEqualToString:@"id_token"]) {
            hasIdToken = YES;
        }
    }
    
    // Hybrid is code + token || code + token + id_token || code + id_token
    // so code && (token || id_token)
    
    return hasCode && (hasToken || hasIdToken);
}


+(BOOL) checkValue:(NSString *)expectedValue forKey:(NSString *)key inDictionary:(NSDictionary *)dictionary okayToNotExist:(BOOL)okayToNotExist
{
    BOOL isValidValue = NO;
    
    NSString *valueToCheck = [dictionary objectForKey:key];
    
    if ([valueToCheck length] != 0) {
        if ([valueToCheck isEqualToString:expectedValue]) {
            isValidValue = YES;
        } else {
            isValidValue = NO;
        }
    } else {
        return okayToNotExist;
    }
    
    return isValidValue;
}

+(BOOL)validateAudienceForToken:(JSONWebToken *)token Audience:(NSString *)expectedAudience
{
    BOOL isValid = NO;
    // Audience validation rules (OpenID Connect Core section 3.1.3.7)
    
    //    The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
    //    If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
    //    If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
    
    if ([[token getValueFromPayload:@"aud"] isKindOfClass:[NSArray class]])
    {
        // we have multiple audiences
        for (NSString *thisAudience in [token getValueFromPayload:@"aud"])
        {
            if ([thisAudience isEqualToString:expectedAudience])
            {
                // audience is there and matches
                isValid = YES;
            }
        }
        
        if ([self checkValue:expectedAudience forKey:@"azp" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) { // Should this be OKAY if it doesn't exist?
            // audience is there and matches
            isValid = YES;
        } else {
            [[token validation_comments] addObject:@"Invalid audience (multiple audiences, azp check failed)"];
        }
        
    } else {
        if ([self checkValue:expectedAudience forKey:@"aud" inDictionary:[token getPayloadAsDictionary] okayToNotExist:NO]) {
            // audience is there and matches
            isValid = YES;
        } else {
            [[token validation_comments] addObject:@"Invalid audience"];
        }
    }
    
    return isValid;
}

+(BOOL)checkTimeIsSameOrEarlierForClaim:(NSString *)claimName inToken:(JSONWebToken *)token skewSeconds:(double)skew
{
    BOOL isSameOrEarlier = NO;
    
    NSDate *claimTimestamp = [NSDate dateWithTimeIntervalSince1970:[[token getValueFromPayload:claimName] doubleValue]];
    NSDate *nowPlusSkew = [[NSDate date] dateByAddingTimeInterval:skew];
    
    if ([claimTimestamp compare:nowPlusSkew] != NSOrderedAscending) {
        isSameOrEarlier = YES;
    }
    return isSameOrEarlier;
}

+(BOOL)validateTimeClaimForToken:(JSONWebToken *)token Claim:(NSString *)claimName skewSeconds:(double)skew
{
    BOOL isValid = NO;
    
    if ([self checkTimeIsSameOrEarlierForClaim:claimName inToken:token skewSeconds:skew]) {
        // value is before nowPlusSkew - so is in range
        isValid = YES;
    } else {
        [[token validation_comments] addObject:[NSString stringWithFormat:@"%@ not within range", claimName]];
    }
    return isValid;
}

+(BOOL)validateHash:(NSString *)hashValue forToken:(NSString *)tokenValue usingAlgorithm:(NSString *)alg
{
    // Where "token" is access_token for at_hash and code for c_hash
    
    if (hashValue != nil)
    {
        NSData *hash = [Utils base64DecodeString:hashValue];
        NSData *left_most_half = [[NSData alloc] init];
        
        if ([alg isEqualToString:@"None"])
        {
            // What do we do here?
            NSLog(@"The signing algorithm is None.  What size hash?");
        } else {
            NSInteger SHA_Digest_Length = [[alg substringFromIndex:2] integerValue]; // remove the first two char (RS / ES / HS) to get the hash length
            SHA *token_sha_hash = [[SHA alloc] initWithData:[tokenValue dataUsingEncoding:NSASCIIStringEncoding] andDigestLength:SHA_Digest_Length];
            NSMutableData *tokenHash = [[NSMutableData alloc] initWithData:[token_sha_hash getHashBytes]];
            
            left_most_half = [tokenHash subdataWithRange:NSMakeRange(0, ([tokenHash length]/2))];
        }
        
        if ([hash isEqualToData:left_most_half]) {
            return YES;
        } else {
            return NO;
        }
    } else {
        NSLog(@"Missing hash value");
        return NO;
    }
    
    return NO;
}

+(BOOL) validateSignatureForToken:(JSONWebToken *)token
{
    return [self validateSignatureForToken:token withSymmetricKey:nil];
}

+(BOOL) validateSignatureForToken:(JSONWebToken *)token withSymmetricKey:(NSString *)symmetricKey
{
    // Handle the appropriate algorithm
    // Symmetric
    // HS 256, 384, 512 HMAC using SHA-xxx hash
    
    // Asymmetric
    // RS 256, 384, 512 RSASSA-PKCS-v1.5 using SHA-xxx hash
    // ES 256, 384, 512 ECDSA using P-xxx curve and SHA-xxx hash
    // PS 256, 384, 512 RSASSA-PSS using xxx hash and MGF1 mask generation
    
    // None
    // NONE
    
    if ([[token.signing_alg substringToIndex:2] isEqualToString:@"HS"]) { // Symmetric (HMAC w/SHA hash)
        
        return [token validateSignatureUsingSymmetricKey:symmetricKey];
        
    } else if([[token.signing_alg uppercaseString] isEqualToString:@"NONE"]) { // No signing
        
        return YES; // nothing to verify - so I guess the signature is good?
        
    } else if([[token.signing_alg substringToIndex:2] isEqualToString:@"RS"]) { // Asymmetric (RSA PKCS v1.5 w/ SHA hash)
        
        return [token validateSignature];
        
    } else {
        token.signature_comments = [NSString stringWithFormat:@"Unsupported algorithm: %@", token.signing_alg];
        return NO;
    }
    
    return NO;
}

@end
