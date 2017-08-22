//
//  OPOperation.m
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/14/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import "OPOperation.h"
#import "OpenIDConnectLibrary.h"

@implementation OPOperation

NSString *localError;
NSString *localErrorCode;


+(OPOperation *) operation
{
    static OPOperation *op;
    
    if(op == nil)
    {
        op = [[OPOperation alloc] init];
    }
    
    return op;
    
}

-(id) init
{
    self = [super init];
    
    if (self)
    {
        [self reset];
    }
    
    return self;
}

-(void) reset
{
    [_grant reset];
    localError = nil;
    localErrorCode = nil;
}

-(BOOL) inErrorState
{
    if([_grant getOAuthParameter:kOAuth2ParamError] != nil)
    {
        return YES;
    } else {
        return NO;
    }
}

-(NSString *)getLastError
{
    if (localError != nil) {
        return localError;
    } else if ([self inErrorState]) {
        return [_grant getOAuthParameter:kOAuth2ParamErrorDescription];
    } else {
        return @"";
    }
}

-(NSString *)getLastErrorCode
{
    if (localErrorCode != nil) {
        return localErrorCode;
    } else if ([self inErrorState]) {
        return [_grant getOAuthParameter:kOAuth2ParamError];
    } else {
        return @"";
    }
}

-(void)setErrorDescription:(NSString *)errorDescription {
    localError = errorDescription;
}

-(void)setErrorCode:(NSString *)errorCode {
    localErrorCode = errorCode;
}


-(NSString *)getLastRequest
{
    return [_grant getLastRequest];
}

-(NSString *)getLastResponse
{
    return [_grant getLastResponse];
}

-(NSString *)getCurrentAccessToken
{
    return [_grant getOAuthParameter:kOAuth2ParamAccessToken];
}

-(NSString *)getCurrentRefreshToken
{
    return [_grant getOAuthParameter:kOAuth2ParamRefreshToken];
}

-(NSString *)getCurrentIDToken
{
    return [_grant getOAuthParameter:kOAuth2ParamIdToken];
}

-(NSString *)getSubject
{
    if ([_grant getOAuthParameter:kOAuth2ParamIdToken]) {
        // We have an id_token so grab the sub from there
        NSDictionary *idTokenAttributes = [OpenIDConnectLibrary parseIDToken:[_grant getOAuthParameter:kOAuth2ParamIdToken] forClient:_grant];
        return [idTokenAttributes objectForKey:@"sub"];
        
    } else {
        // What about for other grant types (ie ROPC with openid as scope).  OIDC Core spec says the sub returned from
        // the UserInfo endpoint MUST match the sub returned in the id_token (5.3.2) (however not mentioned in the response validation 5.3.4)
        
    }
    
    return nil;
}

@end
