//
//  OAuth2Client.h
//  SampleApp
//
//  Created by Paul Meyer on 11/26/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface OAuth2Client : NSObject

@property (nonatomic, retain) NSString *baseUrl;
@property (nonatomic, retain) NSString *authorizationEndpoint;
@property (nonatomic, retain) NSString *tokenEndpoint;
@property (nonatomic, retain) NSString *grantType;

typedef enum OAuth2Parameters {
    kOAuth2ParamClientId = 0,
    kOAuth2ParamClientSecret,
    kOAuth2ParamResponseType,
    kOAuth2ParamGrantType,
    kOAuth2ParamAcrValues,
    kOAuth2ParamScope,
    kOAuth2ParamIdp,
    kOAuth2ParamPfidpadapterid,
    kOAuth2ParamNonce,
    kOAuth2ParamRedirectUri,
    kOAuth2ParamUsername,
    kOAuth2ParamPassword,
    kOAuth2ParamCode,
    kOAuth2ParamState,
    kOAuth2ParamPrompt,
    kOAuth2ParamValidatorId,
    kOAuth2ParamAssertion,
    kOAuth2ParamToken,
    kOAuth2ParamRefreshToken,
    kOAuth2ParamAccessToken,
    kOAuth2ParamIdToken,
    kOAuth2ParamTokenType,
    kOAuth2ParamExpiresIn,
    kOAuth2ParamError,
    kOAuth2ParamErrorDescription,
    kOAuth2ParamInitialAccessToken, // Hybrid Flow
    kOAuth2ParamInitialIdToken // Hybrid Flow
} OAuth2Parameter;

-(id)init;
-(void)reset;
-(void)setOAuthParameter:(OAuth2Parameter)parameter value:(id)value;
-(id)getOAuthParameter:(OAuth2Parameter)parameter;
-(BOOL)OAuthParameterExists:(OAuth2Parameter)parameter;
-(BOOL)validateAccessToken;
-(BOOL)refreshToken;
-(BOOL)swapCodeForToken;
-(NSDictionary *)getAttributesFromUserInfo:(NSString *)withAccessToken;
-(NSString *)buildAuthorizationRedirectUrl;
-(void)callTokenEndpoint;
-(void)processCallback:(NSString *)urlComponent;
-(NSString *)getLastRequest;
-(NSString *)getLastResponse;
-(void)setLastRequest:(NSString *)request;
-(void)setLastResponse:(NSString *)response;
-(void)handleHybridTokens;

@end
