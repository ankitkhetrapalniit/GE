//
//  OAuth2Client.m
//  SampleApp
//
//  Created by Paul Meyer on 11/26/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "OAuth2Client.h"
#import "HttpHelper.h"
#import "OIDCHelper.h"

@implementation OAuth2Client
{
    NSMutableDictionary *dictClientParameters;
}

NSArray *clientParameterLookup;
NSString *lastRequest;
NSString *lastResponse;


-(id)init
{
    self = [super init];
    
    if (self)
    {
        _authorizationEndpoint = @"/as/authorization.oauth2";
        _tokenEndpoint = @"/as/token.oauth2";
        dictClientParameters = [[NSMutableDictionary alloc] init];
        clientParameterLookup = [NSArray arrayWithObjects: @"client_id",
                                 @"client_secret",
                                 @"response_type",
                                 @"grant_type",
                                 @"acr_values",
                                 @"scope",
                                 @"idp",
                                 @"pfidpadapterid",
                                 @"nonce",
                                 @"redirect_uri",
                                 @"username",
                                 @"password",
                                 @"code",
                                 @"state",
                                 @"prompt",
                                 @"validator_id",
                                 @"assertion",
                                 @"token",
                                 @"refresh_token",
                                 @"access_token",
                                 @"id_token",
                                 @"token_type",
                                 @"expires_in",
                                 @"error",
                                 @"error_description",
                                 @"initial_access_token",
                                 @"initial_id_token",
                                 nil];
        
        // Grant Types:
        //authorization_code
        //password
        //client_credentials
        //refresh_token
        //urn:ietf:params:oauth:grant-type:saml2-bearer
        //urn:pingidentity.com:oauth2:grant_type:validate_bearer

        // Response Types:
        // code
        // token
    }
    
    return self;
}

-(void)reset
{
    [dictClientParameters removeAllObjects];
    _baseUrl = @"";
    _authorizationEndpoint = @"";
    _tokenEndpoint = @"";
}

-(void)setOAuthParameter:(OAuth2Parameter)parameter value:(id)value
{
    if (value != nil)
    {
        if ([value isKindOfClass:[NSString class]])
        {
            if (![value isEqualToString:@""])
            {
                [dictClientParameters setValue:value forKey:clientParameterLookup[parameter]];
            }
        } else             {
            [dictClientParameters setValue:value forKey:clientParameterLookup[parameter]];
        }
        
    }
}

-(id)getOAuthParameter:(OAuth2Parameter)parameter
{
    return [dictClientParameters objectForKey:clientParameterLookup[parameter]];
}

-(BOOL)OAuthParameterExists:(OAuth2Parameter)parameter
{
    if([dictClientParameters objectForKey:clientParameterLookup[parameter]] != nil) {
        return YES;
    } else {
        return NO;
    }
        
}

-(NSString *)getLastRequest
{
    return lastRequest;
}

-(NSString *)getLastResponse
{
    return lastResponse;
}

-(void)setLastRequest:(NSString *)request
{
    lastRequest = request;
}

-(void)setLastResponse:(NSString *)response
{
    lastResponse = response;
}

-(void)handleHybridTokens
{
    [self setOAuthParameter:kOAuth2ParamInitialAccessToken value:[self getOAuthParameter:kOAuth2ParamAccessToken]];
    [self setOAuthParameter:kOAuth2ParamInitialIdToken value:[self getOAuthParameter:kOAuth2ParamIdToken]];
}

-(BOOL)validateAccessToken
{
    if ([self getOAuthParameter:kOAuth2ParamToken] != nil)
    {
        [self setOAuthParameter:kOAuth2ParamGrantType value:@"urn:pingidentity.com:oauth2:grant_type:validate_bearer"];
        [self callTokenEndpointWithPostData:[self buildTokenEndpointPostData]];

        if ([self OAuthParameterExists:kOAuth2ParamError]) {
            return NO;
        } else {
            return YES;
        }
    }
    
    return NO;
}

-(BOOL)refreshToken
{
    if ([self getOAuthParameter:kOAuth2ParamRefreshToken] != nil)
    {
        [self setOAuthParameter:kOAuth2ParamGrantType value:@"refresh_token"];
        [self callTokenEndpointWithPostData:[self buildTokenEndpointPostDataForRefreshToken]];
        
        if ([self OAuthParameterExists:kOAuth2ParamError]) {
            return NO;
        } else {
            return YES;
        }
    }
    
    return NO;
}

-(BOOL)swapCodeForToken
{
    if ([self getOAuthParameter:kOAuth2ParamCode] != nil)
    {
        [self setOAuthParameter:kOAuth2ParamGrantType value:@"authorization_code"];
        [self callTokenEndpoint];
        
        if ([self OAuthParameterExists:kOAuth2ParamError]) {
            return NO;
        } else {
            return YES;
        }
    }
    
    return NO;
}

-(NSString *)getTokenEndpointUrl
{
    if ([_tokenEndpoint hasPrefix:@"/"]) {
        return [NSString stringWithFormat:@"%@%@", _baseUrl, _tokenEndpoint];
    } else {
        return [NSString stringWithFormat:@"%@", _tokenEndpoint];
    }
}

-(NSString *)getAuthorizationEndpointUrl
{
    if ([_authorizationEndpoint hasPrefix:@"/"]) {
        return [NSString stringWithFormat:@"%@%@", _baseUrl, _authorizationEndpoint];
    } else {
        return [NSString stringWithFormat:@"%@", _authorizationEndpoint];
    }
}

-(NSString *)getAuthorizationHeader:(NSString *)withAccessToken
{
    return [NSString stringWithFormat:@"Bearer %@", withAccessToken];
}

-(NSDictionary *)getAttributesFromUserInfo:(NSString *)withAccessToken
{
    NSString *urlUserInfoEndpoint = [NSString stringWithFormat:@"%@/idp/userinfo.openid", _baseUrl];

    lastRequest = [NSString stringWithFormat:@"Sent HTTP GET to: %@", urlUserInfoEndpoint];
    HttpResponse *httpResponse = [HttpHelper getUrl:urlUserInfoEndpoint withAuthZHeader:[self getAuthorizationHeader:withAccessToken]];
    lastResponse = [NSString stringWithFormat:@"Received HTTP response code: %lu\nHTTP response data: %@", (unsigned long)httpResponse.responseCode, [[NSString alloc] initWithData:httpResponse.responseData encoding:NSUTF8StringEncoding]];
    
    if (httpResponse.responseCode == 200) {
        NSError *error;
        NSDictionary *jsonUserInfoData = [NSJSONSerialization JSONObjectWithData:httpResponse.responseData options:kNilOptions error:&error];
        return jsonUserInfoData;
    } else {
        NSString *errorMessage = [NSString stringWithFormat:@"An error occurred\r\nHTTP Response Code: %lu\r\nHTTP Response:\r\n%@", (unsigned long)httpResponse.responseCode, [[NSString alloc] initWithData:httpResponse.responseData encoding:NSUTF8StringEncoding]];
        
        NSLog(@"FAILURE: Error grabbing user info: %@", errorMessage);
    }

    return nil;
}

-(NSString *)appendOAuthParameter:(OAuth2Parameter)parameter
{
    if ([self OAuthParameterExists:parameter]) {
        return [NSString stringWithFormat:@"&%@=%@", clientParameterLookup[parameter], [[self getOAuthParameter:parameter]stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    }
    
    return @"";
}

-(NSString *)buildAuthorizationRedirectUrl
{
    // Uses the values in the current operation to build an AuthZ url
    NSMutableString *authenticationUrl = [NSMutableString stringWithString:[self getAuthorizationEndpointUrl]];

    // Add required values:
    [authenticationUrl appendFormat:@"?client_id=%@", [self getOAuthParameter:kOAuth2ParamClientId]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamResponseType]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamRedirectUri]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamScope]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamNonce]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamState]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamIdp]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamAcrValues]];
    [authenticationUrl appendString:[self appendOAuthParameter:kOAuth2ParamPfidpadapterid]];
    
    lastRequest = [NSString stringWithFormat:@"Built redirect URL: %@", [NSString stringWithString:authenticationUrl]];
    return [NSString stringWithString:authenticationUrl];
}

- (NSString *) buildTokenEndpointPostData
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthParameter:kOAuth2ParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientId]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamCode]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamRedirectUri]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamRefreshToken]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamUsername]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamPassword]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamScope]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamAssertion]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamToken]];
    
    return [NSString stringWithString:tokenUrl];
}

- (NSString *) buildTokenEndpointPostDataForRefreshToken
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthParameter:kOAuth2ParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientId]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamRefreshToken]];
    
    return [NSString stringWithString:tokenUrl];
}

- (NSString *) buildTokenEndpointPostDataForValidateBearer
{
    NSMutableString *tokenUrl = [NSMutableString stringWithFormat:@"grant_type=%@", [[self getOAuthParameter:kOAuth2ParamGrantType] stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding]];
    
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientId]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamClientSecret]];
    [tokenUrl appendString:[self appendOAuthParameter:kOAuth2ParamToken]];
    
    return [NSString stringWithString:tokenUrl];
}

-(void)callTokenEndpoint
{
    NSString *postData = [self buildTokenEndpointPostData];
    [self callTokenEndpointWithPostData:postData];
}

-(void)callTokenEndpointWithPostData:(NSString *)postData
{
    NSString *tokenEndpoint = [self getTokenEndpointUrl];
    lastRequest = [NSString stringWithFormat:@"Sent HTTP POST request to: %@\nWith data:\n%@", tokenEndpoint, postData];
    
    HttpResponse *postResponse = [HttpHelper postToUrl:tokenEndpoint withPostData:postData];

    NSError *error = nil;
    NSLog(@"Response data: %@", [[NSString alloc] initWithData:postResponse.responseData encoding:NSUTF8StringEncoding]);
    lastResponse = [NSString stringWithFormat:@"Received HTTP response code: %lu\nHTTP response data: %@", (unsigned long)postResponse.responseCode, [[NSString alloc] initWithData:postResponse.responseData encoding:NSUTF8StringEncoding]];
    
    // We should probably pre-check that it's JSON....
    NSDictionary* jsonResponse = [NSJSONSerialization JSONObjectWithData:postResponse.responseData options:kNilOptions error:&error];
    
    // Error check first:
    if (error != nil)
    {
        // We received an error!
        NSString *errorValue = [NSString stringWithFormat:@"%lu", (long)[error code]];
        NSString *errorDescValue = [error domain];
        
        NSLog(@"Error received: %@: %@", errorValue, errorDescValue);
        
        [self setOAuthParameter:kOAuth2ParamError value:errorValue];
        [self setOAuthParameter:kOAuth2ParamErrorDescription value:errorDescValue];
        
    } else {
        
        if ([jsonResponse objectForKey:@"error"])
        {
            // We received an error!
            NSString *errorValue = [jsonResponse valueForKey:@"error"];
            NSString *errorDescValue = [jsonResponse valueForKey:@"error_description"];
            
            NSLog(@"Error received: %@: %@", errorValue, errorDescValue);
            
            [self setOAuthParameter:kOAuth2ParamError value:errorValue];
            [self setOAuthParameter:kOAuth2ParamErrorDescription value:errorDescValue];
        }
        
        if([jsonResponse objectForKey:@"access_token"])
        {
            [self setOAuthParameter:kOAuth2ParamAccessToken value:[jsonResponse valueForKey:@"access_token"]];
        }
        
        if([jsonResponse objectForKey:@"id_token"])
        {
            [self setOAuthParameter:kOAuth2ParamIdToken value:[jsonResponse valueForKey:@"id_token"]];
        }
        
        if([jsonResponse objectForKey:@"state"])
        {
            [self setOAuthParameter:kOAuth2ParamState value:[jsonResponse valueForKey:@"state"]];
        }
        
        if([jsonResponse objectForKey:@"token_type"])
        {
            [self setOAuthParameter:kOAuth2ParamTokenType value:[jsonResponse valueForKey:@"token_type"]];
        }
        
        if([jsonResponse objectForKey:@"expires_in"])
        {
            [self setOAuthParameter:kOAuth2ParamExpiresIn value:[jsonResponse valueForKey:@"expires_in"]];
        }
        
        if([jsonResponse objectForKey:@"refresh_token"])
        {
            [self setOAuthParameter:kOAuth2ParamRefreshToken value:[jsonResponse valueForKey:@"refresh_token"]];
        }
    }
}

-(void)processCallback:(NSString *)urlComponent
{

    lastResponse = [NSString stringWithFormat:@"Received OAuth2 callback data: %@", urlComponent];

    NSMutableDictionary *urlParams = [[NSMutableDictionary alloc] init];
    for (NSString *param in [urlComponent componentsSeparatedByString:@"&"]) {
        NSArray *qsElements = [param componentsSeparatedByString:@"="];
        if([qsElements count] < 2) continue;
        [urlParams setObject:[qsElements objectAtIndex:1] forKey:[qsElements objectAtIndex:0]];
    };
    
    // Error check first:
    if ([urlParams objectForKey:@"error"])
    {
        // We received an error!
        NSString *errorValue = [urlParams valueForKey:@"error"];
        NSString *errorDescValue = [urlParams valueForKey:@"error_description"];
        
        NSLog(@"Error received: %@: %@", errorValue, errorDescValue);
        
        [self setOAuthParameter:kOAuth2ParamError value:errorValue];
        [self setOAuthParameter:kOAuth2ParamErrorDescription value:errorDescValue];
    }
    
    if([urlParams objectForKey:@"access_token"])
    {
        [self setOAuthParameter:kOAuth2ParamAccessToken value:[urlParams valueForKey:@"access_token"]];
    }
    
    if([urlParams objectForKey:@"id_token"])
    {
        [self setOAuthParameter:kOAuth2ParamIdToken value:[urlParams valueForKey:@"id_token"]];
    }
    
    if([urlParams objectForKey:@"state"])
    {
        [self setOAuthParameter:kOAuth2ParamState value:[urlParams valueForKey:@"state"]];
    }
    
    if([urlParams objectForKey:@"token_type"])
    {
        [self setOAuthParameter:kOAuth2ParamTokenType value:[urlParams valueForKey:@"token_type"]];
    }
    
    if([urlParams objectForKey:@"expires_in"])
    {
        [self setOAuthParameter:kOAuth2ParamExpiresIn value:[urlParams valueForKey:@"expires_in"]];
    }
    
    if([urlParams objectForKey:@"code"]) //AuthZ Code
    {
        [self setOAuthParameter:kOAuth2ParamCode value:[urlParams valueForKey:@"code"]];
    }
}

@end
