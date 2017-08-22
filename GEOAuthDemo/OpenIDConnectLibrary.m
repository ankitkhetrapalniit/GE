//
//  OpenIDConnectLibrary.m
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "OpenIDConnectLibrary.h"
#import "JSONWebToken.h"
#import "OIDCHelper.h"
#import "Utils.h"


@implementation OpenIDConnectLibrary

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(OAuth2Client *)client {

    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:idToken ofType:@"id_token"];
    
    if ([OIDCHelper validateIDToken:jwt forClient:client]) {
        return [jwt parsed_payload];
    } else
    {
        return nil;
    }
}

+(BOOL)validateIDToken:(NSString *)idToken forClient:(OAuth2Client *)client {

    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:idToken ofType:@"id_token"];
    return [OIDCHelper validateIDToken:jwt forClient:client];
}

+(NSString *)getParsedHeaderForToken:(NSString *)token {
    
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:token ofType:@"any"];
    return [Utils jsonPrettyPrint:[jwt parsed_header]];
}

+(NSString *)getParsedPayloadForToken:(NSString *)token {
    
    JSONWebToken *jwt = [[JSONWebToken alloc] initWithToken:token ofType:@"any"];
    return [Utils jsonPrettyPrint:[jwt parsed_payload]];
}

@end
