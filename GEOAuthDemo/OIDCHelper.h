//
//  OIDCHelper.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/17/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "JSONWebToken.h"
#import "OAuth2Client.h"

@interface OIDCHelper : NSObject

+(BOOL)validateSignatureForToken:(JSONWebToken *)token;
+(BOOL)validateAccessToken:(JSONWebToken *)accessToken forClient:(OAuth2Client *)client;
+(BOOL)validateIDToken:(JSONWebToken *)idToken forClient:(OAuth2Client *)client;

@end
