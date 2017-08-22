//
//  OpenIDConnectLibrary.h
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAuth2Client.h"

@interface OpenIDConnectLibrary : NSObject

+(NSDictionary *)parseIDToken:(NSString *)idToken forClient:(OAuth2Client *)client;
+(BOOL)validateIDToken:(NSString *)idToken forClient:(OAuth2Client *)client;
+(NSString *)getParsedHeaderForToken:(NSString *)token;
+(NSString *)getParsedPayloadForToken:(NSString *)token;

@end
