//
//  OPOperation.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/14/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OAuth2Client.h"

@interface OPOperation : NSObject

@property (nonatomic, retain) OAuth2Client *grant;

+ (OPOperation *)operation;

- (void)reset;
- (BOOL)inErrorState;
- (NSString *)getSubject;
- (NSString *)getLastError;
- (NSString *)getLastErrorCode;
- (NSString *)getCurrentIDToken;
- (NSString *)getCurrentRefreshToken;
- (NSString *)getCurrentAccessToken;
- (NSString *)getLastRequest;
- (NSString *)getLastResponse;
-(void)setErrorDescription:(NSString *)errorDescription;
-(void)setErrorCode:(NSString *)errorCode;

@end
