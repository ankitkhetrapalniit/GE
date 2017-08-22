//
//  Utils.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 3/2/14.
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Utils : NSObject

+(NSData *)base64DecodeString:(NSString * )base64EncodedString;
+(NSString *)jsonPrettyPrint:(NSDictionary *)jsonDictionary;
+(NSString *)jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded;

@end
