//
//  Utils.m
//  OAuthPlayground
//
//  Created by Paul Meyer on 3/2/14.
//  Copyright (c) 2014 Paul Meyer. All rights reserved.
//

#import "Utils.h"

@implementation Utils

+(NSData *) base64DecodeString:(NSString *)base64EncodedString
{
    NSString *cleanBase64EncodedString = [[[base64EncodedString stringByReplacingOccurrencesOfString:@"\n" withString:@""] stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    NSInteger numEqualsNeeded = 4 - ([cleanBase64EncodedString length] % 4);
    if (numEqualsNeeded == 4) { numEqualsNeeded = 0; }
    NSString *padding = [@"" stringByPaddingToLength:numEqualsNeeded withString:@"=" startingAtIndex:0];
    NSString *base64EncodedStringPadded = [NSString stringWithFormat:@"%@%@", cleanBase64EncodedString, padding];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:base64EncodedStringPadded options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    return decodedData;
}

+(NSString *) jsonPrettyPrint:(NSString *)jsonString base64Encoded:(BOOL)base64Encoded
{
    NSData *jsonData = nil;
    
    if (base64Encoded) {
        jsonData = [Utils base64DecodeString:jsonString];
    } else {
        jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    }
    
    NSError *error = nil;
    NSDictionary *jsonDictionary = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:&error];
    
    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}

+(NSString *) jsonPrettyPrint:(NSDictionary *)jsonDictionary
{
    NSMutableString *returnString = [[NSMutableString alloc] init];
    
    
    for (NSString *k in jsonDictionary) {
        
        if ([k isEqualToString:@"exp"] || [k isEqualToString:@"iat"] ) {
            [returnString appendFormat:@"%@: %@ (%@)\r\n", k, [jsonDictionary valueForKey:k], [NSDate dateWithTimeIntervalSince1970:[[jsonDictionary valueForKey:k] doubleValue]]];
        } else {
            [returnString appendFormat:@"%@: %@\r\n", k, [jsonDictionary valueForKey:k]];
        }
    }
    
    return returnString;
}


@end
