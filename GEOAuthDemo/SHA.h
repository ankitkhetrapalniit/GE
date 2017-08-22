//
//  SHA.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/29/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SHA : NSObject
{
    NSData *DataToHash;
    NSUInteger DigestLength;
}

@property (nonatomic, retain) NSData *DataToHash;
@property NSUInteger DigestLength;

- (id)init;
- (id)initWithData:(NSData *)data andDigestLength:(NSUInteger)length;
- (NSData *)getHashBytes;

@end
