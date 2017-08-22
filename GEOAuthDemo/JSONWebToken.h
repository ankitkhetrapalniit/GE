//
//  JSONWebToken.h
//  OAuthPlayground
//
//  Created by Paul Meyer on 10/24/13.
//  Copyright (c) 2013 Paul Meyer. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JSONWebToken : NSObject
{
    NSString *jwt;
    NSData *header;
    NSData *payload;
    NSData *signature;
    NSString *signature_comments;
    NSString *signed_parts;
    
    NSDictionary *parsed_header;
    NSDictionary *parsed_payload;
    
    NSString *type; //access_token or id_token
    SecKeyRef signing_cert;
    NSMutableArray *validation_comments;
    NSString *issuer;
    NSString *kid;
    NSString *signing_alg;
}

@property (nonatomic, retain) NSString *jwt;
@property (nonatomic, retain) NSData *header;
@property (nonatomic, retain) NSData *payload;
@property (nonatomic, retain) NSData *signature;
@property (nonatomic, retain) NSString *signed_parts;

@property (nonatomic, retain) NSDictionary *parsed_header;
@property (nonatomic, retain) NSDictionary *parsed_payload;

@property (nonatomic, retain) NSString *type;
@property (nonatomic) SecKeyRef signing_cert;

@property (nonatomic, retain) NSString *signature_comments;
@property (nonatomic, retain) NSMutableArray *validation_comments;

@property (nonatomic, retain) NSString *issuer;
@property (nonatomic, retain) NSString *kid;
@property (nonatomic, retain) NSString *signing_alg;

-(id)initWithToken:(NSString *)jsonWebToken ofType:(NSString *)tokenType;

-(BOOL) validateSignature;
-(BOOL) validateSignatureUsingSymmetricKey:(NSString *)symmetricKey;

-(id) getValueFromPayload:(NSString *)key;
-(NSDictionary *) getPayloadAsDictionary;

@end
