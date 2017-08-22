//
//  HttpResponse.m
//  OpenIDConnectLibrary
//
//  Created by Paul Meyer on 11/25/13.
//  Copyright (c) 2013 Ping Identity. All rights reserved.
//

#import "HttpResponse.h"

@implementation HttpResponse

@synthesize responseData = _responseData;
@synthesize responseCode = _responseCode;

-(id) init
{
    self = [super init];
    
    if (self) {}
    
    return self;
}

@end
