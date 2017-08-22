//
//  AppDelegate.m
//  GEOAuthDemo
//
//  Created by Akshay Acharya on 27/11/14.
//  Copyright (c) 2014 Akshay Acharya. All rights reserved.
//

#import "AppDelegate.h"
#import "OPOperation.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

- (BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url
{
    // This will handle the app call back from when we redirect out to Safari and return back into the app:
    //  - Authorization code grant type - com.pingidentity.oauthplayground://authorization_grant?code=
    //  - Implicit grant type - com.pingidentity.oauthplayground://implicit_grant?access_token=
    
    //TODO: Hybrid flows
    //  - code token == Hybrid flow - (response is a fragment containing code and access_token
    //  - code id_token == Hybrid flow - (response is a fragment containing code and id_token
    //  - code token id_token == Hybrid flow - (response is a fragment containing code, id_token and access_token)
    
    if (!url) {
        // The URL is nil. There's nothing more to do.
        NSLog(@"Received a message in handleOpenURL (app callback) for URL: No URL specified!");
        return NO;
    }
    
    NSLog(@"Received a message in handleOpenURL (app callback) for URL: %@", [url absoluteURL]);
    
    if ([[url host] isEqualToString:@"authorization_grant"])
    {
        NSLog(@"Handling a callback for an authorization code grant type");
        
        [[OPOperation operation].grant processCallback:[url query]];
        
    } else if ([[url host] isEqualToString:@"implicit_grant"])
    {
        NSLog(@"Handling a callback for an implicit grant type");
        
        [[OPOperation operation].grant processCallback:[url fragment]];
        
    } else if ([[url host] isEqualToString:@"hybrid_grant"])
    {
        NSLog(@"Handling a callback for a hybrid grant type");
        [[OPOperation operation].grant processCallback:[url fragment]];
        
    }
    
    CFRunLoopStop(CFRunLoopGetCurrent());
    
    return YES;
}


@end
