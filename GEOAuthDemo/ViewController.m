//
//  ViewController.m
//  GEOAuthDemo
//
//  Created by Akshay Acharya on 27/11/14.
//  Copyright (c) 2014 Akshay Acharya. All rights reserved.
//

#import "ViewController.h"
#import "OPOperation.h"

@interface ViewController ()
{
    NSString *outletClientId,*outletClientSecret,*outletScope,*outletResponseType,*outletRedirectUri,*outletBaseURL,*outletGrantType,*authToken;
    __block NSString *accessToken,*refreshToken,*idToken;
    OAuth2Client *oauthClient;
}
@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    //setup oauth config
    [self setConfig];
}

- (void)setConfig
{
    outletClientId = @"NIITTESTAPP2";
    outletClientSecret = @"ankit2000";
    //outletScope = @"Test";
    outletScope = @"api+openid+profile";
    outletResponseType = @"code";
    outletRedirectUri = @"GEAcronymBot://authorization_grant/";
    outletBaseURL = @"https://fssfed.ge.com/fss";
    outletGrantType = @"authorization_code";
    
}

- (void)viewDidAppear:(BOOL)animated
{
    [self setOAuthClient];
}

- (void)setOAuthClient
{
    //check if any tokens are stored or not?
    oauthClient = [[OAuth2Client alloc] init];
    
    [oauthClient setBaseUrl:outletBaseURL];
    
    [oauthClient setOAuthParameter:kOAuth2ParamClientId value:outletClientId];
    [oauthClient setOAuthParameter:kOAuth2ParamResponseType value:outletResponseType];
    [oauthClient setOAuthParameter:kOAuth2ParamClientSecret value:outletClientSecret];
    [oauthClient setOAuthParameter:kOAuth2ParamRedirectUri value:outletRedirectUri];
    [oauthClient setOAuthParameter:kOAuth2ParamScope value:outletScope];
    
    [[OPOperation operation] setGrant:oauthClient];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)parseIDToken
{
    NSLog(@"Parse ID Token");
    
    NSDictionary *userDict = [oauthClient getAttributesFromUserInfo:[[OPOperation operation] getCurrentAccessToken]];
    
    NSLog(@"idTokenAttributes %@",[userDict description]);
    
    self.lblResult.text = [self.lblResult.text stringByAppendingString:[NSString stringWithFormat:@"\nUser Info : %@",[userDict description]]];
    
    
}

- (IBAction)getAuthToken:(id)sender
{
    NSLog(@"getAuthToken");
    
    // Step 1 - Build the token url we need to redirect the user to
    NSString *authorizationUrl = [oauthClient buildAuthorizationRedirectUrl];
    NSLog(@"Calling authorization url: %@", authorizationUrl);
    
    [[UIApplication sharedApplication] openURL:[NSURL URLWithString:authorizationUrl]];
    
    // We have returned from Safari and should have something in our OPOperation object
    
    CFRunLoopRun();
    
    if ([[OPOperation operation] inErrorState])
    {
        NSLog(@"FAILURE: Returned from Safari with an Error: %@: %@", [[OPOperation operation] getLastErrorCode], [[OPOperation operation] getLastError]);
        //set error in uilabel
        self.lblResult.text = [[OPOperation operation] getLastError];
        
    }
    else
    {
        NSLog(@"SUCCESS: Returned from Safari with a Authorization code: %@", [[OPOperation operation].grant getOAuthParameter:kOAuth2ParamCode]);
        authToken = [[OPOperation operation].grant getOAuthParameter:kOAuth2ParamCode];
        self.lblResult.text = [NSString stringWithFormat:@"Auth Token is %@",authToken];
    }

    
}
- (IBAction)requestAccessToken:(id)sender
{
    NSLog(@"requestAccessToken");
    [[OPOperation operation].grant setOAuthParameter:kOAuth2ParamClientId value:outletClientId];
    [[OPOperation operation].grant setOAuthParameter:kOAuth2ParamGrantType value:outletGrantType];
    [[OPOperation operation].grant setOAuthParameter:kOAuth2ParamCode value:authToken];
    [[OPOperation operation].grant setOAuthParameter:kOAuth2ParamClientSecret value:outletClientSecret];
    [[OPOperation operation].grant setOAuthParameter:kOAuth2ParamRedirectUri value:outletRedirectUri];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, (unsigned long)NULL), ^{
        [[OPOperation operation].grant swapCodeForToken];
    
        dispatch_async(dispatch_get_main_queue(), ^{
            if ([[OPOperation operation] inErrorState])
            {
                NSLog(@"FAILURE: Returned from code exchange with an error: %@: %@", [[OPOperation operation] getLastErrorCode], [[OPOperation operation] getLastError]);
                //set error in uilabel
                self.lblResult.text = [[OPOperation operation] getLastError];
            }
            else
            {
                NSLog(@"SUCCESS: Access Token received: %@", [[OPOperation operation] getCurrentAccessToken]);
                //set accessToken into label
                accessToken = [[OPOperation operation] getCurrentAccessToken];
                refreshToken = [[OPOperation operation] getCurrentRefreshToken];
                idToken = [[OPOperation operation]getCurrentIDToken];
                self.lblResult.text = [NSString stringWithFormat:@"Access Token is %@ \n \n Refresh Token is %@ \n \n Id token is %@",accessToken,refreshToken,idToken];
                [self saveTokenIntoKeychain:self];
                
                [self parseIDToken];
                
            }
            

        
        });
        });
    
}

- (IBAction)getRefershToken:(id)sender
{
    NSLog(@"Refreshing Access Token...");
    
    accessToken = [[OPOperation operation] getCurrentAccessToken];
    refreshToken = [[OPOperation operation] getCurrentRefreshToken];
    
    if(accessToken!=nil)
        [oauthClient setOAuthParameter:kOAuth2ParamAccessToken value:accessToken];
    if(refreshToken!=nil)
        [oauthClient setOAuthParameter:kOAuth2ParamRefreshToken value:refreshToken];
    
    [[OPOperation operation] setGrant:oauthClient];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, (unsigned long)NULL), ^{
    if ([[OPOperation operation].grant refreshToken])
    {
        NSLog(@"SUCCESS: Access Token refreshed: %@", [[OPOperation operation] getCurrentAccessToken]);
        //set accessToken into label
        accessToken = [[OPOperation operation] getCurrentAccessToken];
        refreshToken = [[OPOperation operation] getCurrentRefreshToken];
        idToken = [[OPOperation operation]getCurrentIDToken];
        
        dispatch_async(dispatch_get_main_queue(), ^{
        self.lblResult.text = [NSString stringWithFormat:@"Access Token is %@ \n \n Refresh Token is %@ \n \n Id token is %@",accessToken,refreshToken,idToken];
        [self saveTokenIntoKeychain:self];
        });
    }
    else
    {
        NSLog(@"FAILURE: Error refreshing Refresh Token: %@: %@", [[OPOperation operation] getLastErrorCode], [[OPOperation operation] getLastError]);
        //set error in uilabel
        dispatch_async(dispatch_get_main_queue(), ^{

        self.lblResult.text = [[OPOperation operation] getLastError];
        });
    }
    });
}

- (IBAction)saveTokenIntoKeychain:(id)sender
{
    NSLog(@"saveTokenIntoKeychain");
    accessToken = [[OPOperation operation] getCurrentAccessToken];
    refreshToken = [[OPOperation operation] getCurrentRefreshToken];
    if (accessToken)
    {
        NSLog(@"Saved access token %@",accessToken);
    
        UIAlertView *info = [[UIAlertView alloc] initWithTitle:@"Info" message:@"Access Token has been saved successfully in keychain!!!" delegate:nil cancelButtonTitle:@"Ok" otherButtonTitles:nil, nil];
        [info show];
    }
}

- (IBAction)loadTokenFromKeychain:(id)sender
{
    NSLog(@"loadTokenFromKeychain");

}

@end
