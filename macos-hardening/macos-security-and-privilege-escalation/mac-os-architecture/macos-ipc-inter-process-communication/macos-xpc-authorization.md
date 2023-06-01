# macOS XPC Authorization

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## XPC Authorization

Apple also proposes another way to authenticate if the connecting process has **permissions to call the an exposed XPC method**.

When an application needs to **execute actions as a privileged user**, instead of running the app as a privileged user it usually installs as root a HelperTool as an XPC service that could be called from the app to perform those actions. However, the app calling the service should have enough authorization.

### ShuoldAcceptNewConnection always YES

An example could be found in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` it tries to **connect** to the **HelperTool**. And in `HelperTool/HelperTool.m` the function **`shouldAcceptNewConnection`** **won't check** any of the requirements indicated previously. It'll always return YES:

```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
    // Called by our XPC listener when a new connection comes in.  We configure the connection
    // with our protocol and ourselves as the main object.
{
    assert(listener == self.listener);
    #pragma unused(listener)
    assert(newConnection != nil);

    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
    newConnection.exportedObject = self;
    [newConnection resume];
    
    return YES;
}
```

For more information about how to properly configure this check:

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Application rights

However, there is some **authorization going on when a method from the HelperTool is called**.

The function **`applicationDidFinishLaunching`** from `App/AppDelegate.m` will create an empty authorization reference after the app has started. This should always work.\
Then, it will try to **add some rights** to that authorization reference calling `setupAuthorizationRights`:

```objectivec
- (void)applicationDidFinishLaunching:(NSNotification *)note
{
    [...]
    err = AuthorizationCreate(NULL, NULL, 0, &self->_authRef);
    if (err == errAuthorizationSuccess) {
        err = AuthorizationMakeExternalForm(self->_authRef, &extForm);
    }
    if (err == errAuthorizationSuccess) {
        self.authorization = [[NSData alloc] initWithBytes:&extForm length:sizeof(extForm)];
    }
    assert(err == errAuthorizationSuccess);
    
    // If we successfully connected to Authorization Services, add definitions for our default 
    // rights (unless they're already in the database).
    
    if (self->_authRef) {
        [Common setupAuthorizationRights:self->_authRef];
    }
    
    [self.window makeKeyAndOrderFront:self];
}
```

The function `setupAuthorizationRights` from `Common/Common.m` will store in the auth database `/var/db/auth.db` the rights of the application. Note how it will only add the rights that aren't yet in the database:

```objectivec
+ (void)setupAuthorizationRights:(AuthorizationRef)authRef
    // See comment in header.
{
    assert(authRef != NULL);
    [Common enumerateRightsUsingBlock:^(NSString * authRightName, id authRightDefault, NSString * authRightDesc) {
        OSStatus    blockErr;
        
        // First get the right.  If we get back errAuthorizationDenied that means there's 
        // no current definition, so we add our default one.
        
        blockErr = AuthorizationRightGet([authRightName UTF8String], NULL);
        if (blockErr == errAuthorizationDenied) {
            blockErr = AuthorizationRightSet(
                authRef,                                    // authRef
                [authRightName UTF8String],                 // rightName
                (__bridge CFTypeRef) authRightDefault,      // rightDefinition
                (__bridge CFStringRef) authRightDesc,       // descriptionKey
                NULL,                                       // bundle (NULL implies main bundle)
                CFSTR("Common")                             // localeTableName
            );
            assert(blockErr == errAuthorizationSuccess);
        } else { 
            // A right already exists (err == noErr) or any other error occurs, we 
            // assume that it has been set up in advance by the system administrator or
            // this is the second time we've run.  Either way, there's nothing more for 
            // us to do.
        }
    }];
}
```

The function `enumerateRightsUsingBlock` is the one used to get applications permissions, which are defined in `commandInfo`:

```objectivec
static NSString * kCommandKeyAuthRightName    = @"authRightName";
static NSString * kCommandKeyAuthRightDefault = @"authRightDefault";
static NSString * kCommandKeyAuthRightDesc    = @"authRightDescription";

+ (NSDictionary *)commandInfo
{
    static dispatch_once_t sOnceToken;
    static NSDictionary *  sCommandInfo;
    
    dispatch_once(&sOnceToken, ^{
        sCommandInfo = @{
            NSStringFromSelector(@selector(readLicenseKeyAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.readLicenseKey", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to read its license key.", 
                    @"prompt shown when user is required to authorize to read the license key"
                )
            },
            NSStringFromSelector(@selector(writeLicenseKey:authorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.writeLicenseKey", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleAuthenticateAsAdmin, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to write its license key.", 
                    @"prompt shown when user is required to authorize to write the license key"
                )
            },
            NSStringFromSelector(@selector(bindToLowNumberPortAuthorization:withReply:)) : @{
                kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.startWebService", 
                kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow, 
                kCommandKeyAuthRightDesc    : NSLocalizedString(
                    @"EBAS is trying to start its web service.", 
                    @"prompt shown when user is required to authorize to start the web service"
                )
            }
        };
    });
    return sCommandInfo;
}

+ (NSString *)authorizationRightForCommand:(SEL)command
    // See comment in header.
{
    return [self commandInfo][NSStringFromSelector(command)][kCommandKeyAuthRightName];
}

+ (void)enumerateRightsUsingBlock:(void (^)(NSString * authRightName, id authRightDefault, NSString * authRightDesc))block
    // Calls the supplied block with information about each known authorization right..
{
    [self.commandInfo enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        #pragma unused(key)
        #pragma unused(stop)
        NSDictionary *  commandDict;
        NSString *      authRightName;
        id              authRightDefault;
        NSString *      authRightDesc;
        
        // If any of the following asserts fire it's likely that you've got a bug 
        // in sCommandInfo.
        
        commandDict = (NSDictionary *) obj;
        assert([commandDict isKindOfClass:[NSDictionary class]]);

        authRightName = [commandDict objectForKey:kCommandKeyAuthRightName];
        assert([authRightName isKindOfClass:[NSString class]]);

        authRightDefault = [commandDict objectForKey:kCommandKeyAuthRightDefault];
        assert(authRightDefault != nil);

        authRightDesc = [commandDict objectForKey:kCommandKeyAuthRightDesc];
        assert([authRightDesc isKindOfClass:[NSString class]]);

        block(authRightName, authRightDefault, authRightDesc);
    }];
}
```

This means that at the end of this process, the permissions declared inside `commandInfo` will be stored in `/var/db/auth.db`. Note how there you can find for **each method** that will r**equire authentication**,  **permission name** and the **`kCommandKeyAuthRightDefault`**. The later one **indicates who can get this right**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Anyone</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nobody</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Current user needs to be an admin (inside admin group)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ask user to authenticate.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ask user to authenticate. He needs to be an admin (inside admin group)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specify rules</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specify some extra comments on the right</td></tr></tbody></table>

### Rights Verification

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **execute such method** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **what is needed to get the right** to call the specific method. If all goes good the **returned `error` will be `nil`**:

```objectivec
- (NSError *)checkAuthorization:(NSData *)authData command:(SEL)command
{
    [...]

    // First check that authData looks reasonable.
    
    error = nil;
    if ( (authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)) ) {
        error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
    }
    
    // Create an authorization ref from that the external form data contained within.
    
    if (error == nil) {
        err = AuthorizationCreateFromExternalForm([authData bytes], &authRef);
        
        // Authorize the right associated with the command.
        
        if (err == errAuthorizationSuccess) {
            AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
            AuthorizationRights rights   = { 1, &oneRight };

            oneRight.name = [[Common authorizationRightForCommand:command] UTF8String];
            assert(oneRight.name != NULL);
            
            err = AuthorizationCopyRights(
                authRef,
                &rights,
                NULL,
                kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
                NULL
            );
        }
        if (err != errAuthorizationSuccess) {
            error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
        }
    }

    if (authRef != NULL) {
        junk = AuthorizationFree(authRef, 0);
        assert(junk == errAuthorizationSuccess);
    }

    return error;
}
```

Note that to **check the requirements to get the right** to call that method the function `authorizationRightForCommand` will just check the previously comment object **`commandInfo`**. Then, it will call **`AuthorizationCopyRights`** to check **if it has the rights** to call the function (note that the flags allow interaction with the user).

In this case, to call the function `readLicenseKeyAuthorization` the `kCommandKeyAuthRightDefault` is defined to `@kAuthorizationRuleClassAllow`. So **anyone can call it**.

### DB Information

It was mentioned that this information is stored in `/var/db/auth.db`. You can list all the stored rules with:

```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```

Then, you can read who can access the right with:

```bash
security authorizationdb read com.apple.safaridriver.allow
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
