# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

जब किसी XPC service से connection स्थापित किया जाता है, तो server यह जांच करेगा कि connection की अनुमति है या नहीं। आमतौर पर यह निम्नलिखित checks करेगा:

1. जांचें कि connecting **process पर Apple-signed** certificate से signature किया गया है या नहीं (जो केवल Apple द्वारा जारी किया जाता है)।
- यदि यह **verified नहीं है**, तो attacker किसी भी अन्य check से मेल खाने वाला **fake certificate** बना सकता है।
2. जांचें कि connecting process पर **organization’s certificate** से signature किया गया है या नहीं (team ID verification)।
- यदि यह **verified नहीं है**, तो Apple का **कोई भी developer certificate** signing के लिए उपयोग करके service से connect किया जा सकता है।
3. जांचें कि connecting process में **proper bundle ID** मौजूद है या नहीं।
- यदि यह **verified नहीं है**, तो **same org** द्वारा signed कोई भी tool XPC service के साथ interact करने के लिए उपयोग किया जा सकता है।
4. (4 या 5) जांचें कि connecting process में **proper software version number** मौजूद है या नहीं।
- यदि यह **verified नहीं है**, तो process injection के प्रति vulnerable कोई पुराना, insecure client, अन्य checks मौजूद होने पर भी XPC service से connect करने के लिए उपयोग किया जा सकता है।
5. (4 या 5) जांचें कि connecting process में dangerous entitlements के बिना hardened runtime है या नहीं (जैसे arbitrary libraries load करने या DYLD env vars उपयोग करने वाले entitlements)
1. यदि यह **verified नहीं है,** तो client **code injection के प्रति vulnerable** हो सकता है।
6. जांचें कि connecting process के पास ऐसी **entitlement** है या नहीं जो उसे service से connect करने की अनुमति देती है। यह Apple binaries पर लागू होता है।
7. **verification** connecting **client के audit token** पर **आधारित** होनी चाहिए, न कि उसके process ID (**PID**) पर, क्योंकि audit token **PID reuse attacks** को रोकता है।
- Developers **audit token** API call का उपयोग **बहुत कम करते हैं**, क्योंकि यह **private** है और Apple इसे किसी भी समय **बदल सकता है**। इसके अतिरिक्त, Mac App Store apps में private API का उपयोग अनुमत नहीं है।
- यदि **`processIdentifier`** method का उपयोग किया जाता है, तो यह vulnerable हो सकता है।
- **`xpc_connection_get_audit_token`** के बजाय **`xpc_dictionary_get_audit_token`** का उपयोग किया जाना चाहिए, क्योंकि बाद वाला कुछ परिस्थितियों में [vulnerable](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) हो सकता है।<sup>[[5]](#references)</sup>

### Communication Attacks

PID reuse attack के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attack के बारे में अधिक जानकारी के लिए देखें:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache Apple Silicon machines में शुरू की गई एक defensive method है, जो Apple binaries के CDHSAH का database store करती है, ताकि केवल allowed और non modified binaries को execute किया जा सके। यह downgrade versions के execution को रोकती है।

### Code Examples

Server इस **verification** को **`shouldAcceptNewConnection`** नामक function में implement करेगा।
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
`NSXPCConnection` object में एक **private** **`auditToken`** property होती है (इसी का उपयोग किया जाना चाहिए, हालांकि private API बदल सकती है) और एक **public** **`processIdentifier`** property होती है (जिसका उपयोग authentication के लिए नहीं किया जाना चाहिए)।

Connecting process को कुछ इस तरह verify किया जा सकता है:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
यदि कोई developer client के version की जाँच नहीं करना चाहता, तो कम-से-कम वह यह जाँच कर सकता है कि client process injection के प्रति vulnerable नहीं है:
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
ऊपर दिए गए `cs_*` constants XNU के `osfmk/kern/cs_blobs.h` में परिभाषित code-signing flags हैं, इसलिए इन्हें अनुमान लगाने के बजाय source के विरुद्ध जाँचा जा सकता है:<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
