# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

XPC service에 connection이 설정되면, server는 해당 connection이 허용되는지 확인합니다. 일반적으로 수행하는 check는 다음과 같습니다:

1. 연결하는 **process가 Apple-signed** certificate(Apple만 발급하는 certificate)로 sign되었는지 확인합니다.
- 이것이 **검증되지 않으면**, attacker가 다른 check와 일치하도록 **fake certificate**를 생성할 수 있습니다.
2. 연결하는 process가 **organization의 certificate**로 sign되었는지 확인합니다(Team ID verification).
- 이것이 **검증되지 않으면**, Apple의 **어떤 developer certificate**든 signing에 사용하여 service에 연결할 수 있습니다.
3. 연결하는 process가 **적절한 bundle ID를 포함하는지** 확인합니다.
- 이것이 **검증되지 않으면**, **동일한 org에서 sign된** 모든 tool을 사용하여 XPC service와 상호작용할 수 있습니다.
4. (4 또는 5) 연결하는 process가 **적절한 software version number를 갖는지** 확인합니다.
- 이것이 **검증되지 않으면**, 다른 check가 적용되어 있더라도 process injection에 취약한 오래된 insecure client를 사용하여 XPC service에 연결할 수 있습니다.
5. (4 또는 5) 연결하는 process가 arbitrary libraries를 load하거나 DYLD env vars를 사용할 수 있도록 하는 entitlement와 같은 위험한 entitlement 없이 hardened runtime을 사용하는지 확인합니다.
1. 이것이 **검증되지 않으면**, client가 **code injection에 취약할 수 있습니다.**
6. 연결하는 process가 service에 연결할 수 있도록 허용하는 **entitlement**를 갖고 있는지 확인합니다. 이는 Apple binaries에 적용됩니다.
7. **verification**은 연결하는 **client의 audit token**을 기반으로 해야 하며, process ID(**PID**)를 기반으로 해서는 안 됩니다. 전자는 **PID reuse attacks**를 방지하기 때문입니다.
- Developers는 **audit token** API call이 **private**이므로 이를 **거의 사용하지 않습니다**. 따라서 Apple이 언제든 이를 **변경할 수 있습니다**. 또한 Mac App Store apps에서는 private API 사용이 허용되지 않습니다.
- **`processIdentifier`** method를 사용하면 취약할 수 있습니다.
- **`xpc_connection_get_audit_token`** 대신 **`xpc_dictionary_get_audit_token`**을 사용해야 합니다. 후자는 특정 상황에서 [취약할 수도 있기 때문입니다](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).<sup>[[5]](#references)</sup>

### Communication Attacks

PID reuse attack에 대한 자세한 정보는 다음 check를 참고하세요:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attack에 대한 자세한 정보는 다음 check를 참고하세요:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache는 Apple Silicon machines에 도입된 defensive method로, Apple binaries의 CDHSAH database를 저장하여 허용된 non modified binaries만 실행할 수 있도록 합니다. 이를 통해 downgrade versions의 실행을 방지합니다.

### Code Examples

Server는 **`shouldAcceptNewConnection`**이라는 function에서 이 **verification**을 구현합니다.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
`NSXPCConnection` 객체에는 **private** **`auditToken`** 속성(사용해야 하는 속성이지만, private API이므로 변경될 수 있음)과 **public** **`processIdentifier`** 속성(인증에 사용해서는 안 됨)이 있습니다.

연결 프로세스는 다음과 같이 검증할 수 있습니다:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
개발자가 client의 버전을 확인하지 않으려는 경우, 최소한 해당 client가 process injection에 취약하지 않은지 확인할 수 있습니다:
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
위의 `cs_*` 상수는 XNU의 `osfmk/kern/cs_blobs.h`에 정의된 code-signing 플래그이므로, 추측하는 대신 소스 코드와 대조하여 확인할 수 있습니다:<sup>[[4]](#references)</sup>
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
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` 코드 서명 플래그)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token 스푸핑](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
