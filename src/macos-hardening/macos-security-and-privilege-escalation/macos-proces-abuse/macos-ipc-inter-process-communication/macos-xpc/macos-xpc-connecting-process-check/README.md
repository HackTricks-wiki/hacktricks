# macOS XPC 연결 프로세스 확인

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC 연결 프로세스 확인

XPC 서비스에 연결이 설정되면, 서버는 연결이 허용되는지 확인합니다. 일반적으로 수행하는 확인 사항은 다음과 같습니다:

1. 연결하는 **프로세스가 Apple 서명** 인증서로 서명되었는지 확인합니다 (Apple에서만 발급).
- 이 **확인이 이루어지지 않으면**, 공격자는 **가짜 인증서**를 만들어 다른 확인 사항에 맞출 수 있습니다.
2. 연결하는 프로세스가 **조직의 인증서**로 서명되었는지 확인합니다 (팀 ID 확인).
- 이 **확인이 이루어지지 않으면**, Apple의 **모든 개발자 인증서**가 서명에 사용될 수 있으며, 서비스에 연결할 수 있습니다.
3. 연결하는 프로세스가 **적절한 번들 ID**를 포함하는지 확인합니다.
- 이 **확인이 이루어지지 않으면**, 동일한 조직에서 **서명된 도구**가 XPC 서비스와 상호작용하는 데 사용될 수 있습니다.
4. (4 또는 5) 연결하는 프로세스가 **적절한 소프트웨어 버전 번호**를 가지고 있는지 확인합니다.
- 이 **확인이 이루어지지 않으면**, 오래된, 안전하지 않은 클라이언트가 프로세스 주입에 취약하여 다른 확인 사항이 있더라도 XPC 서비스에 연결될 수 있습니다.
5. (4 또는 5) 연결하는 프로세스가 위험한 권한이 없는 **강화된 런타임**을 가지고 있는지 확인합니다 (임의의 라이브러리를 로드하거나 DYLD 환경 변수를 사용할 수 있는 권한과 같은).
1. 이 **확인이 이루어지지 않으면**, 클라이언트는 **코드 주입에 취약할 수 있습니다**.
6. 연결하는 프로세스가 서비스에 연결할 수 있는 **권한**을 가지고 있는지 확인합니다. 이는 Apple 바이너리에 적용됩니다.
7. **검증**은 연결하는 **클라이언트의 감사 토큰**을 **기반으로** 해야 하며, 프로세스 ID (**PID**) 대신 사용해야 합니다. 이는 후자가 **PID 재사용 공격**을 방지하기 때문입니다.
- 개발자는 **감사 토큰** API 호출을 **드물게 사용**하며, 이는 **비공식적**이므로 Apple이 언제든지 **변경**할 수 있습니다. 또한, 비공식 API 사용은 Mac App Store 앱에서 허용되지 않습니다.
- **`processIdentifier`** 메서드가 사용되면 취약할 수 있습니다.
- **`xpc_dictionary_get_audit_token`**을 **`xpc_connection_get_audit_token`** 대신 사용해야 하며, 후자는 특정 상황에서 [취약할 수 있습니다](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### 통신 공격

PID 재사용 공격에 대한 자세한 내용은 다음을 확인하십시오:

{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** 공격에 대한 자세한 내용은 다음을 확인하십시오:

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - 다운그레이드 공격 방지

Trustcache는 Apple Silicon 기계에서 도입된 방어 방법으로, Apple 바이너스의 CDHSAH 데이터베이스를 저장하여 허용된 비수정 바이너스만 실행될 수 있도록 합니다. 이는 다운그레이드 버전의 실행을 방지합니다.

### 코드 예제

서버는 **`shouldAcceptNewConnection`**이라는 함수에서 이 **검증**을 구현합니다.
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
NSXPCConnection 객체는 **private** 속성 **`auditToken`** (사용해야 하지만 변경될 수 있는 것)과 **public** 속성 **`processIdentifier`** (사용해서는 안 되는 것)을 가지고 있습니다.

연결된 프로세스는 다음과 같은 방법으로 확인할 수 있습니다:
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
개발자가 클라이언트의 버전을 확인하고 싶지 않다면, 적어도 클라이언트가 프로세스 주입에 취약하지 않은지 확인할 수 있습니다:
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
{{#include ../../../../../../banners/hacktricks-training.md}}
