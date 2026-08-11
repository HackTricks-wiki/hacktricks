# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

当与 XPC service 建立连接后，server 会检查该连接是否被允许。通常会执行以下检查：

1. 检查连接进程是否使用 **Apple-signed** certificate 签名（该 certificate 仅由 Apple 签发）。
- 如果**未进行验证**，攻击者就可以创建一个**伪造 certificate** 来满足其他任意检查。
2. 检查连接进程是否使用**组织的 certificate** 签名（team ID verification）。
- 如果**未进行验证**，可以使用 Apple 提供的**任意 developer certificate** 进行签名并连接到该 service。
3. 检查连接进程是否包含正确的 **bundle ID**。
- 如果**未进行验证**，任何**由同一组织签名**的 tool 都可以用来与 XPC service 交互。
4. （4 或 5）检查连接进程是否具有正确的软件版本号。
- 如果**未进行验证**，即使其他检查均已到位，仍可能使用一个易受 process injection 攻击的旧版、不安全 client 来连接 XPC service。
5. （4 或 5）检查连接进程是否启用了 hardened runtime，且未包含危险的 entitlements（例如允许加载任意 libraries 或使用 DYLD env vars 的 entitlements）。
1. 如果**未进行验证**，client 可能**易受 code injection 攻击**。
6. 检查连接进程是否具有允许其连接到该 service 的 **entitlement**。这适用于 Apple binaries。
7. **verification** 必须基于连接**client 的 audit token**，而不是其 process ID（**PID**），因为前者可以防止 **PID reuse attacks**。
- 开发者**很少使用 audit token** API call，因为它是**private** 的，Apple 可能随时对其进行更改。此外，Mac App Store apps 不允许使用 private API。
- 如果使用 **`processIdentifier`** 方法，则可能存在漏洞。
- 应使用 **`xpc_dictionary_get_audit_token`**，而不是 **`xpc_connection_get_audit_token`**，因为后者在某些情况下也可能存在漏洞，详见 [此处](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。<sup>[[5]](#references)</sup>

### Communication Attacks

有关 PID reuse attack 的更多信息，请检查：


{{#ref}}
macos-pid-reuse.md
{{#endref}}

有关 **`xpc_connection_get_audit_token`** attack 的更多信息，请检查：


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache 是 Apple Silicon machines 中引入的一种 defensive method，它存储 Apple binaries 的 CDHSAH 数据库，因此只有获允许且未被修改的 binaries 才能执行。这可以防止执行 downgrade versions。

### Code Examples

server 会在名为 **`shouldAcceptNewConnection`** 的 function 中实现此 **verification**。
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
`NSXPCConnection` 对象具有一个**私有**的 `auditToken` 属性（应使用该属性，但私有 API 可能发生变化）以及一个**公共**的 `processIdentifier` 属性（不应将其用于身份验证）。

可以通过类似以下方式验证连接进程：<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
如果开发者不希望检查 client 的版本，至少可以检查 client 是否容易受到进程注入攻击：
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
上述 `cs_*` 常量是 XNU 的 `osfmk/kern/cs_blobs.h` 中定义的 code-signing flags，因此可以对照源代码进行检查，而不是靠猜测：<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## References

- [1] [Apple Developer — 代码签名要求语言](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h`（代码签名标志 `CS_*`）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
