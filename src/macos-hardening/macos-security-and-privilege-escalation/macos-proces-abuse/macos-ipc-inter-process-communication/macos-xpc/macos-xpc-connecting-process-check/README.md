# macOS XPC 连接进程检查

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC 连接进程检查

当与 XPC 服务建立连接时，服务器将检查该连接是否被允许。通常会执行以下检查：

1. 检查连接的 **进程是否使用 Apple 签名** 的证书（仅由 Apple 发放）。
- 如果 **未验证**，攻击者可以创建一个 **伪造证书** 来匹配其他检查。
2. 检查连接的进程是否使用 **组织的证书**（团队 ID 验证）。
- 如果 **未验证**，可以使用 **任何开发者证书** 从 Apple 进行签名，并连接到服务。
3. 检查连接的进程 **是否包含正确的包 ID**。
- 如果 **未验证**，任何 **由同一组织签名的工具** 都可以用来与 XPC 服务交互。
4. (4 或 5) 检查连接的进程是否具有 **正确的软件版本号**。
- 如果 **未验证**，旧的、不安全的客户端，易受进程注入攻击，可以在其他检查到位的情况下连接到 XPC 服务。
5. (4 或 5) 检查连接的进程是否具有没有危险权限的 **强化运行时**（例如允许加载任意库或使用 DYLD 环境变量的权限）。
1. 如果 **未验证**，客户端可能 **易受代码注入** 攻击。
6. 检查连接的进程是否具有允许其连接到服务的 **权限**。这适用于 Apple 二进制文件。
7. **验证** 必须 **基于** 连接 **客户端的审计令牌** **而不是** 其进程 ID (**PID**)，因为前者可以防止 **PID 重用攻击**。
- 开发者 **很少使用审计令牌** API 调用，因为它是 **私有的**，所以 Apple 可能会 **随时更改**。此外，Mac App Store 应用不允许使用私有 API。
- 如果使用 **`processIdentifier`** 方法，可能会存在漏洞。
- 应使用 **`xpc_dictionary_get_audit_token`** 而不是 **`xpc_connection_get_audit_token`**，因为后者在某些情况下也可能 [存在漏洞](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。

### 通信攻击

有关 PID 重用攻击的更多信息，请查看：

{{#ref}}
macos-pid-reuse.md
{{#endref}}

有关 **`xpc_connection_get_audit_token`** 攻击的更多信息，请查看：

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - 降级攻击防护

Trustcache 是一种防御方法，旨在 Apple Silicon 机器中引入，存储 Apple 二进制文件的 CDHSAH 数据库，以便仅允许未修改的二进制文件执行。这可以防止降级版本的执行。

### 代码示例

服务器将在名为 **`shouldAcceptNewConnection`** 的函数中实现此 **验证**。
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
对象 NSXPCConnection 具有一个 **私有** 属性 **`auditToken`**（应该使用但可能会更改）和一个 **公共** 属性 **`processIdentifier`**（不应该使用）。

可以通过以下方式验证连接的进程：
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
如果开发者不想检查客户端的版本，他至少可以检查客户端是否不易受到进程注入的攻击：
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
