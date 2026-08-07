# macOS XPC Connecting Process Check

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC Connecting Process Check

XPC serviceへの接続が確立されると、serverはその接続が許可されているかを確認します。通常、以下のチェックを実行します。

1. 接続している **processがApple-signed** 証明書（Appleからのみ発行される証明書）で署名されているかを確認する。
- これが **検証されない場合**、攻撃者は他のチェックに一致する **fake certificate** を作成できます。
2. 接続しているprocessが **organizationの証明書**（team ID verification）で署名されているかを確認する。
- これが **検証されない場合**、Appleの **developer certificate** で署名すれば、どのdeveloperでもserviceに接続できます。
3. 接続しているprocessに **適切なbundle IDが含まれているか** を確認する。
- これが **検証されない場合**、**同じorgによって署名された**あらゆるtoolを使用してXPC serviceとやり取りできます。
4. (4または5) 接続しているprocessに **適切なsoftware version number** があるかを確認する。
- これが **検証されない場合**、process injectionに対してvulnerableな古く安全でないclientを使用して、他のチェックが実施されていてもXPC serviceに接続できる可能性があります。
5. (4または5) 接続しているprocessが、任意のlibraryのloadやDYLD env varsの使用を許可するものなど、危険なentitlementなしでhardened runtimeを有効にしているかを確認する。
1. これが **検証されない場合**、clientは **code injectionに対してvulnerable** である可能性があります。
6. 接続しているprocessがserviceへの接続を許可する **entitlement** を持っているかを確認する。これはApple binariesに適用されます。
7. **verification** は、process ID（**PID**）ではなく、接続している **clientのaudit token** に **基づいて** 実行する必要があります。前者ではなく後者を使用することで、**PID reuse attacks** を防止できます。
- Developersが **audit token** API callを使用することは **ほとんどありません**。これは **private** であり、Appleがいつでも変更する可能性があるためです。また、private APIの使用はMac App Store appsでは許可されていません。
- **`processIdentifier`** methodが使用されている場合、vulnerableである可能性があります。
- **`xpc_connection_get_audit_token`** の代わりに **`xpc_dictionary_get_audit_token`** を使用する必要があります。後者も[特定の状況ではvulnerableになる可能性があります](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。<sup>[[5]](#references)</sup>

### Communication Attacks

PID reuse attackのチェックに関する詳細:


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attackのチェックに関する詳細:


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

TrustcacheはApple Silicon machinesで導入されたdefensive methodで、Apple binariesのCDHSAHのdatabaseを保存し、許可された変更されていないbinariesのみを実行できるようにします。これにより、downgrade versionsの実行が防止されます。

### Code Examples

serverは、**`shouldAcceptNewConnection`** というfunctionでこの **verification** を実装します。
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
オブジェクト NSXPCConnection には、**private** なプロパティ **`auditToken`**（使用すべきものですが、変更される可能性があります）と、**public** なプロパティ **`processIdentifier`**（使用すべきではないもの）があります。

接続元プロセスは、次のように検証できます:<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
開発者がクライアントのバージョンを確認したくない場合でも、少なくともクライアントが process injection に対して脆弱でないことを確認できます：
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
上記の `cs_*` constants は、XNU の `osfmk/kern/cs_blobs.h` で定義されている code-signing flags なので、推測ではなくソースと照合して確認できます。<sup>[[4]](#references)</sup>
```c
#define CS_HARD                     0x00000100  /* don't load invalid pages */
#define CS_KILL                     0x00000200  /* kill process if it becomes invalid */
#define CS_RESTRICT                 0x00000800  /* tell dyld to treat restricted */
#define CS_REQUIRE_LV               0x00002000  /* require library validation */
#define CS_RUNTIME                  0x00010000  /* Apply hardened runtime policies */
```
## 参考文献

- [1] [Apple Developer — Code Signing Requirement Language](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html)
- [2] [Apple Developer — `SecCodeCheckValidity`](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:))
- [3] [Apple Developer — `SecTaskCreateWithAuditToken`](https://developer.apple.com/documentation/security/sectaskcreatewithaudittoken(_:_:))
- [4] [XNU — `osfmk/kern/cs_blobs.h` (`CS_*` code-signing flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../../../banners/hacktricks-training.md}}
