# macOS XPC 接続プロセスのチェック

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC 接続プロセスのチェック

XPC service への接続が確立されると、サーバーはその接続が許可されているかをチェックします。通常、以下のチェックが実行されます。

1. 接続元の **process が Apple-signed** 証明書（Apple だけが発行する証明書）で署名されているかをチェックする。
- これが **検証されない場合**、攻撃者は他のチェックに一致する **fake certificate** を作成できる。
2. 接続元の process が **組織の証明書**で署名されているかをチェックする（team ID verification）。
- これが **検証されない場合**、Apple の **developer certificate** で署名し、service に接続できる。
3. 接続元の process に **適切な bundle ID** が含まれているかをチェックする。
- これが **検証されない場合**、**同じ組織によって署名された**任意の tool を使用して XPC service とやり取りできる。
4. (4 または 5) 接続元の process に **適切な software version number** があるかをチェックする。
- これが **検証されない場合**、process injection に対して脆弱な古い insecure client を使用し、他のチェックが実施されていても XPC service に接続できる。
5. (4 または 5) 接続元の process が、任意の library の読み込みや DYLD env vars の使用を許可するものなど、危険な entitlements を持たない hardened runtime を使用しているかをチェックする。
1. これが **検証されない場合、** client は **code injection に対して脆弱**である可能性がある。
6. 接続元の process が service への接続を許可する **entitlement** を持っているかをチェックする。これは Apple binaries に適用される。
7. **verification** は、接続元の **client の audit token** に基づいて実行する必要があり、その process ID (**PID**) に基づいてはならない。前者は **PID reuse attacks** を防止するためである。
- Developers が **audit token** API call を使用することは **ほとんどない**。これは **private** であり、Apple がいつでも変更する可能性があるためである。さらに、private API の使用は Mac App Store apps では許可されていない。
- **`processIdentifier`** method が使用されている場合、脆弱である可能性がある。
- **`xpc_connection_get_audit_token`** の代わりに **`xpc_dictionary_get_audit_token`** を使用する必要がある。後者も [特定の状況では脆弱](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/) である可能性があるためである。<sup>[[5]](#references)</sup>

### 通信攻撃

PID reuse attack のチェックに関する詳細は、以下を参照してください。


{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`** attack のチェックに関する詳細は、以下を参照してください。


{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - Downgrade Attacks Prevention

Trustcache は Apple Silicon machines に導入された defensive method であり、Apple binaries の CDHSAH の database を保存し、許可された modified されていない binaries のみを実行できるようにします。これにより、downgrade versions の実行を防止します。

### Code Examples

サーバーは、**verification** を **`shouldAcceptNewConnection`** という function で実装します。
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
`NSXPCConnection`オブジェクトには、**private**な**`auditToken`**プロパティ（使用すべきもの。ただし、private APIは変更される可能性があります）と、**public**な**`processIdentifier`**プロパティ（認証には使用すべきではありません）があります。

接続元プロセスは、次のような方法で検証できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
開発者が client のバージョンを確認したくない場合でも、少なくとも client が process injection に対して脆弱でないことを確認できます：
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
上記の `cs_*` 定数は、XNU の `osfmk/kern/cs_blobs.h` で定義されている code-signing flags なので、推測ではなくソースコードと照合して確認できます。<sup>[[4]](#references)</sup>
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
- [4] [XNU — `osfmk/kern/cs_blobs.h`（`CS_*` code-signing flags）](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h)
- [5] [Sector 7 — XPC audit token spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
{{#include ../../../../../../banners/hacktricks-training.md}}
