# macOS XPC Mach Services 滥用

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

**XPC**（跨进程通信）是 macOS 上主要的 IPC 机制。系统守护进程会暴露 **Mach services**——由 `launchd` 注册的命名端口，其他进程可以通过 `NSXPCConnection` 连接到这些端口。<sup>[[1]](#references)</sup>

每个包含 `MachServices` 键的 **LaunchDaemon** 和 **LaunchAgent** plist 都会注册一个或多个命名 Mach 端口。这些是系统范围的 XPC 端点，任何进程都可以尝试连接。<sup>[[2]](#references)</sup>

> [!WARNING]
> XPC Mach services 是 macOS 上**最大的单一本地提权攻击面**。近年来大多数本地 root exploit 都是通过 LaunchDaemons 中存在漏洞的 XPC services 实现的。root daemon 中暴露的每个方法都可能成为提权向量。

### 架构
```
Client Process (user context)
↓ NSXPCConnection / xpc_connection_create_mach_service()
↓ Mach message via launchd
Daemon Process (root context)
↓ Receives XPC message
↓ (Should verify client identity / entitlements)
↓ Performs privileged operation
```
## 枚举

### 查找提供 Mach Services 的 Daemons
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
### 枚举 XPC Interfaces

识别出 daemon 后，对其 XPC interface 进行 reverse-engineer：
```bash
# Find the protocol definition in the binary
strings /path/to/daemon | grep -i "protocol\|interface\|xpc\|method"

# Use class-dump to extract ObjC protocol definitions
class-dump /path/to/daemon | grep -A20 "@protocol"

# Check for XPC service bundles inside app bundles
find /Applications -path "*/XPCServices/*.xpc" 2>/dev/null
```
## XPC Client Verification Vulnerabilities

XPC services 中最常见的漏洞类型是**客户端验证不足**。守护进程应验证：

1. 连接进程的**代码签名**
2. 连接进程的**Entitlements**
3. **Audit token**（而不是 PID，因为 PID 可能被重新使用）

### Vulnerable Pattern: No Verification
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
### 漏洞模式：基于 PID 的验证（竞态条件）
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
### 安全模式：Audit Token Verification
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
## 攻击：连接到未受保护的 XPC Services
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
## 攻击：XPC 对象反序列化

接受复杂对象（符合 `NSSecureCoding`）的 XPC services 可能容易受到**反序列化攻击**：
```objc
// If the daemon accepts NSObject subclasses via XPC:
// An attacker can send a crafted object that triggers:
// 1. Type confusion (wrong class instantiated)
// 2. Path traversal (filename objects with ../)
// 3. Format string bugs (string objects as format arguments)
// 4. Integer overflow (large numeric values)
```
## Mach-Lookup Sandbox Exceptions

### How Exceptions Enable Sandbox Escape

Sandboxed applications normally can only communicate with their own XPC services. However, **mach-lookup exceptions** allow reaching system-wide services:
```xml
<!-- Entitlement granting mach-lookup exception -->
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array>
<string>com.apple.system.opendirectoryd.api</string>
<string>com.apple.SecurityServer</string>
<string>com.apple.CoreServices.coreservicesd</string>
</array>
```
### 查找具有广泛例外的应用程序
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
### Sandbox 逃逸链
```
1. Compromise sandboxed app (e.g., via renderer exploit in browser/email)
2. Enumerate mach-lookup exceptions from entitlements
3. Connect to each reachable system daemon
4. Fuzz the daemon's XPC interface for vulnerabilities
5. Exploit a daemon bug → code execution outside the sandbox
6. Escalate from daemon's privilege level (often root)
```
## 特权 Helper 工具（SMJobBless）

### 工作原理

`SMJobBless` 会安装一个由 launchd 以 root 身份运行的特权 Helper。该 Helper 通过 XPC 与其父应用通信：
```
App (user context) ←→ XPC ←→ Helper (root via launchd)
```
### 常见漏洞：弱授权
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
### 利用弱 Helper
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
## 现实世界中的 CVE

| CVE | 描述 |
|---|---|
| CVE-2023-41993 | XPC service 反序列化漏洞 |
| CVE-2022-22616 | 通过 XPC service abuse 绕过 Gatekeeper |
| CVE-2021-30657 | Sysmond XPC 权限提升 |
| CVE-2020-9839 | system daemon 中的 XPC 竞态条件 |
| CVE-2019-8802 | 特权 helper tool 缺少客户端验证<sup>[[5]](#references)</sup> |
| CVE-2023-32369 | Migraine —— 通过 `systemmigrationd` XPC 绕过 SIP<sup>[[3]](#references)</sup> |
| CVE-2022-26712 | 通过 PackageKit XPC 提升至 root 权限<sup>[[4]](#references)</sup> |

## 枚举脚本
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
## References

- [1] [Apple Developer — XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [2] [Apple Developer — Daemons and Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)
- [3] [New macOS vulnerability, Migraine, could bypass System Integrity Protection — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [4] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)
- [5] [Objective-See — XPC client validation and Rootpipe](https://objective-see.org/blog/blog_0x3E.html)
{{#include ../../../banners/hacktricks-training.md}}
