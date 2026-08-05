# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Quick LookはmacOSの**ファイルプレビュー framework**です。Finderでユーザーがファイルを選択したとき、Spaceキーを押したとき、ファイルにカーソルを合わせたとき、またはサムネイルが有効なディレクトリを表示したとき、Quick Lookは**generator pluginを自動的にロード**してファイルを解析し、視覚的なプレビューを生成します。<sup>[[1]](#references)</sup>

Quick Look generatorsは、特定の**Uniform Type Identifiers (UTIs)** に対して登録される**bundles**（`.qlgenerator`）です。macOSがそのUTIに一致するファイルのプレビューを必要とすると、generatorをsandbox化されたhelper process（`QuickLookSatellite`または`qlmanage`）にロードし、そのgenerator functionを呼び出します。

### セキュリティ上重要な理由

> [!WARNING]
> Quick Look generatorsは**ファイルを選択または表示するだけ**でトリガーされます。「Open」actionは必要ありません。つまり、ユーザーがmalicious fileを含むディレクトリに移動するだけでよいため、強力な**passive exploitation vector**になります。

**Attack surface:**
- Generatorsは、disk、downloads、email attachments、またはnetwork sharesにある**任意のファイルコンテンツを解析**する
- Crafted fileは、generator codeの**parsing vulnerabilities**（buffer overflows、format strings、type confusion）を悪用できる
- Preview renderingは**自動的に**実行されるため、malicious fileが保存されたDownloads folderを表示するだけで十分
- Quick Lookは**sandbox化されたhelper**で実行されるが、このcontextからのsandbox escapesも実証されている

## Architecture
```
User selects file in Finder
↓
Finder → QuickLookSatellite (sandboxed helper)
↓
Generator plugin loaded (.qlgenerator bundle)
↓
Plugin parses file content → Returns preview image/HTML
↓
Preview displayed to user
```
## 列挙

### インストール済み Generator の一覧
```bash
# List all Quick Look generators with their UTI registrations
qlmanage -m plugins 2>&1

# Find generator bundles on the system
find / -name "*.qlgenerator" -type d 2>/dev/null

# Common locations
ls /Library/QuickLook/
ls ~/Library/QuickLook/
ls /System/Library/QuickLook/

# Check a generator's Info.plist for UTI registrations
defaults read /path/to/Generator.qlgenerator/Contents/Info.plist 2>/dev/null
```
### Scannerの使用
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## 攻撃シナリオ

### ファイルベースのExploit

複雑なファイル形式（3Dモデル、科学データ、アーカイブ形式）を解析するサードパーティ製のQuick Look generatorは、格好の標的です：
```bash
# 1. Identify a third-party generator and its UTI
qlmanage -m plugins 2>&1 | grep -v "com.apple" | head -20

# 2. Find what file types it handles
defaults read /Library/QuickLook/SomeGenerator.qlgenerator/Contents/Info.plist \
CFBundleDocumentTypes 2>/dev/null

# 3. Craft a malicious file matching that UTI
# (fuzzer output or hand-crafted malformed file)

# 4. Place the file where the user will preview it
cp malicious.xyz ~/Downloads/

# 5. When user opens Downloads in Finder → preview triggers → exploit fires
```
### Downloads 経由の Drive-By
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### Third-Party Generator Replacement

Quick Look ジェネレータ bundle が **user-writable location**（`~/Library/QuickLook/`）にインストールされている場合、置き換えることができます:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### リモートからQuick Lookを起動する
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandbox に関する考慮事項

Quick Look generators は sandbox 化された helper process 内で実行されます。sandbox profile により、以下が制限されます。
- File system access（プレビュー対象ファイルへの mostly read-only）
- Network access（restricted）
- IPC（limited mach-lookup）

ただし、sandbox には既知の escape vectors があります:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## Real-World CVEs

| CVE | Description |
|---|---|
| CVE-2019-8741 | crafted file による Quick Look preview のメモリ破壊 |
| CVE-2018-4293 | Quick Look generator の sandbox escape |
| CVE-2020-9963 | Quick Look preview の処理による information disclosure |
| CVE-2021-30876 | Thumbnail generation におけるメモリ破壊 |

## Fuzzing Quick Look Generators
```bash
# Basic fuzzing approach for a Quick Look generator:

# 1. Identify the target generator and its file format
qlmanage -m plugins 2>&1 | grep "target-uti"

# 2. Collect seed corpus of valid files
find / -name "*.targetext" -size -1M 2>/dev/null | head -100

# 3. Mutate files and trigger preview
for f in /tmp/fuzz_corpus/*; do
# Mutate the file (using radamsa, honggfuzz, etc.)
radamsa "$f" > /tmp/fuzz_input.targetext

# Trigger Quick Look (with timeout to catch hangs)
timeout 5 qlmanage -t /tmp/fuzz_input.targetext 2>&1

# Check if QuickLookSatellite crashed
log show --last 5s --predicate 'process == "QuickLookSatellite" AND eventMessage CONTAINS "crash"' 2>/dev/null
done
```
## 参照

- [1] [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
- [3] [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
