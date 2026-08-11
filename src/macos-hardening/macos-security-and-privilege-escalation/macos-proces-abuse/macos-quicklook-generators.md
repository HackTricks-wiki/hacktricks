# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Quick LookはmacOSの**ファイルプレビュー framework**です。ユーザーがFinderでファイルを選択したり、Spaceキーを押したり、ファイルにカーソルを合わせたり、サムネイルを有効にしたディレクトリを表示したりすると、Quick Lookは**generator pluginを自動的にロード**してファイルを解析し、視覚的なプレビューを生成します。<sup>[[1]](#references)</sup>

Quick Look generatorsは、特定の**Uniform Type Identifiers (UTIs)** に登録される**bundles**（`.qlgenerator`）です。macOSがそのUTIに一致するファイルのプレビューを必要とすると、generatorをsandbox化されたhelper process（`QuickLookSatellite`または`qlmanage`）にロードし、そのgenerator functionを呼び出します。

### これがSecurity上重要な理由

> [!WARNING]
> Quick Look generatorsは**ファイルを選択または表示するだけ**で起動されます。「Open」操作は必要ありません。つまり、ユーザーがmalicious fileを含むディレクトリに移動するだけでよく、強力な**passive exploitation vector**になります。

**Attack surface:**
- Generatorsは、ディスク、downloads、email attachments、またはnetwork shares上の**任意のファイル内容を解析**します
- 細工されたファイルは、generator codeの**parsing vulnerabilities**（buffer overflows、format strings、type confusion）を悪用できます
- プレビューのrenderingは**自動的に**実行されるため、malicious fileが保存されたDownloadsフォルダを表示するだけで十分です
- Quick Lookは**sandbox化されたhelper**内で実行されますが、このcontextからのsandbox escapesが実証されています

## アーキテクチャ
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

### インストール済みジェネレータの一覧表示
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
### Third-Party Generator の置き換え

Quick Look generator bundle が **user-writable location**（`~/Library/QuickLook/`）にインストールされている場合、置き換えることができます：
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Lookをリモートでトリガーする
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## Sandboxに関する考慮事項

Quick Look generatorsは、sandbox化されたhelper process内で実行されます。sandbox profileによって以下が制限されます：
- File system access（プレビュー対象ファイルへのほぼread-onlyアクセス）
- Network access（制限あり）
- IPC（mach-lookupは制限あり）

ただし、sandboxには既知のescape vectorsがあります：
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## 実際のCVE<sup>[[2]](#references)</sup>

| CVE | 説明 |
|---|---|
| CVE-2019-8741 | 細工したファイルによるQuick Lookプレビューのメモリ破損 |
| CVE-2018-4293 | Quick Look generatorのsandbox escape |
| CVE-2020-9963 | Quick Lookプレビュー処理による情報漏えい |
| CVE-2021-30876 | サムネイル生成時のメモリ破損 |

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
## References

- [1] [Apple Developer — Quick Look プログラミングガイド](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
- [2] [Apple セキュリティアップデート — Quick Look CVE](https://support.apple.com/en-us/HT201222)
{{#include ../../../banners/hacktricks-training.md}}
