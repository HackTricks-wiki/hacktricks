# macOS Quick Look Generators

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Quick LookはmacOSの**ファイルプレビュー用フレームワーク**です。ユーザーがFinderでファイルを選択したり、Spaceキーを押したり、ホバーしたり、サムネイルが有効なディレクトリを表示すると、Quick Lookはファイルを解析して視覚的なプレビューをレンダリングするために**ジェネレータプラグインを自動的に読み込みます**。

Quick Lookジェネレータは特定の**Uniform Type Identifiers (UTIs)** に登録される**バンドル**（`.qlgenerator`）です。macOSがそのUTIに一致するファイルのプレビューを必要とすると、ジェネレータをサンドボックス化されたヘルパープロセス（`QuickLookSatellite` または `qlmanage`）に読み込み、そのジェネレータ関数を呼び出します。

### なぜセキュリティ上重要か

> [!WARNING]
> Quick Lookジェネレータは**ファイルを選択または表示するだけで**トリガーされ、"Open" 操作は必要ありません。これはユーザーが悪意のあるファイルを含むディレクトリに移動するだけで成立する強力な**受動的な悪用ベクタ**となります。

**攻撃対象:**
- ジェネレータはディスク、ダウンロード、メール添付、ネットワーク共有から**任意のファイルコンテンツを解析**する
- 細工されたファイルはジェネレータのコード内の**解析脆弱性**（バッファオーバーフロー、フォーマット文字列、型の混同など）を突く可能性がある
- プレビューのレンダリングは**自動的に**行われる — 悪意のあるファイルが置かれたDownloadsフォルダを表示するだけで十分
- Quick Lookは**サンドボックス化されたヘルパー**で実行されるが、このコンテキストからのサンドボックス脱出が実証されている

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

### インストール済みジェネレータの一覧
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
### スキャナーの使用
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

### ファイルベースの悪用

複雑なファイル形式（3Dモデル、科学データ、アーカイブ形式）を解析するサードパーティの Quick Look generator は格好の標的です：
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
### Drive-By (Downloads 経由)
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### サードパーティ製ジェネレータの置換

Quick Look generator bundle が **ユーザー書き込み可能な場所** (`~/Library/QuickLook/`) にインストールされている場合、置き換え可能です:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look をリモートでトリガーする
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## サンドボックスの考慮事項

Quick Look generators はサンドボックス化されたヘルパープロセス内で実行されます。サンドボックスプロファイルは次を制限します:
- File system access (主にプレビュー対象ファイルに対して読み取り専用)
- Network access (制限される)
- IPC (制限された mach-lookup)

ただし、サンドボックスには既知のエスケープベクターがあります:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## 実世界の CVE

| CVE | 説明 |
|---|---|
| CVE-2019-8741 | Quick Look のプレビューで発生した memory corruption（細工されたファイル経由） |
| CVE-2018-4293 | Quick Look generator の sandbox escape |
| CVE-2020-9963 | Quick Look のプレビュー処理での information disclosure |
| CVE-2021-30876 | Thumbnail generation における memory corruption |

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
## 参考文献

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
