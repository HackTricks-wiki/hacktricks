# macOS Quick Look 생성기

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Quick Look은 macOS의 **파일 미리보기 프레임워크**입니다. 사용자가 Finder에서 파일을 선택하거나 Space를 누르거나 마우스를 올리거나 썸네일이 활성화된 디렉터리를 볼 때, Quick Look은 **파일을 파싱하고 시각적 미리보기를 렌더링하기 위해 생성기 플러그인**을 자동으로 로드합니다.

Quick Look 생성기는 **번들**(`.qlgenerator`)로 특정 **Uniform Type Identifiers (UTIs)**에 등록됩니다. macOS가 해당 UTI에 맞는 파일의 미리보기가 필요하면, 생성기를 샌드박스된 헬퍼 프로세스(`QuickLookSatellite` 또는 `qlmanage`)로 로드하고 해당 생성기 함수를 호출합니다.

### 보안상 중요한 이유

> [!WARNING]
> Quick Look 생성기는 **파일을 단순히 선택하거나 보는 것만으로** 트리거됩니다 — "열기" 동작이 필요하지 않습니다. 이는 사용자가 악성 파일이 포함된 디렉터리로 이동하기만 하면 되는 강력한 passive exploitation vector가 됩니다.

공격 표면:
- 생성기는 디스크, 다운로드, 이메일 첨부파일, 또는 네트워크 공유 등에서 임의의 파일 콘텐츠를 **파싱**합니다
- 정교하게 조작된 파일은 생성기 코드의 **파싱 취약점**(buffer overflows, format strings, type confusion)을 악용할 수 있습니다
- 미리보기 렌더링은 **자동으로** 발생합니다 — 악성 파일이 놓인 Downloads 폴더를 보기만 해도 충분합니다
- Quick Look은 **샌드박스된 헬퍼**로 실행되지만, 이 컨텍스트에서의 sandbox escapes가 입증된 바 있습니다

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
## 열거

### 설치된 생성기 나열
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
### 스캐너 사용하기
```bash
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_type, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'quicklook_generator'
ORDER BY e.path;"
```
## 공격 시나리오

### 파일 기반 익스플로잇

복잡한 파일 형식(3D 모델, 과학 데이터, 아카이브 형식)을 파싱하는 타사 Quick Look generator는 주요 표적이다:
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
### Drive-By — 다운로드를 통한
```
1. Send crafted file via email/AirDrop/web download
2. File lands in ~/Downloads/
3. User opens Finder → navigates to Downloads
4. Finder requests thumbnail/preview → Quick Look loads generator
5. Generator parses malicious file → code execution in QuickLookSatellite
6. (Optional) Sandbox escape from QuickLookSatellite context
```
### 타사 생성기 교체

Quick Look generator 번들이 **사용자 쓰기 가능한 위치** (`~/Library/QuickLook/`)에 설치되어 있다면, 교체할 수 있습니다:
```bash
# Check for user-writable generators
ls -la ~/Library/QuickLook/ 2>/dev/null

# Replace with a malicious generator that:
# 1. Executes payload when any matching file is previewed
# 2. Optionally still generates a valid preview to avoid suspicion
```
### Quick Look을 원격으로 트리거하기
```bash
# Force Quick Look preview generation (for testing)
qlmanage -p /path/to/malicious/file

# Generate thumbnail (triggers generator without full preview)
qlmanage -t /path/to/malicious/file

# Force thumbnail regeneration for a directory
qlmanage -r cache
```
## 샌드박스 고려사항

Quick Look generators는 샌드박스된 헬퍼 프로세스 내에서 실행됩니다. 샌드박스 프로파일은 다음을 제한합니다:
- 파일 시스템 접근(대부분 미리보기 중인 파일에 대한 읽기 전용)
- 네트워크 접근(제한됨)
- IPC(제한된 mach-lookup)

하지만 샌드박스에는 알려진 탈출 벡터가 있습니다:
```bash
# Check the sandbox profile used by QuickLookSatellite
sandbox-exec -p '(version 1)(allow default)' /usr/bin/true 2>&1
# Compare with QuickLookSatellite's actual profile

# Quick Look processes may have mach-lookup exceptions to system services
# A sandbox escape chain: QLGenerator vuln → QuickLookSatellite → mach-lookup → system daemon
```
## 실제 CVE 사례

| CVE | 설명 |
|---|---|
| CVE-2019-8741 | Quick Look preview에서 조작된 파일을 통한 memory corruption |
| CVE-2018-4293 | Quick Look generator의 sandbox escape |
| CVE-2020-9963 | Quick Look preview 처리 중 information disclosure |
| CVE-2021-30876 | Thumbnail generation 중 memory corruption |

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
## 참고 자료

* [Apple Developer — Quick Look Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Introduction/Introduction.html)
* [Apple Security Updates — Quick Look CVEs](https://support.apple.com/en-us/HT201222)
* [Objective-See — Quick Look Attack Surface](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
