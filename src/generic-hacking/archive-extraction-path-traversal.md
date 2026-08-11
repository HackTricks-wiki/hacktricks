# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 archive 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목에 자체 **internal path**를 포함할 수 있습니다. extraction utility가 해당 경로를 무조건 따를 경우, `..` 또는 **absolute path**(예: `C:\Windows\System32\`)가 포함된 조작된 파일명이 사용자가 선택한 디렉터리 외부에 기록됩니다.
이러한 취약점 유형은 일반적으로 *Zip-Slip* 또는 **archive extraction path traversal**이라고 합니다.<sup>[[6]](#references)</sup>

영향은 임의의 파일 덮어쓰기부터 Windows *Startup* 폴더와 같은 **auto-run** 위치에 payload를 배치하여 직접 **remote code execution (RCE)** 을 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자는 하나 이상의 file header에 다음 항목이 포함된 archive를 생성합니다.
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 target dir 외부로 resolve되는 조작된 **symlinks**(*nix의 ZIP/TAR에서 일반적).
2. Victim은 embedded path를 신뢰하거나 symlinks를 따르는 vulnerable tool로 archive를 extract합니다. 이 tool은 해당 경로를 sanitise하거나 선택한 디렉터리 아래로 extraction을 강제하지 않습니다.
3. 파일이 공격자가 제어하는 위치에 기록되고, 다음에 system 또는 user가 해당 경로를 trigger할 때 실행되거나 load됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET anti-pattern은 의도한 destination과 **user-controlled** `ZipArchiveEntry.FullName`을 결합한 뒤 path normalisation 없이 extraction하는 것입니다:<sup>[[4]](#references)[[8]](#references)</sup>
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
- scheduled scanner가 감시하는 sibling `app` 디렉터리에 기록하는 PoC archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 모니터링되는 inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 외부로의 traversal이 가능함을 입증하고, 후속 primitive(예: DLL hijack)를 사용할 수 있게 됩니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR와 해당 Windows RAR/UnRAR components는 extraction 중 filename을 검증하지 못했습니다. 이 취약점은 NTFS alternate data streams (ADS)를 사용해 선택된 extraction path를 우회하고 의도하지 않은 위치에 파일을 기록했습니다.<sup>[[5]](#references)</sup>
다음과 같은 entry가 포함된 malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
선택한 출력 디렉터리의 **외부**에 위치하고 사용자의 *Startup* 폴더 내부에 생성된다. ESET은 악성 LNK 파일이 해당 위치에 압축 해제된 후 사용자가 로그온할 때 실행되어 persistence와 RCE 경로를 제공하는 사례를 관찰했다.<sup>[[5]](#references)</sup>

### PoC Archive 제작 (Linux/Mac)

CVE-2025-8088은 ADS 이름에 traversal path를 사용하므로, 용도에 맞게 제작된 generator를 사용해 RAR을 만든 다음 vulnerable WinRAR build를 사용하는 격리된 lab에서만 extraction을 테스트해야 한다.<sup>[[5]](#references)</sup>

### 실제 환경에서 관찰된 Exploitation

ESET은 RomCom (Storm-0978/UNC2596)의 spear-phishing campaigns에서 CVE-2025-8088을 악용하는 RAR archives를 첨부해 customised backdoors를 배포하고 ransomware operations를 지원한 사례를 보고했다.<sup>[[5]](#references)</sup>

## 최신 사례 (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic links**인 ZIP entries가 extraction 중 dereference되어 attackers가 destination directory를 벗어나 임의의 paths를 overwrite할 수 있었다. User interaction은 archive를 *opening/extracting*하는 것뿐이다.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** 이전의 7-Zip builds. Symbolic-link processing flaw는 **25.00** (2025년 7월) 및 이후 버전에서 수정되었다.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` 또는 service-run locations를 overwrite → 다음 logon 또는 service restart 시 code가 실행된다.
* **간단한 symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
이 archive에는 extraction directory 외부를 가리키는 symlink entry가 포함되어 있다. disposable target을 사용하고 extractor가 해당 symlink를 follow하지 않는지 확인해야 한다. Write-through test에는 symlink 아래에 regular-file entry도 필요하다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`가 `../` 및 symlinked ZIP entries를 follow하여 `outputDir` 외부에 write한다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (현재 project는 deprecated 상태).
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나 write 전에 canonical-path checks를 구현한다.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Archive entries를 나열하고 `../`, `..\\`, *absolute paths* (`/`, `C:`)를 포함하는 이름 또는 target이 extraction dir 외부에 있는 *symlink* 유형의 entries를 flag한다.
* **Canonicalisation** – `realpath(join(dest, name))`이 `realpath(dest)` 내부에 유지되는지 확인한다 (raw string prefix만이 아니라 path components를 비교). 그렇지 않으면 reject한다.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – path/symlink checks를 수행하는 extractor (예: bsdtar의 default secure checks 또는 7-Zip ≥ 25.00)를 사용해 disposable directory에 Decompress한 다음, 결과 paths가 해당 directory 내부에 유지되는지 확인한다.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip 등이 archive를 연 직후 `Startup`/`Run`/`cron` locations에 새 executables가 write되는 경우 alert한다.

## Mitigation & Hardening

1. **Extractor를 Update** – WinRAR 7.13+ 및 7-Zip 25.00+에는 d path/symlink issues에 대한 fixes가 포함되어 있다.<sup>[[1]](#references)[[5]](#references)</sup>
2. 가능한 경우 “**Do not extract paths**” / “**Ignore paths**”를 사용해 archives를 Extract한다.
3. Unix에서는 extraction 전에 privileges를 drop하고 **chroot/namespace**를 mount한다. Windows에서는 **AppContainer** 또는 sandbox를 사용한다.
4. Custom code를 작성하는 경우 create/write **전에** `realpath()`/`PathCanonicalize()`로 normalise하고 destination에서 벗어나는 모든 entry를 reject한다.

## Additional Affected / Historical Cases

* 2018 – 다수의 Java/Go/JS libraries에 영향을 준 Snyk의 대규모 *Zip-Slip* advisory.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377)의 slugs 내 TAR extraction traversal (v0.16.3에서 수정됨).<sup>[[7]](#references)</sup>
* Write 전에 `PathCanonicalize` / `realpath`를 호출하지 못하는 모든 custom extraction logic.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET에서 Zip Slip 방지](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 지금 WinRAR tools를 Update할 것: RomCom 및 기타 actors가 zero-day vulnerability (CVE-2025-8088)를 Exploit](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability의 Public Disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug가 Zip Slip Attack (CVE-2025-0377)에 취약](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip의 CVE-2025-11001에 대한 Proof-of-Concept Exploit 보고](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
