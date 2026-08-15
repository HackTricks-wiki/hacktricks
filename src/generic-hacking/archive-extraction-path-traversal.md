# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 archive format (ZIP, RAR, TAR, 7-ZIP 등)은 각 entry에 자체 **internal path**를 포함할 수 있습니다. extraction utility가 해당 path를 무조건 따를 경우, `..` 또는 **absolute path** (예: `C:\Windows\System32\`)가 포함된 조작된 filename이 사용자가 선택한 directory 외부에 기록됩니다.
이 vulnerability class는 일반적으로 *Zip-Slip* 또는 **archive extraction path traversal**이라고 알려져 있습니다.<sup>[[6]](#references)</sup>

영향은 임의의 file overwrite부터 Windows *Startup* folder와 같은 **auto-run** location에 payload를 배치하여 직접 **remote code execution (RCE)**을 달성하는 것까지 다양합니다.

## 근본 원인

1. Attacker가 하나 이상의 file header에 다음 항목이 포함된 archive를 생성합니다.
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 target dir 외부로 resolve되는 조작된 **symlinks** (*nix의 ZIP/TAR에서 일반적)
2. Victim이 embedded path를 신뢰하거나 symlinks를 따르는 vulnerable tool로 archive를 extract합니다. 이때 path를 sanitise하거나 선택한 directory 하위로 extraction을 강제하지 않습니다.
3. File이 attacker-controlled location에 기록되고, 다음에 system 또는 user가 해당 path를 trigger할 때 실행되거나 load됩니다.

### .NET `Path.Combine` + `ZipArchive` traversal

일반적인 .NET anti-pattern은 의도한 destination과 **user-controlled** `ZipArchiveEntry.FullName`을 결합한 뒤 path normalisation 없이 extract하는 것입니다.<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName`이 `..\\`로 시작하면 traversal이 발생합니다. **absolute path**인 경우 왼쪽 구성 요소가 완전히 삭제되어, extraction identity로 **arbitrary file write**가 발생합니다.
- scheduled scanner가 감시하는 sibling `app` 디렉터리에 쓰기 위한 proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 모니터링되는 inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 외부로의 traversal이 가능함을 입증하고, 후속 primitive(예: DLL hijacks)를 활성화합니다.

## 고급 Archive-Breakout Primitives

Extraction을 서로 독립적인 filename 검사들의 집합이 아니라 일련의 filesystem mutation으로 취급해야 합니다. 파싱 시에는 안전한 entry가 앞선 member가 link를 생성하거나 교체한 후에는 안전하지 않게 될 수 있습니다. Extractor가 directory를 안전하다고 캐시한 뒤 해당 directory의 type이 변경되는 경우에도 같은 문제가 발생합니다.<sup>[[11]](#references)</sup>

### Link pivots 및 entry collisions

* **Symlink write-through**: `pivot -> /tmp`를 생성한 다음 regular member를 `pivot/PWNED.txt`로 extract합니다. Extractor가 첫 번째 member를 따르는 상태에서 두 번째 member를 materialise하면, 두 번째 name에 `..`가 없어도 write가 탈출합니다.
* **Directory-cache/TOCTOU collision**: directory `d/sub/`를 생성하고, `d/sub`를 `/tmp`를 가리키는 symlink로 교체한 다음 `d/sub/PWNED.txt`를 생성합니다. 이는 directory를 한 번만 validate하거나 cache하고 최종 write 전에 다시 확인하지 않는 extractor를 대상으로 합니다.
* **Hardlink read/overwrite**: TAR 및 RAR은 hardlink를 표현할 수 있습니다. 기존 host file에 대한 hardlink는 이후 component가 extracted name을 제공할 때 해당 file의 contents를 노출할 수 있으며, 충돌하는 regular entry는 대신 연결된 inode를 overwrite할 수 있습니다. 이는 동일 filesystem 및 OS hardlink-permission 규칙의 제약을 받습니다.
* **Pre-existing 또는 cross-archive pivot**: 비어 있지 않은 destination에서 다시 시도합니다. 각 archive가 stateless header-name check를 통과하더라도, 한 archive가 link를 심고 이후 extraction이 이를 통해 write할 수 있습니다.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

이름은 해당 이름을 수용할 filesystem의 semantics를 사용해 비교해야 합니다. 유용한 differential case에는 case-insensitive filesystem에서의 `LINK`와 `link`, NFC와 NFD Unicode 표기, `ﬁle`과 `file`처럼 compatibility-equivalent인 이름, path를 directory에서 symlink로 변경하는 duplicate member, Windows에서만 backslash를 separator로 해석하는 경우가 포함됩니다. 또한 NTFS에서 ADS-bearing name도 테스트해야 합니다. 이러한 경우 validator는 두 path를 인식하지만 filesystem은 하나로 resolve할 수 있습니다.<sup>[[5]](#references)[[11]](#references)</sup>

따라서 compact corpus는 **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, `/`와 `\`의 혼합, absolute/rooted name, `.tar.gz`와 같은 compressed wrapper의 순서가 있는 조합을 테스트해야 합니다. 이 작업은 disposable VM/container에서만 실행하고 destination과 의도한 외부 canary path를 모두 감시해야 합니다.<sup>[[11]](#references)</sup>

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR 및 Windows RAR/UnRAR component는 extraction 중 filename을 validate하지 못했습니다. 이 flaw는 NTFS alternate data stream(ADS)을 사용해 선택된 extraction path를 우회하고 의도하지 않은 위치에 file을 write했습니다.<sup>[[5]](#references)</sup>
다음과 같은 entry를 포함하는 malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **선택한 출력 디렉터리의 외부**이자 사용자의 *Startup* 폴더 내부에 위치하게 됩니다. ESET은 악성 LNK 파일이 해당 위치에 압축 해제된 후 사용자 로그온 시 실행되어 persistence와 RCE 경로를 제공하는 사례를 관찰했습니다.<sup>[[5]](#references)</sup>

### PoC Archive 만들기 (Linux/Mac)

CVE-2025-8088은 ADS 이름에 traversal path를 사용하므로, 특수 목적의 generator를 사용해 RAR를 만든 다음 취약한 WinRAR build를 사용하는 격리된 lab에서만 extraction을 테스트해야 합니다.<sup>[[5]](#references)</sup>

### 실제 환경에서 관찰된 Exploitation

ESET은 RomCom (Storm-0978/UNC2596)이 CVE-2025-8088을 악용하는 RAR archive를 첨부하여 맞춤형 backdoor를 배포하고 ransomware 작업을 지원한 spear-phishing campaign을 보고했습니다.<sup>[[5]](#references)</sup>

## 최신 사례 (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic link**인 ZIP entry가 extraction 중 dereference되어, attacker가 destination directory를 벗어나 임의의 path를 overwrite할 수 있었습니다. User interaction은 archive를 *opening/extracting*하는 것뿐입니다.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** 이전의 7-Zip build. Symbolic-link processing flaw는 **25.00** (2025년 7월) 및 이후 버전에서 수정되었습니다.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` 또는 service-run location을 overwrite → 다음 logon 또는 service restart 시 code 실행.
* **간단한 symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
이 archive에는 extraction directory 외부를 가리키는 symlink entry가 포함됩니다. 일회용 target을 사용하고 extractor가 해당 symlink를 follow하지 않는지 확인해야 합니다. Write-through test에는 symlink 아래의 regular-file entry도 필요합니다.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`는 ZIP symlink를 extract한 다음, 이후 regular member가 동일한 name을 가질 때 이를 dereference할 수 있습니다. 그 결과 겉보기에는 root 내부인 write가 root 외부의 write로 바뀝니다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (현재 project는 deprecated 상태).<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나 link를 reject하고, destination을 opening하기 직전에 매번 다시 resolve합니다.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (그런 다음 `archiver.Unarchive("exploit.zip", "/tmp/safe")` 호출):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

`tarfile.extractall(filter="data")`와 `filter="tar"`도 link-order bypass가 발생한 사례가 있습니다. 이 경우 hardlink가 더 깊은 path에 archive된 symlink를 참조했습니다. Fallback extraction은 해당 deep location의 relative symlink를 검증했지만, 이를 hardlink의 더 얕은 location에 재생성했고, 동일한 relative target이 그 위치에서 escape했습니다. 이는 일반적인 test로 유용합니다. 즉, validation과 materialisation이 base directory 또는 최종 member type에 대해 서로 다른 결과를 내도록 구성합니다.<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – Member name과 link target을 모두 나열합니다. `../`, `..\\`, absolute/rooted path, symlink, hardlink, special file, duplicate name, type change, case/Unicode-equivalent collision을 flag합니다. Exploit이 이전 member에 의존할 수 있으므로 review 중 entry order를 유지해야 합니다.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Resolved parent와 최종 basename을 합친 경로가 resolved destination 아래에 계속 위치하는지 확인합니다(원시 string prefix가 아니라 path component를 비교). 모든 preceding member 이후 다시 확인해야 합니다. 일회성 `realpath(join(dest, name))` test는 link replacement에 취약하며 아직 생성되지 않은 leaf에서는 실패할 수 있습니다.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Path/symlink check를 수행하는 extractor(예: bsdtar의 기본 secure check 또는 7-Zip ≥ 25.00)를 사용해 새로 만든 일회용 directory에 decompress한 후, 결과 tree에 외부를 가리키는 link가 없는지 확인합니다. 이미 발생한 escape가 host path에 도달하지 못하도록 isolation해야 합니다.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Extraction 자체가 외부 file을 생성하지 않았더라도, 남아 있는 symlink 또는 hardlink는 previewer, CDN, file browser 또는 package pipeline이 나중에 extract된 name을 열거나 제공할 때 arbitrary-file-read primitive가 될 수 있습니다.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip 등이 archive를 연 직후 `Startup`/`Run`/`cron` location에 새 executable이 작성되는 경우 alert를 발생시킵니다.

## Mitigation & Hardening

1. **Extractor 업데이트** – WinRAR 7.13+ 및 7-Zip 25.00+에는 인용된 path/symlink issue에 대한 fix가 포함되어 있습니다.<sup>[[1]](#references)[[5]](#references)</sup>
2. 가능한 경우 “**Do not extract paths**” / “**Ignore paths**”를 사용해 archive를 extract합니다. Untrusted input의 경우 application에 명시적으로 필요하지 않다면 symbolic link, hardlink, device 및 FIFO를 reject합니다.<sup>[[9]](#references)[[11]](#references)</sup>
3. **새로운 빈 directory**에 extract합니다. Attacker가 교체할 수 있는 path가 포함된 tree에 untrusted member를 merge하지 말고, 이전 archive가 생성한 directory를 재사용하지 않습니다.<sup>[[11]](#references)</sup>
4. Unix에서는 privilege를 drop하고 destination을 **chroot/mount namespace**에서 isolate합니다. Windows에서는 **AppContainer** 또는 sandbox를 사용합니다. Post-extraction scan만으로는 충분하지 않습니다. escape된 write는 scan 전에 발생하기 때문입니다.<sup>[[11]](#references)</sup>
5. Custom code에서는 target OS의 separator/case/Unicode rule을 적용하고 member와 link target을 모두 validate합니다. Link를 follow하지 않고 destination을 resolve한 뒤 open하며, containment check를 이후의 create/replace operation과 분리하지 않습니다. Validator는 write path와 정확히 동일한 base 및 link-emulation semantics를 사용해야 합니다.<sup>[[11]](#references)[[12]](#references)</sup>

## 추가 영향 / 과거 사례

* 2018 – 다수의 Java/Go/JS library에 영향을 준 Snyk의 대규모 *Zip-Slip* advisory.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377)의 slug 내 TAR extraction traversal (v0.16.3에서 수정).<sup>[[7]](#references)</sup>
* Header string은 validate하지만 link target과 각 write에 사용되는 최종 filesystem path는 validate하지 않는 모든 custom extraction logic.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET에서 Zip Slip 방지](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 지금 WinRAR tools 업데이트: RomCom 및 기타 공격자의 zero-day vulnerability 악용 (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability의 Public Disclosure: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug가 Zip Slip Attack에 취약 (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip에서 CVE-2025-11001의 Proof-of-Concept Exploit 보고](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip, tar-slip, symlink, hardlink, collision 등을 활용한 Hacking 재미](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
