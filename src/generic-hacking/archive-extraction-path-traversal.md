# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Overview

많은 archive 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목에 자체 **internal path**를 포함할 수 있습니다. extraction utility가 해당 경로를 무조건 따를 경우, `..` 또는 **absolute path**(예: `C:\Windows\System32\`)가 포함된 조작된 filename이 사용자가 선택한 directory 외부에 기록됩니다.
이 취약점 유형은 일반적으로 *Zip-Slip* 또는 **archive extraction path traversal**로 알려져 있습니다.<sup>[[6]](#references)</sup>

그 결과는 임의의 파일 덮어쓰기부터, Windows *Startup* folder와 같은 **auto-run** 위치에 payload를 저장하여 직접 **remote code execution (RCE)**을 달성하는 것까지 다양합니다.

## Root Cause

1. Attacker는 하나 이상의 file header에 다음 항목이 포함된 archive를 생성합니다.
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* 또는 target dir 외부로 resolve되는 조작된 **symlinks** (*nix)의 ZIP/TAR에서 흔히 발생).
2. Victim은 embedded path를 신뢰하거나 symlinks를 따르는 취약한 tool을 사용하여 archive를 extract합니다. 이때 path를 sanitise하거나 선택한 directory 아래로 extraction을 강제하지 않습니다.
3. 파일은 attacker가 제어하는 위치에 기록되고, 다음에 system 또는 user가 해당 path를 trigger할 때 실행되거나 load됩니다.

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
- `entry.FullName`이 `..\\`로 시작하면 경로를 순회합니다. **absolute path**인 경우 왼쪽 구성 요소가 완전히 삭제되어, 추출 대상 경로로 **arbitrary file write**가 발생합니다.
- 예약된 scanner가 감시하는 형제 `app` 디렉터리에 기록하는 proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
해당 ZIP을 monitored inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성되어 `C:\samples\queue\` 외부로의 traversal이 가능함이 입증되고, 후속 primitives(예: DLL hijacks)를 사용할 수 있게 됩니다.

## 고급 Archive-Breakout Primitives

Extraction을 서로 독립적인 filename 검사로 보지 말고 filesystem mutation의 연속으로 다뤄야 합니다. 파싱 시에는 안전한 entry라도 이전 member가 link를 생성하거나 교체한 뒤에는 안전하지 않게 될 수 있으며, extractor가 directory를 안전하다고 캐시한 후 그 타입이 변경되는 경우에도 같은 문제가 발생합니다.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp`를 생성한 다음, regular member를 `pivot/PWNED.txt`로 extraction합니다. extractor가 첫 번째 member를 따르고 두 번째 member를 materialise하면, 두 번째 name에 `..`가 없어도 write가 외부로 벗어납니다.
* **Directory-cache/TOCTOU collision**: directory `d/sub/`를 생성하고, `d/sub`를 `/tmp`를 가리키는 symlink로 교체한 다음, `d/sub/PWNED.txt`를 생성합니다. 이는 directory를 한 번만 validate하거나 cache한 뒤 최종 write 전에 다시 확인하지 않는 extractor를 대상으로 합니다.
* **Hardlink read/overwrite**: TAR와 RAR은 hardlink를 표현할 수 있습니다. 기존 host file을 가리키는 hardlink는 이후 component가 extracted name을 제공할 때 해당 파일의 contents를 노출할 수 있으며, 충돌하는 regular entry는 대신 연결된 inode를 overwrite할 수 있습니다. 이는 동일 filesystem 및 OS hardlink-permission 규칙의 제한을 받습니다.
* **Pre-existing or cross-archive pivot**: 비어 있지 않은 destination으로 다시 시도합니다. 각 archive가 stateless header-name check를 통과하더라도, 한 archive가 link를 심고 이후 extraction이 이를 통해 write할 수 있습니다.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

name은 해당 name을 수용할 filesystem의 semantics를 사용하여 비교해야 합니다. 유용한 differential case로는 case-insensitive filesystem에서의 `LINK`와 `link`, NFC와 NFD Unicode 표기, `ﬁle`과 `file`처럼 compatibility-equivalent인 name, path를 directory에서 symlink로 변경하는 duplicate member, Windows에서만 separator로 해석되는 backslash가 있습니다. 또한 NTFS에서 ADS-bearing name도 테스트해야 합니다. 이러한 case에서는 validator가 두 path로 보더라도 filesystem은 하나로 resolve할 수 있습니다.<sup>[[5]](#references)[[11]](#references)</sup>

따라서 compact corpus는 **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, 혼합된 `/` 및 `\`, absolute/rooted name, `.tar.gz`와 같은 compressed wrapper의 ordered combination을 테스트해야 합니다. 이는 disposable VM/container에서만 실행하고 destination과 의도한 외부 canary path를 모두 감시해야 합니다.<sup>[[11]](#references)</sup>

ZIP-specific structural ambiguity로 인해 pre-scan과 실제 extractor가 서로 다른 entry name이나 tree를 관찰할 수 있습니다. 하나의 ZIP library 출력만 신뢰하지 말고 [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion)를 참조하십시오.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR 및 Windows RAR/UnRAR components는 extraction 중 filename을 validate하지 못했습니다. 이 flaw는 NTFS alternate data streams (ADS)를 사용하여 선택된 extraction path를 우회하고 의도하지 않은 location에 file을 write했습니다.<sup>[[5]](#references)</sup>
다음과 같은 entry를 포함하는 malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
는 선택한 출력 디렉터리 **외부**이자 사용자의 *Startup* 폴더 내부에 위치하게 됩니다. ESET은 악성 LNK 파일이 해당 위치에 압축 해제되고 사용자 로그온 시 실행되어 persistence와 RCE 경로를 제공하는 것을 관찰했습니다.<sup>[[5]](#references)</sup>

### PoC Archive 제작 (Linux/Mac)

CVE-2025-8088은 ADS 이름에 traversal path를 사용하므로, purpose-built generator를 사용해 RAR를 생성한 다음 취약한 WinRAR build가 설치된 격리된 lab에서만 extraction을 테스트하십시오.<sup>[[5]](#references)</sup>

### 실제 환경에서 관찰된 Exploitation

ESET은 RomCom (Storm-0978/UNC2596)이 CVE-2025-8088을 악용하는 RAR archive를 첨부하여 맞춤형 backdoor를 배포하고 ransomware operations를 지원한 spear-phishing campaign을 보고했습니다.<sup>[[5]](#references)</sup>

## 최신 사례 (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: extraction 중 **symbolic link**인 ZIP entry가 dereference되어, 공격자가 destination directory를 벗어나 임의의 path를 덮어쓸 수 있었습니다. 사용자의 interaction은 archive를 *열거나 extraction하는 것*뿐입니다.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** 이전의 7-Zip build. symbolic-link processing flaw는 **25.00** (2025년 7월) 및 이후 버전에서 수정되었습니다.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` 또는 service-run location을 덮어씀 → 다음 logon 또는 service restart 시 code가 실행됩니다.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
이 archive에는 extraction directory 외부를 가리키는 symlink entry가 포함되어 있습니다. 일회용 target을 사용하고 extractor가 해당 symlink를 follow하지 않는지 확인하십시오. write-through test에는 symlink 아래에 regular-file entry도 필요합니다.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`는 ZIP symlink를 extraction한 후, 나중에 동일한 이름의 regular member가 나타나면 이를 dereference할 수 있습니다. 그 결과 겉보기에는 root 내부에 대한 write가 실제로는 root 외부에 대한 write가 됩니다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (현재 project는 deprecated 상태).<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나 link를 거부하고 destination을 열기 직전에 매번 다시 resolve하십시오.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (그런 다음 `archiver.Unarchive("exploit.zip", "/tmp/safe")`를 호출):<sup>[[2]](#references)</sup>
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

`tarfile.extractall(filter="data")`와 `filter="tar"`조차 link-order bypass가 발생한 사례가 있습니다. 이 경우 hardlink가 더 깊은 path에 archive된 symlink를 참조했습니다. fallback extraction은 해당 깊은 위치의 relative symlink를 검증했지만, 이를 hardlink의 더 얕은 위치에 재생성했고, 그곳에서는 동일한 relative target이 escape되었습니다. 이는 유용한 일반 테스트입니다. validation과 materialisation이 base directory 또는 최종 member type에 대해 서로 다른 판단을 하도록 만드십시오.<sup>[[12]](#references)</sup>

### Node `tar` symlink chain을 통한 hardlink target escape (GHSA-83g3-92jg-28cx)

Node.js `tar` package의 `tar.extract()`는 lexical하게는 포함된 것처럼 보이지만, 앞선 두 symlink를 통해 extraction root 외부로 resolve되는 target을 가진 hardlink를 허용했습니다. 이 attack은 기본 extraction options에서 동작합니다. destination-parent checks는 hardlink의 root 내부 name만 검사한 반면, hardlink target은 containment를 위해 전체 chain을 resolve하지 않은 채 filesystem에 전달되었습니다. `tar` ≤ 7.5.7이 영향을 받으며, 7.5.8에서 이 issue가 patch되었습니다.<sup>[[13]](#references)</sup>

중요한 test fixture는 이 문자 그대로의 name이 아니라 member 간의 **ordered relationship**입니다.<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
추출이 성공하면 `exfil`은 출력 트리 내부에 눈에 보이는 상태로 남지만 선택한 외부 파일과 inode를 공유합니다. 이를 읽으면 해당 파일이 leak되고, 쓰기 작업을 수행하면 원본이 수정됩니다. 이 우회는 최종 pathname만 확인하거나, absolute prefix를 제거하거나, hardlink header에서 `..`을 차단하는 것만으로는 충분하지 않은 이유를 보여 줍니다. 이전에 추출된 모든 filesystem state를 적용한 후 link target을 검증해야 합니다.<sup>[[13]](#references)</sup>

## Detection Tips

* **Static inspection** – member name과 link target을 모두 나열합니다. `../`, `..\\`, absolute/rooted path, symlink, hardlink, special file, duplicate name, type change, case/Unicode-equivalent collision을 탐지합니다. exploit이 이전 member에 의존할 수 있으므로 검토 중 entry order를 유지해야 합니다.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
7z l -slt suspect.7z          # technical metadata, one field per line
zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
```

* **Canonicalisation** – resolved parent와 final basename을 합친 경로가 resolved destination 아래에 유지되는지 확인합니다(raw string prefix가 아니라 path component를 비교). 모든 preceding member 이후 다시 확인해야 합니다. 한 번만 `realpath(join(dest, name))`을 검사하는 방식은 link replacement에 취약하며 아직 생성되지 않은 leaf에서는 실패할 수 있습니다.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – path/symlink check를 수행하는 extractor(예: bsdtar의 기본 secure check 또는 7-Zip ≥ 25.00)를 사용해 새로 생성된 일회성 directory에 decompress한 다음, 결과 tree에 외부를 가리키는 link가 없는지 확인합니다. 이미 발생한 escape가 host path에 도달하지 못하도록 isolation해야 합니다.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – extraction 자체가 외부 파일을 생성하지 않았더라도, 남아 있는 symlink 또는 hardlink는 previewer, CDN, file browser, package pipeline이 나중에 추출된 name을 열거나 제공할 때 arbitrary-file-read primitive가 될 수 있습니다.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip/etc.로 archive를 연 직후 `Startup`/`Run`/`cron` 위치에 새 executable이 작성되면 alert를 발생시킵니다.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+, 7-Zip 25.00+, Node `tar` 7.5.8+에는 인용된 path/symlink/link-target 문제에 대한 fix가 포함되어 있습니다.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 가능하면 “**Do not extract paths**” / “**Ignore paths**”를 사용해 archive를 extract합니다. 신뢰할 수 없는 input에 대해서는 application이 명시적으로 필요로 하지 않는 한 symbolic link, hardlink, device 및 FIFO를 reject합니다.<sup>[[9]](#references)[[11]](#references)</sup>
3. **새로운 빈 directory**에 extract합니다. attacker가 교체할 수 있는 path가 포함된 tree에 untrusted member를 merge하지 말고, 이전 archive가 생성한 directory를 재사용하지 않습니다.<sup>[[11]](#references)</sup>
4. Unix에서는 privilege를 drop하고 destination을 **chroot/mount namespace**에 isolate합니다. Windows에서는 **AppContainer** 또는 sandbox를 사용합니다. post-extraction scan만으로는 충분하지 않습니다. scan 전에 escaped write가 발생하기 때문입니다.<sup>[[11]](#references)</sup>
5. Custom code에서는 target OS의 separator/case/Unicode rule을 적용하고 member와 link target을 모두 검증합니다. link를 follow하지 않고 destination을 resolve하여 open하며, containment check와 이후 create/replace operation을 분리하지 않습니다. validator는 write path와 정확히 동일한 base 및 link-emulation semantics를 사용해야 합니다.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – 다수의 Java/Go/JS library에 영향을 준 Snyk의 대규모 *Zip-Slip* advisory.<sup>[[6]](#references)</sup>
* 2025 – slug에서 발생한 HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal (v0.16.3에서 fix됨).<sup>[[7]](#references)</sup>
* link target과 각 write에 사용되는 최종 filesystem path는 검증하지 않고 header string만 검증하는 모든 custom extraction logic.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET에서 Zip Slip 방지](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 지금 WinRAR tools를 update하세요: RomCom 및 기타 공격자가 zero-day vulnerability 악용 (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability 공개: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug가 Zip Slip Attack에 취약 (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip의 CVE-2025-11001에 대해 보고된 Proof-of-Concept Exploit](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip, tar-slip, symlink, hardlink, collision 등을 활용한 Hacking fun](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – symlink chain을 통한 node-tar hardlink target escape](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
