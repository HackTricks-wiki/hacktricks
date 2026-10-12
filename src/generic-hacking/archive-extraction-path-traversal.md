# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## 개요

많은 아카이브 형식(ZIP, RAR, TAR, 7-ZIP 등)은 각 항목에 **내부 경로**를 지정할 수 있습니다. 추출 유틸리티가 해당 경로를 무조건 그대로 따르면, `..` 또는 **절대 경로**(예: `C:\Windows\System32\`)가 포함된 조작된 파일명이 사용자가 선택한 디렉터리 바깥에 기록됩니다.  
이 취약점 유형은 *Zip-Slip* 또는 **아카이브 추출 경로 순회**로 널리 알려져 있습니다.<sup>[[6]](#references)</sup>

결과는 임의 파일 덮어쓰기부터 Windows *Startup* 폴더와 같은 **자동 실행** 위치에 페이로드를 넣어 **원격 코드 실행(RCE)** 을 직접 달성하는 것까지 다양합니다.

## 근본 원인

1. 공격자가 하나 이상의 파일 헤더에 다음 항목이 포함된 아카이브를 만듭니다.
   * 상대 경로 순회 시퀀스 (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * 절대 경로 (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * 또는 대상 디렉터리 바깥을 가리키는 조작된 **심볼릭 링크** (*nix*의 ZIP/TAR에서 흔함). 
2. 피해자가 경로를 정규화하거나 선택한 디렉터리 하위로 추출하도록 강제하는 대신, 포함된 경로를 신뢰하거나 심볼릭 링크를 따라가는 취약한 도구로 아카이브를 추출합니다.
3. 파일이 공격자가 제어하는 위치에 기록되고, 다음에 시스템이나 사용자가 해당 경로를 트리거하면 실행되거나 로드됩니다.

### .NET `Path.Combine` + `ZipArchive` 경로 순회

일반적인 .NET 안티패턴은 의도한 대상 경로와 **사용자 제어** `ZipArchiveEntry.FullName`을 결합한 뒤 경로를 정규화하지 않고 추출하는 것입니다.<sup>[[4]](#references)[[8]](#references)</sup>

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

- `entry.FullName`이 `..\\`로 시작하면 상위 경로로 이동합니다. **절대 경로**인 경우 왼쪽 경로 구성 요소가 완전히 무시되어, 압축 해제 경로를 통해 **임의 파일 쓰기**가 가능합니다.
- 예약된 스캐너가 감시하는 형제 `app` 디렉터리에 파일을 쓰는 PoC archive:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

해당 ZIP을 모니터링되는 inbox에 넣으면 `C:\samples\app\0xdf.txt`가 생성됩니다. 이는 `C:\samples\queue\` 밖으로 경로 순회가 발생했음을 입증하며, 후속 공격 기법(예: DLL hijack)을 가능하게 합니다.

### 사용자 제어 추출 루트

아카이브 멤버 이름뿐 아니라 **extractor에 전달되는 디렉터리**도 테스트하세요. 애플리케이션은 제목, 프로젝트 이름 또는 다른 요청 필드에서 해당 디렉터리를 가져올 수 있습니다. `../../../../app/module`과 같은 값은 extractor가 멤버를 처리하기 전에 추출 루트를 업로드 영역 밖으로 이동시킬 수 있습니다. 이 경우 `api.py`라는 안전한 basename만 포함한 아카이브로도 애플리케이션 코드를 덮어쓸 수 있습니다.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

이는 기존 Zip-Slip과는 별개의 격리 경계입니다. 확인된 압축 해제 루트와 확인된 모든 멤버 경로를 검증하세요. 루트 검증에는 문자열 접두사가 아닌 경로 구성 요소를 사용할 수 있습니다:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

안전한 테스트를 위해 canary 파일 하나가 들어 있는 유효한 아카이브를 업로드하고, 추출 디렉터리를 선택할 수 있는 각 필드에 경로 탐색 시퀀스를 넣으세요. 지정된 디렉터리와 임시로 사용할 외부 경로를 모두 모니터링하세요. 대상 경로에서 가져온 모듈에 접근할 수 있다면, 해당 모듈을 덮어쓰는 것이 worker가 reload될 때 코드 실행으로 이어질 수 있습니다. reload 중 발생한 HTTP 500 오류나 연결 재설정만으로는 쓰기가 실패했다고 단정할 수 없습니다.<sup>[[14]](#references)[[15]](#references)</sup> 더 폭넓은 [파일 업로드 방법론](../pentesting-web/file-upload/)도 참고하세요.

## 고급 아카이브 탈출 기법

추출을 독립적인 파일 이름 검사들의 집합이 아니라, 파일시스템 변경이 순차적으로 일어나는 과정으로 다루세요. 파싱 시점에는 안전한 항목도 이전 멤버가 링크를 만들거나 대체한 뒤에는 안전하지 않을 수 있습니다. 추출기가 디렉터리를 안전하다고 캐시한 뒤 그 유형이 변경되는 경우에도 같은 문제가 발생합니다.<sup>[[11]](#references)</sup>

### 링크 피벗 및 항목 충돌

* **Symlink를 통한 쓰기**: `pivot -> /tmp`를 만든 다음 일반 멤버를 `pivot/PWNED.txt`로 추출합니다. 두 번째 멤버를 생성할 때 추출기가 첫 번째 멤버를 따라가면, 두 번째 이름에 `..`이 없어도 쓰기가 지정된 경로를 벗어납니다.
* **디렉터리 캐시/TOCTOU 충돌**: 디렉터리 `d/sub/`를 추가하고, `d/sub`를 `/tmp`를 가리키는 symlink로 대체한 다음, `d/sub/PWNED.txt`를 추가합니다. 이는 디렉터리를 한 번만 검증하거나 캐시하고 최종 쓰기 전에 다시 확인하지 않는 추출기를 대상으로 합니다.
* **Hardlink 읽기/덮어쓰기**: TAR와 RAR은 hardlink를 표현할 수 있습니다. 기존 호스트 파일을 가리키는 hardlink는 추출된 이름을 나중에 제공하는 구성 요소가 있다면 파일 내용을 노출할 수 있습니다. 충돌하는 일반 항목은 대신 링크된 inode를 덮어쓸 수 있습니다. 이는 동일한 파일시스템 및 OS의 hardlink 권한 규칙에 따라 제한됩니다.
* **기존 또는 아카이브 간 피벗**: 비어 있지 않은 대상 경로로 다시 시도하세요. 각 아카이브가 상태를 유지하지 않는 헤더 이름 검사를 통과하더라도, 한 아카이브가 링크를 심고 나중에 추출하는 아카이브가 이를 통해 파일을 쓸 수 있습니다.<sup>[[11]](#references)</sup>

### 파일시스템 동등성 충돌

파일을 저장할 파일시스템의 규칙에 따라 이름을 비교하세요. 대소문자를 구분하지 않는 파일시스템에서 `LINK`와 `link` 비교, NFC와 NFD 유니코드 표기 비교, `ﬁle`과 `file`처럼 호환상 동일한 이름 비교, 중복 멤버로 경로가 디렉터리에서 symlink로 바뀌는 경우, Windows에서만 구분자로 해석되는 백슬래시 등이 유용한 차등 테스트 사례입니다. NTFS에서는 ADS가 포함된 이름도 테스트하세요. 이러한 사례에서는 검증기가 두 경로를 본다고 판단하지만 파일시스템은 하나의 경로로 처리할 수 있습니다.<sup>[[5]](#references)[[11]](#references)</sup>

따라서 소규모 테스트 코퍼스에는 **directory → symlink → child**, **symlink → 충돌하는 일반 파일**, **hardlink → 충돌하는 일반 파일**, `/`와 `\` 혼합, 절대/루트 기준 이름, `.tar.gz` 같은 압축 래퍼의 순서 조합을 포함해야 합니다. 폐기 가능한 VM/container에서만 실행하고 대상 경로와 지정된 외부 canary 경로를 모두 확인하세요.<sup>[[11]](#references)</sup>

ZIP의 구조적 모호성으로 인해 사전 검사와 실제 추출기가 서로 다른 항목 이름이나 트리를 인식할 수 있습니다. ZIP 라이브러리 하나의 출력만 신뢰하지 말고 [로컬 헤더와 중앙 디렉터리 간 파서 혼동](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion)을 참고하세요.

## 실제 사례 – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows용 WinRAR 및 Windows RAR/UnRAR 구성 요소는 추출 중 파일 이름을 검증하지 못했습니다. 이 취약점은 NTFS 대체 데이터 스트림(ADS)을 이용해 선택된 추출 경로를 우회하고 의도하지 않은 위치에 파일을 썼습니다.<sup>[[5]](#references)</sup>
악성 RAR 아카이브에는 다음과 같은 항목이 포함되어 있습니다:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

선택한 출력 디렉터리 **외부**이자 사용자의 *Startup* 폴더 안에 놓이게 됩니다. ESET은 악성 LNK 파일이 해당 위치에 압축 해제된 뒤 사용자 로그인 시 실행되어 지속성과 RCE 경로를 제공하는 사례를 관찰했습니다.<sup>[[5]](#references)</sup>

### PoC Archive 만들기 (Linux/Mac)

CVE-2025-8088은 ADS 이름에 traversal 경로를 사용하므로, 전용 생성기를 사용해 RAR을 만든 다음 취약한 WinRAR 빌드가 설치된 격리된 실험 환경에서만 압축 해제를 테스트하세요.<sup>[[5]](#references)</sup>

### 실제 공격에서 관찰된 악용 사례

ESET은 RomCom (Storm-0978/UNC2596)이 CVE-2025-8088을 악용하는 RAR 아카이브를 첨부해 맞춤형 백도어를 배포하고 ransomware 작업을 지원한 spear-phishing 캠페인을 보고했습니다.<sup>[[5]](#references)</sup>

## 최신 사례 (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **취약점**: 압축 해제 중 **symbolic link**인 ZIP 항목의 링크를 따라가 공격자가 대상 디렉터리를 벗어나 임의의 경로를 덮어쓸 수 있었습니다. 사용자의 작업은 아카이브를 *열거나 압축 해제하는 것*뿐입니다.<sup>[[1]](#references)</sup>
* **영향받는 버전**: **25.00** 이전의 7-Zip 빌드. Symbolic link 처리 결함은 **25.00**(2025년 7월) 및 이후 버전에서 수정되었습니다.<sup>[[1]](#references)[[10]](#references)</sup>
* **영향 경로**: `Start Menu/Programs/Startup` 또는 서비스 실행 위치 덮어쓰기 → 다음 로그인 또는 서비스 재시작 시 코드 실행.
* **간단한 symlink 처리 테스트 파일 (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  이 archive에는 extraction directory 밖을 가리키는 symlink 항목이 포함되어 있습니다. disposable target을 사용하고 extractor가 해당 경로를 따라가지 않는지 확인하세요. write-through 테스트에는 symlink 아래에 regular-file 항목도 필요합니다.

### Go mholt/archiver `Unarchive()` symlink 충돌 (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`는 ZIP symlink를 extract한 뒤, 나중에 같은 이름을 가진 regular member를 처리할 때 해당 symlink를 역참조할 수 있습니다. 그 결과 겉보기에는 in-root write처럼 보이지만 실제로는 out-of-root write가 발생합니다.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (현재 프로젝트는 deprecated 상태).<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0으로 전환하거나, 링크를 거부하고 각 destination을 열기 직전에 다시 resolve하세요.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (이후 `archiver.Unarchive("exploit.zip", "/tmp/safe")` 호출):<sup>[[2]](#references)</sup>
  ```python
  import zipfile

  with zipfile.ZipFile("exploit.zip", "w") as z:
      link = zipfile.ZipInfo("./x")
      link.create_system = 3
      link.external_attr = 0o120777 << 16
      z.writestr(link, "../../../tmp/PWNED")
      z.writestr("./x", b"owned\n")
  ```

### CPython 필터링된 TAR 추출 우회 (CVE-2026-11940)

`tarfile.extractall(filter="data")`와 `filter="tar"`도 링크 순서 우회에 취약했습니다. 이 사례에서는 hardlink가 더 깊은 경로에 아카이브된 symlink를 참조했습니다. fallback extraction은 해당 깊은 위치를 기준으로 상대 symlink를 검증했지만, hardlink의 더 얕은 위치에 symlink를 다시 만들었습니다. 이 위치에서는 동일한 상대 대상이 경로 밖으로 빠져나갈 수 있었습니다. 검증과 실제 파일 생성이 기준 디렉터리나 최종 멤버 유형을 서로 다르게 해석하는지 확인하는 유용한 일반 테스트입니다.<sup>[[12]](#references)</sup>

### Node `tar`의 symlink 체인을 통한 hardlink 대상 경로 이탈 (GHSA-83g3-92jg-28cx)

Node.js `tar` 패키지의 `tar.extract()`는 어휘적으로는 추출 루트 안에 있는 것처럼 보이지만, 앞서 생성된 두 symlink를 따라가면 루트 밖으로 이어지는 대상을 가진 hardlink를 허용했습니다. 이 공격은 기본 추출 옵션에서도 작동합니다. 대상 경로의 상위 디렉터리 검사는 루트 내부의 hardlink 이름만 확인했고, hardlink 대상은 전체 체인의 경로 포함 여부를 확인하지 않은 채 파일 시스템에 전달되었습니다. `tar` ≤ 7.5.7이 영향을 받으며, 7.5.8에서 이 문제가 수정되었습니다.<sup>[[13]](#references)</sup>

중요한 테스트 fixture는 다음과 같은 문자 그대로의 이름이 아니라 멤버 간의 **순서 관계**입니다:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

압축 해제가 성공하면 `exfil`은 출력 트리 안에 보이는 상태로 남지만, 지정된 외부 파일과 inode를 공유합니다. 이를 읽으면 해당 파일이 유출되고, 쓰면 원본이 수정됩니다. 이 우회 기법은 최종 경로명만 확인하거나, 절대 경로 접두사를 제거하거나, hardlink 헤더의 `..`를 차단하는 것만으로는 충분하지 않다는 점을 보여 줍니다. 이전에 압축 해제된 모든 파일 시스템 상태를 적용한 뒤 링크 대상을 검증해야 합니다.<sup>[[13]](#references)</sup>

## 탐지 팁

* **정적 검사** – 모든 멤버 이름과 링크 대상을 나열합니다. `../`, `..\\`, 절대/루트 경로, 심볼릭 링크, hardlink, 특수 파일, 중복 이름, 유형 변경, 대소문자/유니코드상 동일한 이름의 충돌을 탐지합니다. 공격이 앞선 멤버에 의존할 수 있으므로 검토 중 항목 순서를 유지합니다.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Canonicalisation** – 확인된 상위 경로와 최종 파일명이 확인된 대상 디렉터리 아래에 있는지 검증합니다(원시 문자열 접두사가 아닌 경로 구성 요소를 비교). 앞서 처리된 각 멤버 뒤에 다시 확인해야 합니다. 한 번만 `realpath(join(dest, name))`을 검사하면 링크 교체에 취약하고 아직 생성되지 않은 리프 경로에서는 실패할 수 있습니다.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox 추출** – 경로/심볼릭 링크 검사를 수행하는 추출기(예: 기본 보안 검사 기능이 있는 bsdtar 또는 7-Zip ≥ 25.00)를 사용해 새로 만든 임시 디렉터리에 압축을 풀고, 결과 트리에 외부를 가리키는 링크가 없는지 확인합니다. 격리 환경은 이미 발생한 경로 이탈이 호스트 경로에 접근하지 못하게 해야 합니다.<sup>[[1]](#references)[[9]](#references)</sup>
* **후속 읽기도 중요** – 미리보기 도구, CDN, 파일 브라우저 또는 패키지 파이프라인이 나중에 추출된 이름을 열거나 제공하면, 남아 있는 심볼릭 링크나 하드링크가 임의 파일 읽기 공격 수단이 될 수 있습니다. 추출 과정에서 외부 파일이 생성되지 않았더라도 마찬가지입니다.<sup>[[11]](#references)</sup>
* **엔드포인트 모니터링** – WinRAR/7-Zip 등이 아카이브를 연 직후 `Startup`/`Run`/`cron` 위치에 새 실행 파일이 기록되면 경고를 발생시킵니다.

## 완화 및 강화

1. **추출기 업데이트** – WinRAR 7.13+, 7-Zip 25.00+ 및 Node `tar` 7.5.8+에는 인용된 경로/심볼릭 링크/링크 대상 문제에 대한 수정 사항이 포함되어 있습니다.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. 가능하면 아카이브를 추출할 때 “**Do not extract paths**” / “**Ignore paths**”를 사용합니다. 신뢰할 수 없는 입력의 경우, 애플리케이션에서 명시적으로 필요로 하지 않는 한 심볼릭 링크, 하드링크, 디바이스 및 FIFO를 거부합니다.<sup>[[9]](#references)[[11]](#references)</sup>
3. **새 빈 디렉터리**에 추출합니다. 공격자가 교체할 수 있는 경로가 있는 트리에 신뢰할 수 없는 멤버를 병합하지 말고, 이전 아카이브가 만든 디렉터리를 재사용하지 않습니다.<sup>[[11]](#references)</sup>
4. Unix에서는 권한을 낮추고 대상 디렉터리를 **chroot/mount namespace**로 격리합니다. Windows에서는 **AppContainer** 또는 샌드박스를 사용합니다. 추출 후 검사만으로는 충분하지 않습니다. 경로 이탈에 따른 쓰기는 검사 전에 발생하기 때문입니다.<sup>[[11]](#references)</sup>
5. 사용자 지정 코드에서는 대상 OS의 구분자/대소문자/Unicode 규칙을 적용하고 멤버와 링크 대상을 모두 검증합니다. 링크를 따라가지 않고 대상 경로를 확인하고 엽니다. 포함 여부 검사와 이후의 생성/교체 작업을 분리하지 않습니다. 검증기는 쓰기 경로와 정확히 동일한 기준 경로 및 링크 에뮬레이션 규칙을 사용해야 합니다.<sup>[[11]](#references)[[12]](#references)</sup>

## 추가 영향 사례 / 과거 사례

* 2018 – Snyk가 다수의 Java/Go/JS 라이브러리에 영향을 미치는 대규모 *Zip-Slip* 권고를 발표했습니다.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377)의 slug 내 TAR 추출 경로 순회 취약점(v0.16.3에서 수정).<sup>[[7]](#references)</sup>
* 헤더 문자열만 검증하고 링크 대상과 각 쓰기에 사용되는 최종 파일 시스템 경로를 검증하지 않는 모든 사용자 지정 추출 로직.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip 심볼릭 링크 ZIP 경로 순회 (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET에서 Zip Slip 방지](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL 하이재킹 체인](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – 지금 WinRAR 도구를 업데이트하세요: RomCom 등의 제로데이 취약점 악용 (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – 중대한 임의 파일 덮어쓰기 취약점 공개: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug의 Zip Slip 공격 취약점 (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine 메서드](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar 보안 추출 플래그](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip의 CVE-2025-11001 개념 증명 익스플로잇 보고](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip, tar-slip, 심볼릭 링크, 하드링크, 충돌 등을 활용한 해킹](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile 추출 필터 우회](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – 심볼릭 링크 체인을 통한 node-tar 하드링크 대상 경로 이탈](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – 사용자 제어 SCORM 추출 루트](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – 원격 코드 실행으로 이어지는 Frappe LMS의 여러 취약점](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
