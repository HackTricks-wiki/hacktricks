# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**명령줄 도구**는 **zip 파일**을 진단하고, 복구하고, 크랙하는 데 필수적입니다. 주요 유틸리티는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **`unzip`**: zip 파일의 압축이 풀리지 않는 이유를 확인합니다.
- **`zipdetails -v`**: zip 파일 형식 필드를 자세히 분석합니다.<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip 파일의 압축을 풀지 않고 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일의 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP 비밀번호를 대상으로 사전 공격과 무차별 대입 공격을 수행하는 도구입니다. 공격 가능성은 비밀번호 탐색 공간에 따라 달라집니다.<sup>[[15]](#references)</sup>

[Zip 파일 형식 명세](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)에는 zip 파일의 구조와 표준에 관한 포괄적인 세부 정보가 제공됩니다.<sup>[[4]](#references)</sup>

기존의 비밀번호 보호 ZIP 파일은 일반적으로 파일 이름과 크기를 노출합니다. 이는 RAR 및 7z에서 지원하는 헤더 암호화 모드와 다릅니다. ZipCrypto 알려진 평문 공격은 **내부 암호화 키**를 복구하며, 원래 비밀번호를 반드시 복구하는 것은 아닙니다. 이 키만으로도 동일한 비밀번호로 암호화된 항목을 복호화할 수 있습니다.<sup>[[13]](#references)</sup> 이 공격에는 **암호화 전** 스트림의 바이트를 알고 있어야 합니다. 저장된 항목의 경우 원본 파일 바이트가 이에 해당하지만, DEFLATE 항목의 경우 압축된 바이트가 필요하므로 정확히 동일한 압축 출력을 재현해야 할 수 있습니다.<sup>[[13]](#references)[[14]](#references)</sup> 실제 작업 절차는 [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack)을 참조하세요. 암호 해독의 배경은 [논문](https://math.ucr.edu/~mike/zipattacks.pdf)과 [단계별 안내](https://www.hackthissite.org/articles/read/793)를 참조하세요.<sup>[[11]](#references)[[12]](#references)</sup> 이 ZipCrypto 공격은 AES로 암호화된 ZIP 항목에는 적용되지 않습니다.<sup>[[13]](#references)</sup>

---

## 조작된 ZIP 헤더를 이용한 APK의 안티 리버싱 트릭

최신 Android 악성코드 드로퍼는 잘못된 ZIP 메타데이터를 사용해 정적 분석 도구(jadx/apktool/unzip)를 오작동하게 만들면서도, 기기에서 APK를 설치할 수 있도록 합니다. 가장 흔한 트릭은 다음과 같습니다:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF)의 비트 0을 설정해 가짜 암호화 표시
- 대형/사용자 지정 Extra 필드를 악용해 파서 혼란시키기
- 파일/디렉터리 이름 충돌로 실제 아티팩트 숨기기(예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉터리 생성)

### 1) 실제 암호화 없이 가짜 암호화 표시 (GPBF 비트 0 설정)

증상:
- `jadx-gui`에서 다음과 같은 오류가 발생하며 실패합니다:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- 유효한 APK의 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`은 암호화될 수 없는데도, 핵심 APK 파일을 대상으로 `unzip`이 암호를 묻는 경우:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

zipdetails를 사용한 탐지:

```bash
zipdetails -v sample.apk | less
```

로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 항목에서도 bit 0이 설정된(Encryption) 값은 명백한 징후입니다:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

휴리스틱: APK가 기기에 설치되어 실행되지만 도구에서 핵심 항목이 "암호화된" 것으로 표시된다면, GPBF가 변조된 것입니다.

LFH(Local File Header)와 CD(Central Directory) 항목 모두에서 GPBF 비트 0을 지워 해결합니다. 최소 바이트 패처:

<details>
<summary>최소 GPBF 비트 제거 패처</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

사용법:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

비트 0만 변경해야 합니다. 예를 들어 `0A09`는 `0000`이 아니라 `0A08`이 됩니다. 이 최소 패처는 원시 바이트에서 헤더 시그니처를 검색하므로, 파일 데이터 안의 시그니처와 유사한 바이트가 잘못된 일치를 일으킬 수 있습니다. 복사본에서 작업하고, 출력을 사용하기 전에 결과 엔트리 목록과 헤더를 확인하세요.<sup>[[4]](#references)</sup>

### 2) 파서를 깨뜨리는 대형/사용자 지정 Extra 필드

공격자는 디컴파일러를 오작동시키기 위해 헤더에 지나치게 큰 Extra 필드와 특이한 ID를 넣습니다. 실제 환경에서는 그 안에 삽입된 사용자 지정 마커(예: `JADXBLOCK` 같은 문자열)를 볼 수 있습니다.

검사:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

관찰된 예시: 대용량 페이로드가 포함된 알 수 없는 ID(예: `0xCAFE`("Java Executable") 또는 `0x414A`("JA:")).<sup>[[2]](#references)</sup>

DFIR 휴리스틱:
- 핵심 항목(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)의 Extra 필드가 이례적으로 크면 경고합니다.
- 해당 항목에서 알 수 없는 Extra ID가 발견되면 의심스러운 것으로 간주합니다.

실용적인 완화 방법: 아카이브를 다시 빌드하면(예: 추출한 파일을 다시 압축) 악성 Extra 필드가 제거됩니다. 가짜 암호화 때문에 도구가 추출을 거부하면, 먼저 위에서 설명한 대로 GPBF 비트 0을 지운 다음 다시 패키징합니다:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨기기)

ZIP에는 파일 `X`와 디렉터리 `X/`가 모두 포함될 수 있습니다. 일부 압축 해제 도구와 디컴파일러는 혼동을 일으켜 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. `classes.dex`와 같은 핵심 APK 이름과 충돌하는 항목에서 이러한 현상이 관찰되었습니다.

분류 및 안전한 압축 해제:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

수정 후 프로그래밍 방식 탐지:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Blue-team 탐지 아이디어:
- 로컬 헤더에 암호화 표시(GPBF bit 0 = 1)가 있는데도 설치/실행되는 APK를 탐지합니다.
- 핵심 엔트리의 크거나 알 수 없는 Extra fields를 탐지합니다(`JADXBLOCK` 같은 마커를 확인).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`의 경로 충돌(`X`와 `X/`)을 탐지합니다.

---

## 기타 악성 ZIP 트릭 (2024–2026)

### 연결된 central directory (multi-EOCD 우회)

2024년 피싱 캠페인에서 공격자들은 실제로 **두 개의 ZIP 파일을 연결한** 단일 blob을 배포했습니다. 각 파일에는 자체 End of Central Directory(EOCD) 레코드와 central directory가 있었습니다. 추출 도구마다 서로 다른 디렉터리를 파싱했으며(7-Zip은 첫 번째, WinRAR는 마지막 디렉터리를 읽음), 이를 통해 공격자들은 일부 도구에서만 표시되는 payload를 숨길 수 있었습니다. 하나의 디렉터리만 검사하는 스캐너는 다른 아카이브를 놓칠 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

**초기 분석 명령**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

EOCD가 둘 이상 나타나거나 "payload 이후 데이터" 경고가 있으면 blob을 분할하고 각 부분을 검사하세요:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs는 작은 **kernel**(고도로 압축된 DEFLATE 블록)을 만들고, 겹치는 엔트리에서 이를 재사용합니다. Full-overlap 변형은 여러 central-directory 엔트리가 하나의 local header를 가리키게 하고, quoted-overlap 변형은 DEFLATE 스트림 안에 local header를 인용합니다. 공개된 구성 방식은 중첩 아카이브 없이 28M:1을 초과하는 압축률을 달성합니다.<sup>[[7]](#references)</sup>

**빠른 탐지 (중복 LFH 오프셋)**

```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**처리**
- 드라이런으로 확인합니다: `zipdetails -v file.zip | grep -n "Local Header Offset"`를 실행하고, 참조된 로컬 헤더 오프셋과 압축 데이터 범위를 비교합니다. 오프셋이 중복되면 완전 중첩 변형일 가능성이 있습니다.<sup>[[7]](#references)[[8]](#references)</sup>
- 추출 전에 파서를 사용해 허용할 총 압축 해제 크기와 항목 수를 제한합니다. `zipinfo -t file.zip`은 총계를 보고하지만 안전 한도를 강제하지는 않습니다.<sup>[[8]](#references)</sup>
- 추출이 꼭 필요하다면 CPU 및 디스크 제한이 설정된 cgroup/VM 안에서 실행합니다(무제한 압축 해제로 인한 충돌 방지).<sup>[[8]](#references)</sup>

---

### 로컬 헤더와 중앙 디렉터리 간 파서 혼동

최근 차등 파서 연구에 따르면 ZIP 모호성은 여전히 최신 도구 체인에서도 악용될 수 있습니다. 핵심은 간단합니다. 일부 소프트웨어는 **Local File Header (LFH)**를 신뢰하고, 다른 소프트웨어는 **Central Directory (CD)**를 신뢰합니다. 따라서 하나의 아카이브가 도구마다 서로 다른 파일 이름, 경로, 주석, 오프셋 또는 항목 집합을 보여줄 수 있습니다.<sup>[[9]](#references)</sup>

실제 공격 활용:
- 업로드 필터, AV 사전 검사 또는 패키지 검증기가 CD에서 무해한 파일을 보게 하고, 추출기는 다른 LFH 이름/경로를 따르게 합니다.
- 중복 이름, 한 구조에만 있는 항목 또는 모호한 유니코드 경로 메타데이터(예: Info-ZIP Unicode Path Extra Field `0x7075`)를 악용해 파서마다 서로 다른 트리를 재구성하게 합니다.
- 이를 경로 순회와 결합해 "무해해 보이는" 아카이브가 추출 중 파일 쓰기 권한으로 이어지게 합니다. 추출 관련 내용은 [아카이브 추출 경로 순회](../../../generic-hacking/archive-extraction-path-traversal.md)를 참고하세요.

DFIR 초기 분류:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

다음으로 보완하세요:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

휴리스틱:
- 보안에 민감한 수집 작업에서는 LFH/CD 이름이 일치하지 않거나, 중복 파일명이 있거나, EOCD 레코드가 여러 개 있거나, 마지막 EOCD 뒤에 바이트가 있는 아카이브를 거부하거나 격리하세요.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIP에서 비정상적인 Unicode 경로 extra field를 사용하거나 주석이 일관되지 않고, 도구마다 추출된 트리 결과가 다르면 의심스러운 것으로 취급하세요.<sup>[[4]](#references)[[9]](#references)</sup>
- 원본 바이트 보존보다 분석이 중요하다면, 샌드박스에서 추출한 뒤 엄격한 parser로 아카이브를 재패키징하고 결과 파일 목록을 원본 메타데이터와 비교하세요.

이 문제는 패키지 생태계를 넘어 중요합니다. 같은 모호성 유형은 메일 게이트웨이, 정적 스캐너, 그리고 아카이브를 처리할 다른 extractor가 오기 전에 ZIP 콘텐츠를 "살펴보는" 사용자 지정 수집 파이프라인에서 페이로드를 숨길 수 있습니다.<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF 포렌식 현장 가이드 (Mike's Blog, CTF 카테고리)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – 다단계 dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress 스크립트)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP 파일 형식 사양 (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [ZIP 아카이브의 유연한 구조를 악용해 탐지되지 않도록 malware 숨기기 (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [해커들이 새로운 ZIP 파일 공격에 malware를 숨기다 — 연결된 ZIP central directory](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [더 나은 zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip Bomb 이해하기: 겹침/인용된 겹침 커널 구성](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [내 ZIP은 네 ZIP과 다르다: ZIP parser 간 의미적 차이 식별 및 악용 (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python 패키지 설치 프로그램의 ZIP parser 혼동 공격 방지](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [알려진 평문을 줄인 ZIP 공격 (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: 현실적인 웹 미션, 레벨 15 (알려진 평문 ZIP 공격)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack 사용법](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack 알려진 평문 튜토리얼](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip 저장소](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
