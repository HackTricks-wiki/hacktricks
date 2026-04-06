# ZIPs 트릭

{{#include ../../../banners/hacktricks-training.md}}

**명령줄 도구**로 **zip 파일**을 관리하는 것은 zip 파일의 진단, 복구 및 암호 해독에 필수적입니다. 다음은 주요 유틸리티입니다:

- **`unzip`**: zip 파일이 왜 압축 해제되지 않는지 알려줍니다.
- **`zipdetails -v`**: zip 파일 포맷 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 추출하지 않고 zip 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 약 7자까지의 비밀번호에 대해 효과적인 zip 비밀번호 무차별 대입 도구입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)는 zip 파일의 구조와 표준에 대한 포괄적인 세부 정보를 제공합니다.

비밀번호로 보호된 zip 파일은 내부의 파일명이나 파일 크기를 **암호화하지 않는다**는 점에 유의해야 합니다. 이 취약점은 해당 정보를 암호화하는 RAR 또는 7z 파일과는 다릅니다. 또한 오래된 ZipCrypto 방식으로 암호화된 zip 파일은 압축된 파일의 비암호화된 사본이 존재할 경우 **plaintext attack**에 취약합니다. 이 공격은 알려진 내용을 이용해 zip의 비밀번호를 깨는 방식이며, 이 취약점은 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)과 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 자세히 설명되어 있습니다. 반면 **AES-256**로 보호된 zip 파일은 이 **plaintext attack**에 대해 면역이므로 민감한 데이터에는 강력한 암호화 방식을 선택하는 것이 중요합니다.

---

## 변조된 ZIP 헤더를 사용한 APK의 Anti-reversing 트릭

최신 Android malware droppers는 잘못된 ZIP 메타데이터를 사용하여 jadx/apktool/unzip 같은 정적 도구를 무력화시키면서도 APK는 기기에서 설치 가능하도록 유지합니다. 가장 흔한 트릭은 다음과 같습니다:

- ZIP General Purpose Bit Flag (GPBF)의 bit 0을 설정해 가짜 암호화 표시
- 파서를 혼동시키기 위한 큰/커스텀 Extra 필드 남용
- 실제 아티팩트를 숨기기 위한 파일/디렉터리 이름 충돌(예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉터리)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

증상:
- `jadx-gui`가 다음과 같은 오류로 실패합니다:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`은 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`을 암호화할 수 없음에도 불구하고 핵심 APK 파일에 대해 비밀번호를 묻습니다:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails로 탐지:
```bash
zipdetails -v sample.apk | less
```
로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 항목에서도 bit 0(Encryption)이 설정되어 있는 것이 단서입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 디바이스에 설치되어 실행되지만 핵심 항목들이 도구에서 "암호화된" 것으로 보인다면 GPBF가 변조된 것입니다.

해결: Local File Headers (LFH)와 Central Directory (CD) 항목 모두에서 GPBF의 bit 0을 클리어하십시오. 최소 바이트 패처:

<details>
<summary>최소 GPBF 비트 클리어 패처</summary>
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
이제 핵심 엔트리에서 `General Purpose Flag  0000`이 표시되며 도구들이 APK를 다시 파싱할 것입니다.

### 2) 파서를 깨뜨리기 위한 대형/커스텀 Extra 필드

공격자는 디컴파일러를 오작동시키기 위해 헤더에 과도하게 큰 Extra 필드와 이상한 ID들을 넣습니다. 실전에서는 `JADXBLOCK` 같은 문자열 등 커스텀 마커가 그 안에 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예: 큰 페이로드를 담고 있는 `0xCAFE` ("Java Executable") 또는 `0x414A` ("JA:")와 같은 알 수 없는 ID.

DFIR 휴리스틱:
- 핵심 엔트리(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)에서 Extra 필드가 비정상적으로 클 경우 경보를 발생시킬 것.
- 해당 엔트리의 알 수 없는 Extra ID는 의심스럽게 처리할 것.

실무적 완화: 아카이브를 재구성(예: 추출한 파일을 다시 re-zipping)하면 악성 Extra 필드를 제거할 수 있음. 도구가 가짜 암호화 때문에 추출을 거부하면, 먼저 위와 같이 GPBF bit 0을 클리어한 뒤 다시 패키징할 것:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨기기)

A ZIP에는 파일 `X`와 디렉터리 `X/`가 동시에 포함될 수 있습니다. 일부 추출기와 디컴파일러는 혼동하여 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. 이러한 현상은 `classes.dex`와 같은 핵심 APK 이름과 항목이 충돌할 때 관찰되었습니다.

분석 및 안전한 추출:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
프로그램적 탐지 후 조치:
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
- 로컬 헤더가 암호화로 표시(GPBF bit 0 = 1)되어 있지만 설치/실행되는 APK를 표시.
- 핵심 엔트리(core entries)의 큰/알 수 없는 Extra fields(예: `JADXBLOCK` 같은 마커)를 표시.
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 `X`와 `X/`의 경로 충돌(path-collisions)을 표시.

---

## 기타 악성 ZIP 트릭 (2024–2026)

### Concatenated central directories (multi-EOCD 우회)

최근 피싱 캠페인에서는 단일 blob으로 전송되지만 실제로는 **두 개의 ZIP 파일이 이어붙여진** 경우가 있습니다. 각 파일은 자체 End of Central Directory (EOCD)와 central directory를 갖습니다. 추출기마다 서로 다른 디렉터리를 파싱합니다(7zip은 첫 번째를, WinRAR은 마지막을 읽음), 이로 인해 공격자는 일부 도구에서만 보이는 페이로드를 숨길 수 있습니다. 또한 이는 첫 번째 디렉터리만 검사하는 기본 mail gateway AV를 우회합니다.

**분석 명령**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
만약 EOCD가 여러 개 나타나거나 "data after payload" 경고가 표시되면, blob을 분할하여 각 부분을 검사하세요:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb"은 아주 작은 **kernel**(고도로 압축된 DEFLATE block)을 생성하고 overlapping local headers를 통해 이를 재사용합니다. 모든 central directory entry는 동일한 압축 데이터를 가리켜 아카이브를 중첩하지 않고도 >28M:1 비율을 달성합니다. central directory sizes를 신뢰하는 라이브러리들(Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds)은 페타바이트 단위의 할당을 강제로 발생시킬 수 있습니다.

**빠른 탐지 (중복 LFH 오프셋)**
```python
# detect overlapping entries by identical relative offsets
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
- 사전 점검(dry-run) 수행: `zipdetails -v file.zip | grep -n "Rel Off"` 그리고 오프셋이 엄격히 증가하고 유일한지 확인.
- 추출 전에 허용되는 총 압축 해제된 크기와 엔트리 수를 제한(`zipdetails -t` 또는 커스텀 파서).
- 추출이 반드시 필요한 경우 CPU·디스크 한계가 설정된 cgroup/VM 안에서 수행(무제한 팽창으로 인한 크래시 방지).

---

### Local-header vs central-directory 파서 혼동

최근 differential-parser 연구는 ZIP 모호성이 여전히 최신 툴체인에서 악용 가능함을 보여주었다. 핵심 아이디어는 단순하다: 일부 소프트웨어는 **Local File Header (LFH)** 를 신뢰하는 반면 다른 소프트웨어는 **Central Directory (CD)** 를 신뢰한다. 따라서 하나의 아카이브가 서로 다른 툴에 서로 다른 파일명, 경로, 코멘트, 오프셋 또는 엔트리 집합을 제시할 수 있다.

실전 공격 활용 예:
- 업로드 필터, AV pre-scan, 또는 패키지 검증기가 CD에서 무해한 파일을 보도록 만들고, 추출기는 다른 LFH 이름/경로를 따르게 한다.
- 중복된 이름, 한 구조에만 존재하는 엔트리, 또는 모호한 Unicode 경로 메타데이터(예: Info-ZIP Unicode Path Extra Field `0x7075`)를 악용해 서로 다른 파서가 서로 다른 트리를 재구성하게 한다.
- 이를 path traversal과 결합하면 "harmless" 아카이브 뷰를 추출 중에 write-primitive로 바꿀 수 있다. 추출 측 내용은 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) 참조.

DFIR 트리아지:
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
Heuristics:
- 불일치하는 LFH/CD 이름, 중복된 파일명, 여러 개의 EOCD 레코드, 또는 마지막 EOCD 이후의 추가 바이트가 있는 아카이브는 거부하거나 격리합니다.
- 특이한 Unicode-path extra fields를 사용하거나 주석이 일관되지 않는 ZIP은, 서로 다른 도구들이 추출된 트리에 대해 다르게 해석할 경우 의심스럽게 취급합니다.
- 분석이 원본 바이트 보존보다 더 중요하다면, sandbox에서 추출한 뒤 strict parser로 아카이브를 재패키징하고 결과 파일 목록을 원본 메타데이터와 비교하세요.

이것은 패키지 생태계에 국한되지 않습니다: 같은 모호성 클래스는 다른 extractor가 아카이브를 처리하기 전에 ZIP 내용을 "peek"하는 메일 게이트웨이, 정적 스캐너, 커스텀 수집 파이프라인으로부터 페이로드를 숨길 수 있습니다.

---



## 참고자료

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
