# ZIP 관련 트릭

{{#include ../../../banners/hacktricks-training.md}}

**명령줄 도구**는 **ZIP 파일** 관리를 위해 필수적이며 ZIP 파일의 진단, 복구 및 암호 해제에 유용합니다. 주요 유틸리티는 다음과 같습니다:

- **`unzip`**: ZIP 파일이 왜 압축 해제되지 않는지 원인을 보여줍니다.
- **`zipdetails -v`**: ZIP 포맷 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 압축을 풀지 않고 ZIP 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 ZIP 파일을 복구하려 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP 암호를 브루트포스로 해독하는 도구로, 대략 7자 이내의 암호에 효과적입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)은 ZIP 파일의 구조와 표준에 대한 포괄적인 세부정보를 제공합니다.

중요한 점은 암호로 보호된 ZIP 파일이 내부의 파일명이나 파일 크기를 **암호화하지 않는다**는 보안 취약점이 있다는 것입니다. 이는 파일명/크기를 암호화하는 RAR나 7z와는 다른 점입니다. 또한 오래된 ZipCrypto 방식으로 암호화된 ZIP 파일은 압축된 파일의 암호화되지 않은 복사본이 존재하면 **known-plaintext 공격**에 취약합니다. 이 공격은 알려진 내용을 이용해 ZIP의 암호를 깨는 방식이며, HackThis의 기사(링크)와 이 학술 논문(링크)에 자세히 설명되어 있습니다. 그러나 **AES-256**으로 보호된 ZIP 파일은 이 평문 공격에 대해 면역이므로 민감한 데이터에는 강력한 암호화 방식을 선택하는 것이 중요합니다.

---

## APKs에서 조작된 ZIP 헤더를 이용한 안티 리버싱 트릭

최신 Android malware droppers는 잘못된 ZIP 메타데이터를 사용해 jadx/apktool/unzip 같은 정적 분석 도구를 깨뜨리면서도 기기에서 APK를 설치 가능하게 유지합니다. 가장 흔한 트릭은 다음과 같습니다:

- ZIP General Purpose Bit Flag (GPBF) bit 0을 설정해 가짜 암호화 표시
- 파서를 혼동시키기 위한 큰/커스텀 Extra 필드 악용
- 실제 아티팩트를 숨기기 위한 파일/디렉토리 이름 충돌(예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉토리)

### 1) 실제 암호화 없이 GPBF bit 0을 설정한 가짜 암호화

증상:
- `jadx-gui`가 다음과 같은 오류로 실패합니다:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`이 핵심 APK 파일들에 대해 비밀번호를 요구하지만 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`을 암호화할 수 없습니다:

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
로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 엔트리에서도 bit 0이 설정된(Encryption) 값이 특징적입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 기기에서 설치되어 실행되지만 도구에서 핵심 항목이 "encrypted"로 표시된다면 GPBF가 변조된 것입니다.

해결: Local File Headers (LFH)와 Central Directory (CD) 항목 모두에서 GPBF의 bit 0을 클리어하세요. 최소 바이트 패처:

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
사용법:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
이제 코어 엔트리에서 `General Purpose Flag  0000`를 볼 수 있으며 도구들은 APK를 다시 parse할 것입니다.

### 2) 파서를 깨뜨리기 위한 Large/custom Extra fields

공격자들은 헤더에 과도하게 큰 Extra fields와 이상한 IDs를 넣어 decompilers를 교란시킨다. 실전에서는 사용자 정의 마커(예: `JADXBLOCK` 같은 문자열)가 그곳에 포함된 것을 볼 수 있다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예: `0xCAFE`("Java 실행 파일") 또는 `0x414A`("JA:") 같은 알려지지 않은 ID들이 대용량 페이로드를 포함하고 있음.

DFIR 휴리스틱:
- 핵심 항목(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)에서 Extra 필드가 비정상적으로 큰 경우 경고.
- 해당 항목의 알려지지 않은 Extra ID를 의심스럽게 처리.

실용적 완화 조치: 아카이브를 재구성(예: 추출한 파일을 재압축(re-zipping))하면 악성 Extra 필드가 제거됩니다. 도구가 가짜 암호화 때문에 추출을 거부하면, 먼저 위에서처럼 GPBF bit 0을 클리어한 다음 다시 패키징하세요:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨기기)

A ZIP에는 파일 `X`와 디렉터리 `X/`가 모두 포함될 수 있습니다. 일부 추출기 및 디컴파일러는 혼동되어 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. 이는 `classes.dex`와 같은 핵심 APK 이름과 항목이 충돌할 때 관찰되었습니다.

분류 및 안전한 추출:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
프로그램 방식 탐지 후처리:
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
- 로컬 헤더가 암호화를 표시(GPBF bit 0 = 1)하지만 설치/실행되는 APK를 플래그.
- 핵심 엔트리(core entries)의 큰/알 수 없는 Extra 필드 플래그(예: `JADXBLOCK` 같은 마커 검사).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 경로 충돌(`X` 및 `X/`) 플래그.

---

## 기타 악성 ZIP 트릭 (2024–2026)

### 연결된 중앙 디렉터리 (multi-EOCD evasion)

최근 피싱 캠페인에서는 실제로 **두 개의 ZIP 파일이 연결된** 단일 blob을 전송합니다. 각각은 자체 End of Central Directory (EOCD)와 중앙 디렉터리를 가집니다. 서로 다른 압축 해제 도구는 서로 다른 디렉터리를 파싱합니다(7zip은 첫 번째를 읽고, WinRAR은 마지막을 읽음), 따라서 공격자는 일부 도구에서만 보이는 페이로드를 숨길 수 있습니다. 이 방법은 첫 번째 디렉터리만 검사하는 기본 메일 게이트웨이 AV도 우회합니다.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
EOCD가 둘 이상 나타나거나 "data after payload" 경고가 있는 경우, blob을 분할하여 각 부분을 검사하세요:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

최신 "better zip bomb"은 작은 **kernel**(고도로 압축된 DEFLATE 블록)을 생성하고 overlapping local headers를 통해 이를 재사용한다. 각 central directory 항목은 동일한 압축 데이터를 가리키며, 아카이브를 중첩하지 않고도 >28M:1 비율을 달성한다. central directory 크기를 신뢰하는 라이브러리(Python `zipfile`, Java `java.util.zip`, hardened build 이전의 Info-ZIP)는 페타바이트를 할당하도록 강제될 수 있다.

**빠른 탐지 (duplicate LFH offsets)**
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
- 드라이런 검사 수행: `zipdetails -v file.zip | grep -n "Rel Off"` 을 실행하여 오프셋이 엄격하게 증가하며 고유한지 확인합니다.
- 추출 전에 허용되는 총 압축해제된 크기와 엔트리 수를 제한하십시오 (`zipdetails -t` 또는 커스텀 파서 사용).
- 반드시 추출해야 할 경우, CPU 및 디스크 제한이 적용된 cgroup/VM 내부에서 수행하십시오 (무한 확장으로 인한 크래시를 피하십시오).

---

### Local-header vs central-directory 파서 혼동

최근의 differential-parser 연구는 ZIP의 모호성이 최신 툴체인에서도 여전히 악용될 수 있음을 보여줍니다. 핵심 아이디어는 간단합니다: 일부 소프트웨어는 **Local File Header (LFH)** 를 신뢰하는 반면 다른 소프트웨어는 **Central Directory (CD)** 를 신뢰합니다. 따라서 하나의 아카이브가 서로 다른 툴에 대해 서로 다른 파일명, 경로, 코멘트, 오프셋 또는 엔트리 집합을 제시할 수 있습니다.

실제 공격적 활용 예:
- 업로드 필터, AV 프리스캔 또는 패키지 검증기가 CD에서 무해한 파일을 보도록 하면서 추출기는 다른 LFH 이름/경로를 따르도록 만듭니다.
- 중복 이름, 특정 구조에만 존재하는 엔트리, 또는 모호한 Unicode 경로 메타데이터(예: Info-ZIP Unicode Path Extra Field `0x7075`)를 악용해 서로 다른 파서가 서로 다른 트리를 재구성하게 합니다.
- 이를 path traversal과 결합해 '무해한' 아카이브 뷰를 추출 중 write-primitive로 전환할 수 있습니다. 추출 측면은 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)을 참조하세요.

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
원문 파일 내용이 제공되지 않았습니다. 번역할 영어 Markdown 텍스트를 붙여넣어 주시거나, 보완할 구체적 내용을 알려주시면 요청하신 규칙(마크다운/태그 미번역 유지 등)에 따라 한국어로 번역·보완해 드리겠습니다.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
휴리스틱:
- LFH/CD 이름이 일치하지 않거나 파일명이 중복되거나 EOCD 레코드가 여러 개이거나 최종 EOCD 뒤에 트레일링 바이트가 있는 아카이브는 차단하거나 격리하세요.
- 도구마다 추출된 트리가 다를 경우, 특이한 Unicode-path extra fields를 사용하거나 일관성 없는 comments를 가진 ZIPs는 의심스럽게 취급하세요.
- 원본 바이트 보존보다 분석이 더 중요하면, 샌드박스에서 추출한 후 엄격한 파서로 아카이브를 재패키징하고 생성된 파일 목록을 원본 메타데이터와 비교하세요.

이 문제는 패키지 생태계에만 국한되지 않습니다: 동일한 모호성 클래스는 다른 추출기가 아카이브를 처리하기 전에 ZIP 내용을 "peek" 하는 메일 게이트웨이, static scanners, 맞춤형 수집 파이프라인에서 페이로드를 숨길 수 있습니다.

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
