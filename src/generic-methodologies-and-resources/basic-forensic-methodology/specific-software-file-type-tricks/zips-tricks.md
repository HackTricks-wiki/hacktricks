# ZIPs 트릭

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files**는 zip 파일의 진단, 복구 및 크래킹에 필수적입니다. 주요 유틸리티는 다음과 같습니다:

- **`unzip`**: zip 파일이 왜 압축 해제되지 않는지 원인을 보여줍니다.
- **`zipdetails -v`**: zip 파일 포맷 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 파일을 추출하지 않고 zip 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일을 복구하려고 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip 비밀번호를 브루트포스로 크래킹하는 도구로, 대략 7자 내외의 비밀번호에 효과적입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)는 zip 파일의 구조와 표준에 대한 포괄적인 세부 정보를 제공합니다.

중요한 점은 비밀번호로 보호된 zip 파일은 내부의 파일명이나 파일 크기를 암호화하지 않는다는 것입니다. 이는 RAR나 7z가 암호화하는 정보와 달리 zip의 보안 결함입니다. 또한 오래된 ZipCrypto 방식으로 암호화된 zip 파일은 압축된 파일의 비암호화 버전이 존재할 경우 **plaintext attack**에 취약합니다. 이 공격은 알려진 내용을 활용해 zip의 비밀번호를 깨는 방식이며, [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)과 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 자세히 다룹니다. 반면 **AES-256**으로 보호된 zip 파일은 이 plaintext 공격에 면역이므로, 민감한 데이터에는 안전한 암호화 방식을 선택하는 것이 중요합니다.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

최신 Android malware droppers는 잘못된 ZIP 메타데이터를 사용하여 static tools (jadx/apktool/unzip)을 무력화하는 동시에 APK가 기기에서 설치 가능하도록 유지합니다. 가장 흔한 기법은 다음과 같습니다:

- ZIP General Purpose Bit Flag (GPBF) bit 0을 설정해 가짜 암호화 표시
- 파서 혼동을 유발하는 큰/커스텀 Extra fields 남용
- 실제 아티팩트를 숨기기 위한 파일/디렉터리 이름 충돌 (예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉터리)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

증상:
- `jadx-gui`가 다음과 같은 오류로 실패합니다:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`을 암호화할 수 없음에도 불구하고 `unzip`이 핵심 APK 파일들에 대해 비밀번호를 묻습니다:

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
local and central headers의 General Purpose Bit Flag를 확인하세요. core entries조차 bit 0(Encryption)가 설정되어 있으면 전형적인 징후입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 디바이스에 설치되어 실행되지만 핵심 항목들이 도구에 의해 "암호화된" 것으로 보인다면, GPBF가 변조된 것입니다.

해결 방법: Local File Headers (LFH)와 Central Directory (CD) 엔트리 둘 다에서 GPBF 비트 0을 클리어하세요. 최소 byte-patcher:

<details>
<summary>최소 GPBF 비트 클리어 patcher</summary>
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
이제 핵심 항목에서 `General Purpose Flag  0000`를 확인할 수 있으며 도구들이 APK를 다시 파싱합니다.

### 2) 파서를 깨뜨리는 대형/커스텀 Extra 필드

공격자들은 디컴파일러를 혼란시키기 위해 헤더에 과도하게 큰 Extra 필드와 이상한 ID를 삽입합니다. 실전에서는 `JADXBLOCK` 같은 문자열 형태의 커스텀 마커가 그 안에 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예: `0xCAFE` ("Java Executable") 또는 `0x414A` ("JA:") 같은 알 수 없는 ID가 큰 페이로드를 포함하는 사례.

DFIR heuristics:
- core 항목(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)의 Extra 필드가 비정상적으로 큰 경우 경고.
- 해당 항목에서 알 수 없는 Extra ID를 의심스러운 것으로 취급.

실무적 완화: 아카이브를 재구성(예: 추출한 파일을 다시 압축)하면 악성 Extra 필드를 제거할 수 있다. 도구가 가짜 암호화 때문에 추출을 거부하면, 먼저 위와 같이 GPBF bit 0을 클리어한 뒤 재패키징:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨김)

ZIP에는 파일 `X`와 디렉터리 `X/`가 동시에 포함될 수 있습니다. 일부 압축 해제 도구 및 디컴파일러는 혼동하여 디렉터리 엔트리로 실제 파일을 덮어쓰거나 숨길 수 있습니다. 이는 `classes.dex` 같은 핵심 APK 이름과 엔트리가 충돌하는 경우에서 관찰되었습니다.

선별 및 안전한 추출:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
프로그래밍 방식 탐지 사후 처리:
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
- 로컬 헤더가 암호화로 표시되어 있음(GPBF bit 0 = 1)에도 설치/실행되는 APK를 플래그.
- 핵심 엔트리의 큰/알 수 없는 Extra 필드(예: `JADXBLOCK` 같은 마커를 확인)를 플래그.
- 경로 충돌(`X` and `X/`)을 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 특히 플래그.

---

## 기타 악성 ZIP 트릭 (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

최근 phishing 캠페인에서는 단일 블롭을 전송하는데, 실제로는 **두 개의 ZIP 파일이 연결된 것**이다. 각 파일은 자체 End of Central Directory (EOCD) + central directory를 가진다. 서로 다른 extractors가 서로 다른 디렉터리를 파싱한다(7zip은 첫 번째를 읽고, WinRAR은 마지막을 읽음), 공격자는 일부 도구에서만 보이는 payloads를 숨길 수 있다. 이것은 첫 번째 디렉터리만 검사하는 기본적인 mail gateway AV를 우회하기도 한다.

**분류 명령**
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

Modern "better zip bomb" builds a tiny **커널** (highly compressed DEFLATE block) and reuses it via overlapping local headers. Every central directory entry points to the same compressed data, achieving >28M:1 ratios without nesting archives. Libraries that trust central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) can be forced to allocate 페타바이트.

**빠른 탐지 (중복된 LFH 오프셋)**
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
- 드라이런 검사 수행: `zipdetails -v file.zip | grep -n "Rel Off"` 그리고 offsets가 엄격히 증가하고 중복되지 않는지 확인.
- 추출 전에 허용되는 전체 압축 해제된 크기와 항목 수를 제한하십시오 (`zipdetails -t` 또는 사용자 지정 파서).
- 반드시 추출해야 할 경우, CPU+disk 제한이 설정된 cgroup/VM 내부에서 수행하세요 (무제한 팽창으로 인한 충돌 방지).

---

## 참고 자료

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
