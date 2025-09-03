# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**명령줄 도구**는 **zip files** 관리를 위해 필수적이며 zip 파일 진단, 복구, 크래킹에 유용합니다. 주요 유틸리티는 다음과 같습니다:

- **`unzip`**: zip 파일이 왜 압축 해제되지 않는지 원인을 보여줍니다.
- **`zipdetails -v`**: zip 파일 포맷 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 파일을 추출하지 않고 zip 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 약 7자 이하 비밀번호에 대해 효과적인 zip 비밀번호 브루트포스 도구입니다.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

암호로 보호된 zip 파일은 내부의 파일명이나 파일 크기를 암호화하지 않는다는 점을 주의해야 합니다. 이는 RAR나 7z와 달리 해당 정보를 암호화하지 않는 보안 결함입니다. 또한 오래된 ZipCrypto 방식으로 암호화된 zip은 압축되지 않은 파일의 복사본이 존재할 경우 **plaintext attack**에 취약합니다. 이 공격은 알려진 내용을 활용해 zip 비밀번호를 크랙하는 방법이며, [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)와 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 자세히 설명되어 있습니다. 반면 **AES-256**으로 보호된 zip 파일은 이 plaintext attack에 대해 면역이므로 민감한 데이터에는 안전한 암호화 방법을 선택하는 것이 중요합니다.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers use malformed ZIP metadata to break static tools (jadx/apktool/unzip) while keeping the APK installable on-device. The most common tricks are:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

증상:
- `jadx-gui`가 다음과 같은 오류를 내며 실패함:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`이 핵심 APK 파일들에 대해 비밀번호를 묻지만, 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`이 암호화될 수 없으므로 비정상적임:

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
로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 항목(core entries)에서도 비트 0이 설정되어 있는 값(Encryption)이 눈에 띕니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 기기에 설치되어 실행되지만 핵심 엔트리가 도구에서 "암호화된" 것으로 보인다면 GPBF가 변조된 것입니다.

해결: Local File Headers (LFH)와 Central Directory (CD) 엔트리 둘 다에서 GPBF 비트 0을 클리어하세요. 최소 바이트 패처:
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
You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) 파서를 깨뜨리기 위한 Large/custom Extra fields

공격자들은 헤더에 과도하게 큰 Extra fields와 특이한 ID를 집어넣어 decompilers를 혼란스럽게 만듭니다. 실제 사례에서는 `JADXBLOCK` 같은 문자열 형식의 커스텀 마커가 그곳에 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예: `0xCAFE` ("Java Executable") 또는 `0x414A` ("JA:") 같은 알려지지 않은 ID가 큰 페이로드를 포함하고 있음.

DFIR 휴리스틱:
- 핵심 항목의 Extra 필드(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)가 비정상적으로 클 경우 경고.
- 해당 항목들에서 알려지지 않은 Extra ID를 의심스럽게 간주.

실제 완화: 아카이브를 재구성(예: 추출한 파일을 다시 zip으로 묶음)하면 악성 Extra 필드를 제거할 수 있습니다. 도구가 가짜 암호화로 인해 추출을 거부하면, 먼저 위와 같이 GPBF bit 0을 클리어한 다음 다시 패키징하세요:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨김)

A ZIP은 파일 `X`와 디렉터리 `X/`를 동시에 포함할 수 있습니다. 일부 추출기나 디컴파일러는 혼동되어 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. 이는 `classes.dex`와 같은 핵심 APK 이름과 항목이 충돌할 때 관찰되었습니다.

Triage 및 안전한 추출:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
프로그래밍 방식 탐지 접미사:
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
- 로컬 헤더가 암호화로 표시(GPBF bit 0 = 1)되었으나 설치/실행되는 APK 탐지.
- 핵심 엔트리의 크거나 알 수 없는 Extra 필드 탐지(예: `JADXBLOCK` 같은 마커 확인).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 경로 충돌(`X` 및 `X/`) 탐지.

---

## 참고

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
