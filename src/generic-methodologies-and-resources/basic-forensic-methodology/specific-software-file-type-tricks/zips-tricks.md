# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools**은 zip files 관리를 위해 필수적이며 zip files의 진단, 복구, 크래킹에 중요합니다. 다음은 주요 유틸리티입니다:

- **`unzip`**: zip files가 압축 해제되지 않는 이유를 보여줍니다.
- **`zipdetails -v`**: zip file format 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 추출하지 않고 zip files의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip files 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip 비밀번호를 브루트포스로 크랙하는 도구로, 대략 7자 내외의 비밀번호에 효과적입니다.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)은 zip files의 구조와 표준에 대한 종합적인 세부 정보를 제공합니다.

암호로 보호된 zip files는 내부의 파일 이름이나 파일 크기를 암호화하지 않는다는 점에 유의해야 합니다(이 점은 RAR나 7z 파일과 달리 해당 정보를 암호화하지 않는 보안 결함입니다). 또한, 오래된 ZipCrypto 방식으로 암호화된 zip files는 압축된 파일의 암호화되지 않은 복사본이 존재할 경우 **plaintext attack**에 취약합니다. 이 공격은 알려진 내용을 이용해 zip의 비밀번호를 크랙하는 방식이며, 이 취약점은 [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)와 [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 자세히 설명되어 있습니다. 반면, **AES-256**로 보호된 zip files는 이 plaintext attack에 면역이므로 민감한 데이터에는 안전한 암호화 방식을 선택하는 것이 중요합니다.

---

## APKs에서 조작된 ZIP headers를 사용한 안티리버싱 트릭

현대의 Android malware droppers는 잘못된 ZIP metadata를 사용해 static tools (jadx/apktool/unzip)을 깨뜨리면서도 APK를 기기에서 설치 가능하게 유지합니다. 가장 흔한 트릭은 다음과 같습니다:

- ZIP General Purpose Bit Flag (GPBF) 비트 0을 설정해 가짜 암호화 표시
- 파서를 혼동시키기 위한 큰/커스텀 Extra 필드 남용
- 실제 아티팩트를 숨기기 위한 파일/디렉터리 이름 충돌(예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉터리 생성)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

증상:
- `jadx-gui`가 다음과 같은 오류로 실패함:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`이 핵심 APK 파일들에 대해 비밀번호를 요청하지만, 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`을 암호화할 수 없습니다:

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
local 및 central 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 항목(core entries)에서도 특징적인 값은 비트 0(Encryption)이 설정된 것입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 기기에 설치되어 실행되지만 핵심 항목들이 도구에 의해 "encrypted"로 보인다면 GPBF가 변조된 것입니다.

해결: Local File Headers (LFH)와 Central Directory (CD) 항목 양쪽에서 GPBF의 bit 0을 클리어하세요. Minimal byte-patcher:
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
이제 핵심 엔트리에서 `General Purpose Flag  0000`이 표시되고 도구들이 APK를 다시 파싱할 것입니다.

### 2) 파서를 무력화하기 위한 대형/커스텀 Extra 필드

공격자들은 디컴파일러를 혼란시키기 위해 헤더에 과도한 크기의 Extra 필드와 이상한 ID들을 넣습니다. 실전에서는 (예: `JADXBLOCK`과 같은 문자열) 그런 커스텀 마커가 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예: `0xCAFE`("Java 실행 파일") 또는 `0x414A`("JA:") 같은 알 수 없는 ID가 대용량 페이로드를 포함하는 경우.

DFIR 휴리스틱:
- core 항목(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)에서 Extra 필드가 비정상적으로 클 때 경고.
- 해당 항목들에서 알 수 없는 Extra ID는 의심스러운 것으로 간주.

실무적 완화: 아카이브를 재구성(예: 추출된 파일을 다시 zip으로 압축)하면 악성 Extra 필드가 제거됩니다. 도구가 가짜 암호화 때문에 추출을 거부하면, 위에서 설명한 대로 먼저 GPBF bit 0을 지운 다음 재패키지하세요:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨김)

ZIP 파일은 파일 `X`와 디렉터리 `X/`를 동시에 포함할 수 있다. 일부 extractors와 decompilers는 혼동되어 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있다. 이는 `classes.dex`와 같은 핵심 APK 이름과 충돌하는 항목에서 관찰되었다.

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
프로그램적 탐지 접미사:
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
- APK의 local headers가 암호화로 표시되나 (GPBF bit 0 = 1) 설치/실행되는 경우 탐지.
- 핵심 엔트리의 크거나 알려지지 않은 Extra 필드(예: `JADXBLOCK` 같은 마커)를 탐지.
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 경로 충돌(`X` 및 `X/`)을 탐지.

---

## 참고자료

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
