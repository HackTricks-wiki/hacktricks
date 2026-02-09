# ZIP 트릭

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** 는 **zip 파일** 관리를 위해 필수적이며 zip 파일 진단, 복구, 크래킹에 중요합니다. 주요 유틸리티는 다음과 같습니다:

- **`unzip`**: zip 파일이 왜 압축 해제되지 않는지 원인을 보여줍니다.
- **`zipdetails -v`**: zip 파일 포맷 필드에 대한 상세 분석을 제공합니다.
- **`zipinfo`**: 압축을 풀지 않고 zip 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip 비밀번호를 브루트포스로 크랙하는 도구로, 대략 7자 내외의 비밀번호에 효과적입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) 은 zip 파일의 구조와 표준에 대한 포괄적인 세부사항을 제공합니다.

비밀번호로 보호된 zip 파일은 내부의 파일명이나 파일 크기를 **암호화하지 않는다는 점**(파일명/크기 노출)은 RAR이나 7z와는 다른 보안 결함입니다. 또한 오래된 ZipCrypto 방식으로 암호화된 zip 파일은, 압축된 파일의 비암호화된 복사본이 존재할 경우 **plaintext attack**에 취약합니다. 이 공격은 알려진 내용을 이용해 zip의 비밀번호를 알아내는 기법이며, [HackThis의 기사](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)와 [해당 학술 논문](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 자세히 설명되어 있습니다. 반면 **AES-256**으로 보호된 zip 파일은 이 plaintext attack에 대해 면역이므로, 민감한 데이터에는 안전한 암호화 방식을 선택하는 것이 중요합니다.

---

## APKs에서 조작된 ZIP headers를 사용한 안티-리버싱 트릭

Modern Android malware droppers는 잘못된 ZIP 메타데이터를 사용해 static 도구들(jadx/apktool/unzip)을 깨뜨리면서도 APK는 기기에서 설치 가능하게 유지합니다. 가장 흔한 트릭들은 다음과 같습니다:

- ZIP General Purpose Bit Flag (GPBF) 비트 0을 설정해 가짜 암호화 표시
- 파서들을 혼란시키기 위해 큰/커스텀 Extra 필드 남용
- 실제 아티팩트를 숨기기 위한 파일/디렉토리 이름 충돌 (예: 실제 `classes.dex` 옆에 `classes.dex/`라는 디렉토리)

### 1) Fake encryption (GPBF bit 0 set) — 실제 암호화 없음

증상:
- `jadx-gui`가 다음과 같은 오류로 실패함:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`이 핵심 APK 파일들에 대해 비밀번호를 묻는데, 유효한 APK는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`이 암호화되어 있을 수 없습니다:

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
로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 단서가 되는 값은 코어 항목에서도 비트 0이 설정되어 있는 것(Encryption)입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
휴리스틱: APK가 장치에서 설치되어 실행되지만 핵심 항목들이 도구상에서 "암호화된" 것으로 보인다면, GPBF가 변조된 것입니다.

해결: Local File Headers (LFH)와 Central Directory (CD) 항목 모두에서 GPBF 비트 0을 클리어하세요. 최소 바이트 패처:

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
You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) 파서를 깨뜨리기 위한 대형/커스텀 Extra 필드

공격자는 디컴파일러를 속이기 위해 헤더에 과도한 크기의 Extra 필드와 이상한 ID를 집어넣습니다. 실제 환경에서는 `JADXBLOCK` 같은 문자열과 같은 커스텀 마커가 그곳에 삽입된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예시: `0xCAFE` ("Java 실행 파일") 또는 `0x414A` ("JA:") 같은 알려지지 않은 ID가 큰 페이로드를 담고 있음.

DFIR 휴리스틱:
- 핵심 엔트리(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)의 Extra fields가 비정상적으로 큰 경우 경고.
- 해당 엔트리의 알려지지 않은 Extra ID를 의심스러운 것으로 처리.

실용적인 완화 방법: 아카이브를 재구성(예: 추출한 파일을 다시 zip)하면 악성 Extra fields가 제거됩니다. 도구가 가짜 암호화 때문에 추출을 거부하면, 먼저 위와 같이 GPBF bit 0을 클리어한 뒤 재패키징하세요:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 아티팩트 숨기기)

ZIP은 파일 `X`와 디렉터리 `X/`를 동시에 포함할 수 있습니다. 일부 extractors 및 decompilers는 혼동되어 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. 이는 `classes.dex`와 같은 핵심 APK 이름과 충돌하는 항목에서 관찰되었습니다.

트리아지 및 안전한 추출:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
프로그램 기반 탐지 후처리:
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
블루팀 탐지 아이디어:
- 로컬 헤더가 암호화를 표시(GPBF bit 0 = 1)하지만 실제로 설치/실행되는 APK를 플래그.
- 핵심 엔트리(core entries)의 큰/알 수 없는 Extra fields를 플래그(예: `JADXBLOCK` 같은 마커 확인).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 `X`와 `X/` 같은 경로 충돌(path-collisions)을 플래그.

---

## Other malicious ZIP tricks (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

최근 피싱 캠페인에서는 하나의 blob이 사실상 **두 개의 ZIP 파일이 연결된 것**으로 배포됩니다. 각 파일은 자체 End of Central Directory (EOCD) + central directory를 포함합니다. 서로 다른 압축 해제기는 서로 다른 디렉터리를 파싱합니다(7zip은 첫 번째를 읽고, WinRAR은 마지막을 읽음). 이로 인해 공격자는 일부 도구에서만 보이는 페이로드를 숨길 수 있습니다. 또한 이는 첫 번째 디렉터리만 검사하는 기본 메일 게이트웨이 AV를 우회합니다.

**트리아지 명령**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
EOCD가 둘 이상 나타나거나 "data after payload" 경고가 있는 경우, blob을 분할해 각 부분을 검사하세요:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

최신 "better zip bomb"은 작은 **커널**(고도로 압축된 DEFLATE block)을 만들고 overlapping local headers를 통해 재사용합니다. 모든 central directory entry가 동일한 압축 데이터를 가리키도록 만들어, 아카이브를 중첩하지 않고도 >28M:1 비율을 달성합니다. central directory sizes를 신뢰하는 라이브러리들(예: Python `zipfile`, Java `java.util.zip`, hardened 빌드 이전의 Info-ZIP)은 페타바이트 단위의 메모리를 할당하도록 강제될 수 있습니다.

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
- 사전 검사(dry-run)를 수행하세요: `zipdetails -v file.zip | grep -n "Rel Off"` 그리고 오프셋이 엄격히 증가하며 고유한지 확인하세요.
- 추출 전에 허용되는 총 압축 해제 크기와 항목 수를 제한하세요 (`zipdetails -t` 또는 커스텀 파서 사용).
- 반드시 추출해야 할 경우, CPU 및 디스크 제한이 설정된 cgroup/VM 내에서 실행하세요 (무제한 팽창으로 인한 충돌 방지).

---

## 참고

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
