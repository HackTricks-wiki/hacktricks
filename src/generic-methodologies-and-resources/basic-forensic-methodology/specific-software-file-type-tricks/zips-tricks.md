# ZIP tricks

{{#include ../../../banners/hacktricks-training.md}}

**ZIP 파일을 관리하기 위한 명령줄 도구**는 ZIP 파일을 진단하고, 복구하고, cracking하는 데 필수적입니다. 주요 유틸리티는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **`unzip`**: ZIP 파일의 압축이 해제되지 않는 이유를 확인합니다.
- **`zipdetails -v`**: ZIP 파일 형식 필드에 대한 상세한 분석을 제공합니다.
- **`zipinfo`**: 압축을 해제하지 않고 ZIP 파일의 내용을 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 ZIP 파일의 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP password를 brute-force cracking하는 도구로, 약 7자 이하의 password에 효과적입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)은 ZIP 파일의 구조와 표준에 관한 포괄적인 세부 정보를 제공합니다.<sup>[[4]](#references)</sup>

password로 보호된 ZIP 파일은 내부의 **파일 이름이나 파일 크기를 암호화하지 않는다**는 점에 유의해야 합니다. 이러한 보안 결함은 이 정보를 암호화하는 RAR 또는 7z 파일에는 존재하지 않습니다. 또한 이전 ZipCrypto 방식으로 암호화된 ZIP 파일은 압축된 파일의 암호화되지 않은 사본을 사용할 수 있는 경우 **plaintext attack**에 취약합니다.<sup>[[1]](#references)</sup> 이 attack은 알려진 콘텐츠를 이용해 ZIP의 password를 cracking하며, [HackThis의 article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)에 이 취약점이 자세히 설명되어 있고 [이 academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)에서 추가로 설명합니다.<sup>[[11]](#references)[[12]](#references)</sup> 그러나 **AES-256** encryption으로 보호된 ZIP 파일은 이 plaintext attack에 면역이므로, 민감한 데이터에 안전한 encryption method를 선택하는 것이 중요하다는 점을 보여줍니다.<sup>[[1]](#references)</sup>

---

## manipulated ZIP headers를 사용하는 APK의 Anti-reversing tricks

최신 Android malware dropper는 잘못된 ZIP metadata를 사용해 static tool(jadx/apktool/unzip)을 중단시키면서도 APK가 device에 설치될 수 있도록 합니다. 가장 일반적인 tricks는 다음과 같습니다:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF)의 bit 0을 설정해 Fake encryption 수행
- 크거나 사용자 지정된 Extra field를 악용해 parser 혼란
- 실제 artifact를 숨기기 위한 file/directory name collision(`classes.dex/`라는 directory를 실제 `classes.dex` 옆에 배치하는 경우 등)

### 1) 실제 crypto 없이 GPBF bit 0을 설정하는 Fake encryption

증상:
- `jadx-gui`가 다음과 같은 error와 함께 실패합니다:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- 유효한 APK에서는 `classes*.dex`, `resources.arsc`, 또는 `AndroidManifest.xml`을 encrypted할 수 없음에도 `unzip`이 핵심 APK 파일의 password를 요청합니다:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails를 사용한 Detection:
```bash
zipdetails -v sample.apk | less
```
local 및 central headers의 General Purpose Bit Flag를 확인하세요. 핵심 entries에서도 bit 0이 설정된(Encryption) 값은 명백한 징후입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: APK가 device에 설치되고 실행되지만 핵심 entries가 tools에서 "encrypted"로 나타난다면, GPBF가 변조된 것입니다.

Local File Headers (LFH)와 Central Directory (CD) entries 모두에서 GPBF bit 0을 clear하여 수정합니다. Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
이제 core entries에 `General Purpose Flag  0000`이 표시되고 tools가 APK를 다시 parse할 수 있습니다.

### 2) parser를 깨뜨리기 위한 대형/custom Extra fields

Attackers는 decompiler를 문제 일으키도록 header에 지나치게 큰 Extra fields와 특이한 ID를 삽입합니다. 실제 환경에서는 여기에 custom marker(예: `JADXBLOCK`과 같은 문자열)가 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예시: `0xCAFE` ("Java Executable") 또는 `0x414A` ("JA:")와 같이 대용량 payload를 포함하는 알 수 없는 ID.

DFIR heuristics:
- 핵심 entries(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)의 Extra fields가 비정상적으로 큰 경우 alert를 발생시킵니다.
- 해당 entries에서 알 수 없는 Extra IDs를 suspicious한 것으로 간주합니다.

실용적인 mitigation: archive를 다시 빌드하면(예: 추출한 files를 다시 zipping) malicious Extra fields가 제거됩니다. fake encryption으로 인해 tools가 extract를 거부하는 경우, 먼저 위와 같이 GPBF bit 0을 clear한 다음 repackage합니다:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 artifact 숨기기)

ZIP에는 파일 `X`와 디렉터리 `X/`가 모두 포함될 수 있습니다. 일부 extractor와 decompiler는 혼동하여 디렉터리 entry로 실제 파일을 덮어쓰거나 숨길 수 있습니다. `classes.dex`와 같은 핵심 APK 이름과 충돌하는 entry에서 이러한 현상이 관찰되었습니다.

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
프로그램을 통한 수정 후 탐지:
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
Blue-team detection ideas:
- 로컬 헤더에서 encryption을 표시하는(GPBF bit 0 = 1) APK가 설치 또는 실행되는 경우를 flag합니다.
- 핵심 entry의 크기가 크거나 알 수 없는 Extra field를 flag합니다(`JADXBLOCK` 같은 marker를 확인).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대한 path-collisions(`X` 및 `X/`)을 flag합니다.

---

## 기타 악성 ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

최근 phishing campaign에서는 실제로 **두 개의 ZIP file이 연결된** 단일 blob을 전송합니다. 각 파일에는 자체 End of Central Directory (EOCD)와 central directory가 있습니다. Extractor마다 서로 다른 directory를 parse합니다(7zip은 첫 번째 것을 읽고, WinRAR는 마지막 것을 읽음). 이를 통해 공격자는 일부 tool에서만 표시되는 payload를 숨길 수 있습니다. 또한 이는 첫 번째 directory만 검사하는 기본 mail gateway AV도 우회합니다.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
둘 이상의 EOCD가 나타나거나 "data after payload" 경고가 표시되면 blob을 분할하고 각 부분을 검사합니다:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" builds a tiny **kernel** (highly compressed DEFLATE block) and reuses it via overlapping local headers. Every central directory entry points to the same compressed data, achieving >28M:1 ratios without nesting archives. Libraries that trust central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) can be forced to allocate petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
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
- Dry-run walk를 수행합니다: `zipdetails -v file.zip | grep -n "Rel Off"`를 실행하고 offset이 엄격하게 증가하며 중복되지 않는지 확인합니다.
- 압축 해제 전에 허용되는 전체 압축 해제 크기와 entry 수를 제한합니다(`zipdetails -t` 또는 custom parser).
- 반드시 압축을 해제해야 한다면 CPU와 disk 제한이 적용된 cgroup/VM 내부에서 수행합니다(제한 없는 inflation으로 인한 crash 방지).

---

### Local-header와 central-directory parser 간 혼동

최근 differential-parser 연구에 따르면 ZIP ambiguity는 최신 toolchain에서도 여전히 악용할 수 있습니다. 핵심 아이디어는 간단합니다. 일부 software는 **Local File Header (LFH)** 를 신뢰하는 반면, 다른 software는 **Central Directory (CD)** 를 신뢰하므로 하나의 archive가 서로 다른 tool에 서로 다른 filename, path, comment, offset 또는 entry set을 표시할 수 있습니다.<sup>[[9]](#references)</sup>

실전 offensive uses:
- upload filter, AV pre-scan 또는 package validator에는 CD의 benign file이 보이게 하면서 extractor는 다른 LFH name/path를 따르게 만듭니다.
- duplicate name, 한 구조에만 존재하는 entry 또는 모호한 Unicode path metadata(예: Info-ZIP Unicode Path Extra Field `0x7075`)를 악용하여 서로 다른 parser가 서로 다른 tree를 재구성하도록 합니다.
- 이를 path traversal과 결합하여 "harmless" archive view를 extraction 중 write-primitive로 전환합니다. extraction 측면은 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)을 참조하세요.

DFIR triage:
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
- LFH/CD 이름이 일치하지 않거나, 중복 파일 이름, 여러 개의 EOCD 레코드 또는 최종 EOCD 뒤에 추가 바이트가 있는 archive는 거부하거나 격리합니다.<sup>[[10]](#references)</sup>
- 서로 다른 도구가 추출된 트리에 대해 서로 다른 결과를 내놓는 경우, 비정상적인 Unicode-path extra field 또는 일관되지 않은 주석을 사용하는 ZIP을 의심합니다.<sup>[[9]](#references)</sup>
- 원본 바이트 보존보다 분석이 중요하다면, sandbox에서 추출한 후 strict parser로 archive를 다시 패키징하고, 결과 파일 목록을 원본 메타데이터와 비교합니다.

이는 package ecosystem을 넘어 중요합니다. 동일한 모호성 유형이 mail gateway, static scanner 및 ZIP 콘텐츠를 먼저 "peek"한 다음 다른 extractor가 archive를 처리하는 custom ingestion pipeline에서 payload를 숨길 수 있습니다.

---



## 참고 문헌

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – 다단계 dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip 스크립트)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [탐지되지 않도록 malware를 숨기는 ZIP archive의 유연한 구조 악용 (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [새로운 ZIP file attack에 malware를 숨기는 Hackers — 연결된 ZIP central directory](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [더 나은 zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Zip Bomb 이해하기: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [내 ZIP이 당신의 ZIP과 다른 이유: ZIP parser 간 semantic gap 식별 및 악용 (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python package installer에 대한 ZIP parser confusion attack 방지](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Known Plaintext가 감소된 ZIP Attack (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: ZIP Files Cracking](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
