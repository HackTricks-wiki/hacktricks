# ZIP tricks

**Command-line tools** for managing **zip files**는 zip 파일을 진단하고, 복구하고, cracking하는 데 필수적입니다. 주요 유틸리티는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **`unzip`**: zip 파일의 압축이 해제되지 않는 이유를 보여 줍니다.
- **`zipdetails -v`**: zip file format 필드에 대한 상세한 분석을 제공합니다.<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip 파일의 내용을 추출하지 않고 나열합니다.
- **`zip -F input.zip --out output.zip`** 및 **`zip -FF input.zip --out output.zip`**: 손상된 zip 파일의 복구를 시도합니다.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip password를 brute-force cracking하는 도구로, 약 7자 이하의 password에 효과적입니다.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)은 zip 파일의 구조와 표준에 대한 포괄적인 세부 정보를 제공합니다.<sup>[[4]](#references)</sup>

기존의 password-protected ZIP 파일은 일반적으로 파일명과 파일 크기를 그대로 노출한다는 점에 유의해야 합니다. 이는 RAR 및 7z에서 지원하는 header-encryption 모드와 다릅니다. 또한 이전 ZipCrypto 방식으로 암호화된 ZIP 파일은 압축된 파일의 unencrypted copy를 사용할 수 있는 경우 **plaintext attack**에 취약합니다.<sup>[[1]](#references)</sup> 이 attack은 알려진 콘텐츠를 활용해 ZIP의 password를 crack하며, 자세한 내용은 [this academic paper](https://math.ucr.edu/~mike/zipattacks.pdf)에 설명되어 있고 [this Hack This Site walk-through](https://www.hackthissite.org/articles/read/793)에 예시가 나와 있습니다.<sup>[[11]](#references)[[12]](#references)</sup> 그러나 ZipCrypto known-plaintext attack은 **AES-256** encryption으로 보호되는 entries에는 적용되지 않습니다.<sup>[[1]](#references)</sup>

---

## 조작된 ZIP headers를 사용하는 APK의 Anti-reversing tricks

Modern Android malware droppers는 malformed ZIP metadata를 사용해 static tools (jadx/apktool/unzip)를 무력화하면서도 APK가 device에 설치될 수 있도록 합니다. 가장 일반적인 tricks는 다음과 같습니다:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF)의 bit 0을 설정해 fake encryption 수행
- 대규모 또는 custom Extra fields를 악용해 parsers 혼란시키기
- 파일/디렉터리 이름 충돌을 이용해 실제 artifacts 숨기기 (예: 실제 `classes.dex` 옆에 `classes.dex/`라는 이름의 디렉터리 배치)

### 1) 실제 crypto 없이 fake encryption 수행 (GPBF bit 0 설정)

증상:
- `jadx-gui`가 다음과 같은 errors와 함께 실패합니다:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`이 password를 묻습니다. 하지만 유효한 APK에서는 `classes*.dex`, `resources.arsc` 또는 `AndroidManifest.xml`을 encrypted 상태로 둘 수 없습니다:

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
로컬 및 중앙 헤더의 General Purpose Bit Flag를 확인하세요. 핵심 항목에서도 bit 0 set(Encryption)인 값이 명확한 단서입니다:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: APK가 기기에 설치되고 실행되지만 핵심 항목이 도구에서 "encrypted"로 표시된다면, GPBF가 변조된 것입니다.

LFH(Local File Headers)와 CD(Central Directory) 항목 모두에서 GPBF bit 0을 지워 수정합니다. 최소 바이트 패처:

<details>
<summary>최소 GPBF bit-clear 패처</summary>
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
이제 core 항목에 `General Purpose Flag  0000`이 표시되고 tools가 APK를 다시 파싱할 수 있습니다.

### 2) 파서를 중단시키기 위한 대형/custom Extra fields

Attackers는 decompiler를 방해하기 위해 헤더에 크기가 과도한 Extra fields와 특이한 ID를 삽입합니다. 실제 환경에서는 그 안에 사용자 지정 marker(예: `JADXBLOCK`과 같은 문자열)가 포함된 것을 볼 수 있습니다.

검사:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
관찰된 예시: `0xCAFE`("Java Executable") 또는 `0x414A`("JA:")와 같은 알 수 없는 ID가 대용량 payload를 포함하고 있습니다.<sup>[[2]](#references)</sup>

DFIR 휴리스틱:
- 핵심 엔트리(`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`)에서 Extra fields가 비정상적으로 큰 경우 경고합니다.
- 해당 엔트리에서 알 수 없는 Extra ID를 발견하면 suspicious한 것으로 처리합니다.

실용적인 완화 방법: archive를 다시 빌드하면(예: 추출한 파일을 다시 zipping) 악성 Extra fields가 제거됩니다. fake encryption 때문에 tools가 추출을 거부하는 경우, 먼저 위와 같이 GPBF bit 0을 clear한 다음 다시 package합니다:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) 파일/디렉터리 이름 충돌 (실제 artifact 숨기기)

ZIP에는 파일 `X`와 디렉터리 `X/`가 모두 포함될 수 있습니다. 일부 extractor와 decompiler는 혼동하여 디렉터리 항목으로 실제 파일을 덮어쓰거나 숨길 수 있습니다. `classes.dex`와 같은 핵심 APK 이름의 항목에서 이러한 충돌이 관찰되었습니다.

Triage 및 안전한 extraction:
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
Blue-team detection ideas:
- 로컬 헤더에서 암호화가 표시되어 있지만 (GPBF bit 0 = 1) 설치되거나 실행되는 APK를 탐지합니다.
- 핵심 엔트리의 크거나 알 수 없는 Extra 필드를 탐지합니다 (`JADXBLOCK` 같은 marker를 확인).
- 특히 `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`에 대해 경로 충돌(`X` 및 `X/`)을 탐지합니다.

---

## 기타 악성 ZIP tricks (2024–2026)

### 연결된 central directories (multi-EOCD evasion)

2024년 phishing campaign에서 공격자들은 실제로 **두 개의 ZIP 파일을 연결한** 단일 blob을 배포했습니다. 각각 고유한 End of Central Directory (EOCD) record와 central directory를 포함했습니다. 서로 다른 extractor가 서로 다른 directory를 파싱했습니다(7-Zip은 첫 번째 것을 읽고 WinRAR는 마지막 것을 읽음). 이를 통해 공격자들은 일부 도구에서만 표시되는 payload를 숨길 수 있었습니다. 하나의 directory만 검사하는 scanner는 다른 archive를 놓칠 수 있습니다.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
둘 이상의 EOCD가 나타나거나 "data after payload" 경고가 표시되면 blob을 분할하고 각 부분을 검사하세요:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (비재귀)

Quoted-overlap ZIP bombs는 작은 **kernel**(고도로 압축된 DEFLATE block)을 생성하고, 이를 겹치는 entries에서 재사용합니다. Full-overlap variants는 여러 central-directory entries가 하나의 local header를 가리키도록 하며, quoted-overlap variants는 DEFLATE streams 내부에서 local headers를 인용합니다. 공개된 construction은 nested archives 없이 28M:1 이상의 비율을 달성합니다.<sup>[[7]](#references)</sup>

**빠른 탐지(중복 LFH offsets)**
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
- Dry-run walk를 수행합니다: `zipdetails -v file.zip | grep -n "Local Header Offset"`를 실행하고, 참조된 local-header offset과 compressed-data 범위를 비교합니다. offset이 중복되면 full-overlap 변형을 나타냅니다.<sup>[[7]](#references)[[8]](#references)</sup>
- parser를 사용해 extraction 전에 허용되는 전체 uncompressed size와 entry 수를 제한합니다. `zipinfo -t file.zip`은 총계를 보고하지만 안전 제한을 적용하지는 않습니다.<sup>[[8]](#references)</sup>
- 반드시 extract해야 한다면 CPU와 디스크 제한이 적용된 cgroup/VM 내부에서 수행합니다(unbounded inflation crash 방지).<sup>[[8]](#references)</sup>

---

### Local-header와 central-directory parser의 혼동

최근 differential-parser 연구에 따르면 ZIP ambiguity는 최신 toolchain에서도 여전히 exploit할 수 있습니다. 핵심은 간단합니다. 일부 software는 **Local File Header (LFH)** 를 신뢰하는 반면, 다른 software는 **Central Directory (CD)** 를 신뢰하므로 하나의 archive가 서로 다른 tool에 서로 다른 filename, path, comment, offset 또는 entry set을 표시할 수 있습니다.<sup>[[9]](#references)</sup>

실제 offensive 사용 사례:
- upload filter, AV pre-scan 또는 package validator에는 CD의 benign file이 보이게 하면서, extractor는 다른 LFH name/path를 따르게 만듭니다.
- duplicate name, 한 구조에만 존재하는 entry 또는 모호한 Unicode path metadata(예: Info-ZIP Unicode Path Extra Field `0x7075`)를 악용해 서로 다른 parser가 서로 다른 tree를 재구성하게 합니다.
- 이를 path traversal과 결합해 "무해한" archive view를 extraction 중 write-primitive로 전환합니다. extraction 측면은 [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)을 참조하세요.

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
- 보안에 민감한 ingestion의 경우, LFH/CD 이름이 일치하지 않거나, 중복된 파일 이름이 있거나, 여러 EOCD 레코드가 있거나, 마지막 EOCD 뒤에 trailing bytes가 있는 archive는 거부하거나 격리합니다.<sup>[[9]](#references)[[10]](#references)</sup>
- 비정상적인 Unicode-path extra fields를 사용하거나 comments가 일관되지 않은 ZIP은, 서로 다른 도구가 추출된 tree에 대해 서로 다른 결과를 내놓는 경우 의심스러운 것으로 처리합니다.<sup>[[4]](#references)[[9]](#references)</sup>
- 원본 bytes 보존보다 analysis가 중요한 경우, sandbox에서 extraction한 후 strict parser를 사용해 archive를 다시 패키징하고, 그 결과 생성된 file list를 원본 metadata와 비교합니다.

이는 package ecosystems를 넘어 중요한 문제입니다. 동일한 ambiguity class는 mail gateways, static scanners, 그리고 다른 extractor가 archive를 처리하기 전에 ZIP contents를 "peek"하는 custom ingestion pipelines에서 payloads를 숨길 수 있습니다.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
