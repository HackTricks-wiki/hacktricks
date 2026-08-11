# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**ZIP files** の管理に使用する **Command-line tools** は、ZIP files の診断、修復、cracking に不可欠です。主な utilities は次のとおりです。<sup>[[1]](#references)</sup>

- **`unzip`**: ZIP file が decompress できない理由を明らかにします。
- **`zipdetails -v`**: ZIP file format の fields を詳細に分析します。<sup>[[3]](#references)</sup>
- **`zipinfo`**: ZIP file の contents を extract せずに一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: corrupted ZIP files の修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP passwords の brute-force cracking 用 tool で、約 7 文字までの passwords に有効です。

[ZIP file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) には、ZIP files の structure と standards に関する包括的な詳細が記載されています。<sup>[[4]](#references)</sup>

従来の password-protected ZIP files では、RAR や 7z がサポートする header-encryption modes とは異なり、通常は filenames と file sizes が visible のままである点に注意が必要です。さらに、古い ZipCrypto method で encrypted された ZIP files は、compressed file の unencrypted copy が利用可能な場合、**plaintext attack** に対して vulnerable です。<sup>[[1]](#references)</sup> この attack は既知の content を利用して ZIP の password を crack します。詳細は[この academic paper](https://math.ucr.edu/~mike/zipattacks.pdf)で説明され、[この Hack This Site walk-through](https://www.hackthissite.org/articles/read/793)で実演されています。<sup>[[11]](#references)[[12]](#references)</sup> ただし、ZipCrypto known-plaintext attack は **AES-256** encryption で保護された entries には適用されません。<sup>[[1]](#references)</sup>

---

## 改変された ZIP headers を使った APKs の Anti-reversing tricks

Modern Android malware droppers は、malformed ZIP metadata を使用して static tools（jadx/apktool/unzip）を破壊しながら、device 上では APK を install 可能な状態に保ちます。最も一般的な tricks は次のとおりです。<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) の bit 0 を設定して Fake encryption を行う
- 大きな/custom Extra fields を悪用して parsers を混乱させる
- File/directory name collisions によって real artifacts を隠す（例: real `classes.dex` の隣に `classes.dex/` という名前の directory を置く）

### 1) real crypto を使わない Fake encryption（GPBF bit 0 が設定されている場合）

Symptoms:
- `jadx-gui` が次のような errors で失敗します。

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` は、valid APK では `classes*.dex`、`resources.arsc`、または `AndroidManifest.xml` を encrypted にできないにもかかわらず、core APK files の password を要求します。

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails による Detection:
```bash
zipdetails -v sample.apk | less
```
local および central headers の General Purpose Bit Flag を確認します。core entries であっても bit 0 が設定されている（Encryption）場合は、典型的な兆候です：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APKがデバイス上でインストールおよび実行できる一方で、主要なエントリがツール上で「encrypted」と表示される場合、GPBFが改変されています。

LFH（Local File Header）とCD（Central Directory）の両方のエントリでGPBF bit 0をクリアして修正します。最小限のbyte-patcher:

<details>
<summary>最小限のGPBF bit-clear patcher</summary>
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

使用方法:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
`General Purpose Flag  0000` が core entries に表示され、tools で APK を再び parse できるようになります。

### 2) Large/custom Extra fields で parsers を破壊する

Attackers は oversized な Extra fields と奇妙な IDs を headers に詰め込み、decompilers を誤動作させます。実際の環境では、そこに埋め込まれた custom markers（例: `JADXBLOCK` のような strings）が見つかることがあります。

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観測された例: 大きな payload を格納した、`0xCAFE`（"Java Executable"）や `0x414A`（"JA:"）のような未知の ID。<sup>[[2]](#references)</sup>

DFIR ヒューリスティック:
- コアエントリ（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）の Extra fields が通常より大きい場合に Alert する。
- これらのエントリにある未知の Extra ID は suspicious とみなす。

実用的な mitigation: archive を再構築する（例: 抽出した files を再度 zip 化する）と、悪意のある Extra fields が除去される。fake encryption が原因で tools が extract を拒否する場合は、まず上記のように GPBF bit 0 を clear してから、repackage する:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions（実際の artifact の隠蔽）

ZIP には、ファイル `X` とディレクトリ `X/` の両方を含めることができます。一部の extractor や decompiler は混乱し、ディレクトリエントリによって実際のファイルを上書きまたは隠蔽する場合があります。`classes.dex` のような中核 APK 名とエントリが衝突するケースが確認されています。

Triage と安全な extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
修正後のプログラムによる検出:
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
Blue-teamによる検出アイデア:
- ローカルヘッダーで暗号化（GPBF bit 0 = 1）とマークされているにもかかわらず、install/runできるAPKを検出する。
- coreエントリにある大きい/未知のExtra fieldsを検出する（`JADXBLOCK`のようなmarkerを探す）。
- `AndroidManifest.xml`、`resources.arsc`、`classes*.dex`について、path-collisions（`X`と`X/`）を特に検出する。

---

## その他の悪意あるZIP tricks（2024–2026）

### 連結されたcentral directories（multi-EOCD evasion）

2024年のphishing campaignでは、攻撃者が実際には**2つのZIP filesを連結した**単一のblobを配布した。それぞれに独自のEnd of Central Directory（EOCD）recordとcentral directoryが含まれていた。extractorごとに異なるdirectoryをparseし（7-Zipは最初のものを、WinRARは最後のものを読み取る）、攻撃者は一部のtoolでしか表示されないpayloadsを隠すことができた。1つのdirectoryだけをinspectするscannerでは、もう一方のarchiveを見落とす可能性がある。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
複数の EOCD が存在する場合、または「data after payload」警告が表示される場合は、blob を分割して各部分を調査します。
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs（non-recursive）

Quoted-overlap ZIP bombs は、小さな **kernel**（高度に圧縮された DEFLATE block）を構築し、overlapping entries 間で再利用します。Full-overlap variants は複数の central-directory entries を 1 つの local header に向け、quoted-overlap variants は DEFLATE streams 内で local headers を quote します。公開された construction では、nested archives を使用せずに 28M:1 を超える圧縮率を実現しています。<sup>[[7]](#references)</sup>

**Quick detection（duplicate LFH offsets）**
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
**Handling**
- Perform a dry-run walk: `zipdetails -v file.zip | grep -n "Local Header Offset"` を実行し、参照されている local-header offsets と compressed-data ranges を比較する。重複する offsets は full-overlap variants を示す。<sup>[[7]](#references)[[8]](#references)</sup>
- parser を使って、extraction 前に許可する total uncompressed size と entry count に上限を設定する。`zipinfo -t file.zip` は totals を報告するが、安全上の制限は強制しない。<sup>[[8]](#references)</sup>
- extraction が必要な場合は、CPU と disk の制限を設定した cgroup/VM 内で実行する（unbounded inflation によるクラッシュを回避する）。<sup>[[8]](#references)</sup>

---

### Local-header と central-directory の parser confusion

Recent differential-parser research により、ZIP の ambiguity は modern toolchains でも依然として exploitable であることが示された。基本的な考え方は単純で、一部の software は **Local File Header (LFH)** を信頼し、他の software は **Central Directory (CD)** を信頼する。そのため、1 つの archive が、異なる tools に対して異なる filenames、paths、comments、offsets、または entry sets を提示できる。<sup>[[9]](#references)</sup>

Practical offensive uses:
- upload filter、AV pre-scan、または package validator には CD 内の benign file を認識させ、extractor には異なる LFH name/path を使用させる。
- duplicate names、片方の structure にのみ存在する entries、または ambiguous Unicode path metadata（例: Info-ZIP Unicode Path Extra Field `0x7075`）を悪用し、異なる parsers に異なる trees を再構築させる。
- これを path traversal と組み合わせ、"harmless" な archive view を extraction 中の write-primitive に変える。extraction 側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) を参照。

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
翻訳する英文を送ってください。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Security-sensitive ingestion では、LFH/CD の名前が一致しない archive、重複するファイル名、複数の EOCD レコード、または最後の EOCD 後に trailing bytes がある archive を拒否または隔離します。<sup>[[9]](#references)[[10]](#references)</sup>
- 通常とは異なる Unicode-path extra fields を使用している ZIP や、抽出された tree について異なる tools の結果が一致しない場合は、一貫性のない comments を持つ ZIP を suspicious として扱います。<sup>[[4]](#references)[[9]](#references)</sup>
- 元の bytes の保持よりも analysis が重要な場合は、sandbox 内で抽出した後、strict parser を使用して archive を repack し、結果の file list を元の metadata と比較します。

これは package ecosystems に限った問題ではありません。同じ ambiguity class により、mail gateways、static scanners、そして異なる extractor が archive を処理する前に ZIP contents を "peek" する custom ingestion pipelines から payloads が隠される可能性があります。<sup>[[9]](#references)</sup>

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
