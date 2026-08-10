# ZIP tricks

**ZIP files**を管理するための**Command-line tools**は、ZIP filesの診断、修復、crackingに不可欠です。主なutilityは次のとおりです:<sup>[[1]](#references)</sup>

- **`unzip`**: ZIP fileがdecompressできない理由を明らかにします。
- **`zipdetails -v`**: ZIP file formatのfieldを詳細に分析します。<sup>[[3]](#references)</sup>
- **`zipinfo`**: ZIP fileの内容をextractせずに一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: corruptしたZIP filesの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIP passwordsのbrute-force cracking用toolで、約7文字までのpasswordに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)には、ZIP filesの構造とstandardsに関する包括的な詳細が記載されています。<sup>[[4]](#references)</sup>

従来のpassword-protected ZIP filesでは、RARや7zがサポートするheader-encryption modesとは異なり、通常はfilenamesとfile sizesが表示されたままになる点に注意が必要です。さらに、古いZipCrypto methodで暗号化されたZIP filesは、compressed fileのunencrypted copyが利用可能な場合、**plaintext attack**に対して脆弱です。<sup>[[1]](#references)</sup>このattackは、既知のcontentを利用してZIPのpasswordをcrackします。詳細は[このacademic paper](https://math.ucr.edu/~mike/zipattacks.pdf)で説明され、[このHack This Site walk-through](https://www.hackthissite.org/articles/read/793)で実演されています。<sup>[[11]](#references)[[12]](#references)</sup>ただし、ZipCrypto known-plaintext attackは**AES-256** encryptionで保護されたentriesには適用されません。<sup>[[1]](#references)</sup>

---

## manipulated ZIP headersを使用したAPKsのAnti-reversing tricks

Modern Android malware droppersは、malformed ZIP metadataを使用してstatic tools（jadx/apktool/unzip）を破壊しつつ、on-deviceではAPKをinstall可能な状態に保ちます。最も一般的なtricksは次のとおりです:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF)のbit 0を設定してFake encryptionを行う
- Large/custom Extra fieldsを悪用してparsersを混乱させる
- File/directory name collisionsによってreal artifactsを隠す（例: realな`classes.dex`の隣に`classes.dex/`という名前のdirectoryを置く）

### 1) real cryptoなしでFake encryption（GPBF bit 0を設定）

Symptoms:
- `jadx-gui`が次のようなerrorsで失敗します:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip`は、validなAPKでは`classes*.dex`、`resources.arsc`、または`AndroidManifest.xml`をencryptedにできないにもかかわらず、core APK filesのpasswordを要求します:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetailsによるDetection:
```bash
zipdetails -v sample.apk | less
```
local および central headers の General Purpose Bit Flag を確認します。core entries であっても、bit 0 が設定されている（Encryption）ことが典型的な値です：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APK がデバイス上でインストールおよび実行できるにもかかわらず、コアエントリがツール上で「暗号化」されているように見える場合、GPBF が改ざんされています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF bit 0 をクリアして修正します。最小限の byte-patcher:

<details>
<summary>最小限の GPBF bit-clear patcher</summary>
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

使用法:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
You should now see `General Purpose Flag  0000` on core entries and tools will parse the APK again.

### 2) Large/custom Extra fields to break parsers

Attackers stuff oversized Extra fields and odd IDs into headers to trip decompilers. In the wild you may see custom markers (e.g., strings like `JADXBLOCK`) embedded there.

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観察された例: 大きな payload を含む、`0xCAFE`（"Java Executable"）や `0x414A`（"JA:"）のような未知の ID。<sup>[[2]](#references)</sup>

DFIR ヒューリスティック:
- コアエントリ（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）の Extra fields が異常に大きい場合に Alert する。
- これらのエントリにある未知の Extra IDs は suspicious とみなす。

実用的な mitigation: archive を再構築する（例: 展開したファイルを再度 zip 化する）と、malicious な Extra fields が除去される。fake encryption が原因で tools が extract を拒否する場合は、まず上記のように GPBF bit 0 を clear してから、repackage する:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実際のアーティファクトの隠蔽）

ZIPには、ファイル `X` とディレクトリ `X/` の両方を含めることができます。一部のextractorやdecompilerは混乱し、ディレクトリエントリによって実際のファイルを上書きしたり隠蔽したりする場合があります。これは `classes.dex` のような主要なAPK名と衝突するエントリで確認されています。

トリアージと安全な展開:
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
Blue-team の検出アイデア:
- local headers で暗号化（GPBF bit 0 = 1）が示されているにもかかわらず、install/run される APK を検出する。
- core entries にある大きな/未知の Extra fields を検出する（`JADXBLOCK` のような marker を探す）。
- 特に `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` について、path-collisions（`X` と `X/`）を検出する。

---

## その他の悪意ある ZIP tricks（2024–2026）

### Concatenated central directories（multi-EOCD evasion）

2024 年の phishing campaign では、攻撃者は実際には **2 つの ZIP files を連結した**単一の blob を配布した。それぞれに独自の End of Central Directory（EOCD）record と central directory があった。異なる extractors は異なる directory を parse した（7-Zip は最初のものを、WinRAR は最後のものを read した）ため、攻撃者は一部の tools でしか表示されない payloads を隠すことができた。1 つの directory だけを inspect する scanners は、もう一方の archive を見逃す可能性がある。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
複数の EOCD が現れる、または「data after payload」警告がある場合は、blob を分割して各部分を調査します:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs は、小さな **kernel**（高度に圧縮された DEFLATE block）を構築し、overlapping entries 間で再利用します。Full-overlap variants は複数の central-directory entries を 1 つの local header に指定し、quoted-overlap variants は DEFLATE streams 内で local headers を quote します。公開された construction では、nested archives を使用せずに 28M:1 を超える圧縮率を実現しています。<sup>[[7]](#references)</sup>

**Quick detection（重複する LFH offsets）**
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
- Dry-run walkを実行する: `zipdetails -v file.zip | grep -n "Local Header Offset"` を使い、参照されているlocal-header offsetとcompressed-data rangeを比較する。重複したoffsetは完全な重複variantを示す。<sup>[[7]](#references)[[8]](#references)</sup>
- parserでextraction前に、許容するtotal uncompressed sizeとentry countに上限を設定する。`zipinfo -t file.zip` はtotalを報告するが、安全上の上限は強制しない。<sup>[[8]](#references)</sup>
- extractionが必要な場合は、CPUとdiskの制限を設定したcgroup/VM内で実行する（制限のないinflationによるcrashを回避する）。<sup>[[8]](#references)</sup>

---

### Local-headerとcentral-directoryのparserの混乱

最近のdifferential-parser researchにより、ZIPの曖昧性はmodern toolchainでも依然としてexploit可能であることが示された。基本的な考え方は単純で、一部のsoftwareは **Local File Header (LFH)** を信頼し、別のsoftwareは **Central Directory (CD)** を信頼する。そのため、1つのarchiveが異なるtoolに対して、異なるfilename、path、comment、offset、またはentry setを提示できる。<sup>[[9]](#references)</sup>

実践的なoffensive use:
- upload filter、AV pre-scan、またはpackage validatorにはCD内のbenignなfileを認識させ、extractorには異なるLFH name/pathを使用させる。
- duplicate name、片方のstructureにのみ存在するentry、または曖昧なUnicode path metadata（例: Info-ZIP Unicode Path Extra Field `0x7075`）を悪用し、異なるparserに異なるtreeを再構築させる。
- これをpath traversalと組み合わせ、extraction時に「harmless」なarchive viewをwrite-primitiveへ変える。extraction側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) を参照。

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
翻訳する本文を送ってください。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ヒューリスティック:
- セキュリティに敏感な取り込み処理では、LFH/CD の名前が一致しない archive、重複したファイル名、複数の EOCD レコード、または最後の EOCD の後に trailing bytes がある archive を拒否または隔離する。<sup>[[9]](#references)[[10]](#references)</sup>
- 通常とは異なる Unicode-path extra fields を使用している ZIP や、異なる tools が展開後の tree について異なる結果を示す場合は、一貫性のない comments とともに suspicious として扱う。<sup>[[4]](#references)[[9]](#references)</sup>
- 元の bytes の保持よりも分析が重要な場合は、sandbox 内で展開した後、strict parser を使って archive を再パッケージ化し、得られた file list を元の metadata と比較する。

これは package ecosystems に限った話ではない。同じ曖昧性のクラスによって、mail gateways、static scanners、さらに別の extractor が archive を処理する前に ZIP の内容を "peek" する custom ingestion pipelines から payloads を隠すことができる。<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide（Mike's Blog、CTF category）](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper（APK ZIP anti-reversing）](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails（IO::Compress script）](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification（PKWARE APPNOTE.TXT）](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [検知されないように malware を隠す、柔軟な ZIP archives の構造の悪用（Perception Point）](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [より優れた zip bomb（David Fifield、USENIX WOOT 2019）](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip Bombs の理解: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [私の ZIP はあなたの ZIP ではない: ZIP parsers 間の semantic gaps の特定と悪用（USENIX Security 2025）](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python package installers に対する ZIP parser confusion attacks の防止](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Reduced Known Plaintext による ZIP Attacks（Michael Stay、AccessData Corporation）](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission、Level 15（known-plaintext ZIP attack）](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
