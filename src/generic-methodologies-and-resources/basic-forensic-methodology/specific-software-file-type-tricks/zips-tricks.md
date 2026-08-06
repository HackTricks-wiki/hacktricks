# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**zip files** の管理に使用する **Command-line tools** は、zip files の診断、修復、cracking に不可欠です。主な utility は次のとおりです。<sup>[[1]](#references)</sup>

- **`unzip`**: zip file が decompress できない理由を明らかにします。
- **`zipdetails -v`**: zip file format のフィールドを詳細に分析します。<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip file の内容を extraction せずに一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 破損した zip files の修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords の brute-force cracking 用 tool で、約 7 文字までの passwords に効果的です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) には、zip files の構造と standards に関する包括的な詳細が記載されています。<sup>[[4]](#references)</sup>

password-protected zip files は、内部の **filenames や file sizes を encrypt しない**ことに注意が必要です。これは、これらの情報も encrypt する RAR files や 7z files にはない security flaw です。さらに、旧式の ZipCrypto method で encrypt された zip files は、圧縮された file の unencrypted copy が利用可能な場合、**plaintext attack** に対して脆弱です。<sup>[[1]](#references)</sup> この attack は既知の content を利用して zip の password を crack します。この脆弱性については [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) で詳しく説明されており、[this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) でもさらに解説されています。<sup>[[11]](#references)[[12]](#references)</sup> ただし、**AES-256** encryption で保護された zip files はこの plaintext attack の影響を受けません。これは、sensitive data には secure な encryption methods を選択することの重要性を示しています。<sup>[[1]](#references)</sup>

---

## manipulated ZIP headers を使用した APKs の Anti-reversing tricks

Modern Android malware droppers は、malformed ZIP metadata を使用して static tools (jadx/apktool/unzip) を破壊しながら、device 上では APK を install 可能な状態に保ちます。最も一般的な tricks は次のとおりです。<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) の bit 0 を設定して Fake encryption を行う
- 大きな/custom Extra fields を悪用して parsers を混乱させる
- file/directory name collisions を利用して real artifacts を隠す（例: 実際の `classes.dex` の隣に `classes.dex/` という名前の directory を置く）

### 1) real crypto なしで Fake encryption (GPBF bit 0 set)

Symptoms:
- `jadx-gui` が次のような errors で失敗します:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` は、valid APK では `classes*.dex`、`resources.arsc`、または `AndroidManifest.xml` を encrypted にできないにもかかわらず、core APK files の password を要求します:

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
ローカルヘッダーとセントラルヘッダーの General Purpose Bit Flag を確認します。典型的な値は、コアエントリであってもビット 0（Encryption）がセットされていることです：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
経験則: APK がデバイス上でインストールおよび実行できるにもかかわらず、主要なエントリがツール上で「暗号化」されているように見える場合、GPBF が改変されています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF のビット 0 をクリアして修正します。最小限の byte-patcher:

<details>
<summary>最小限の GPBF ビットクリアパッチャー</summary>
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
これで、core entries に `General Purpose Flag  0000` が表示され、tools が再び APK を parse できるようになります。

### 2) parsers を破壊する Large/custom Extra fields

Attackers は oversized Extra fields と odd IDs を headers に詰め込み、decompilers を誤動作させます。実際の環境では、そこに埋め込まれた custom markers（`JADXBLOCK` のような strings など）が見つかることがあります。

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観測された例: `0xCAFE`（"Java Executable"）や `0x414A`（"JA:"）などの未知の ID が、大きな payload を保持しているケース。

DFIR ヒューリスティック:
- コアエントリ（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）の Extra fields が異常に大きい場合に Alert する。
- これらのエントリ上にある未知の Extra IDs を suspicious として扱う。

実践的な mitigation: archive を再構築する（例: 抽出した files を再度 zip 化する）ことで、悪意のある Extra fields が除去される。fake encryption が原因で tools が extract を拒否する場合は、まず上記のように GPBF bit 0 を clear してから、repackage する:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実際のartifactの隠蔽）

ZIPには、ファイル`X`とディレクトリ`X/`の両方を含めることができます。一部のextractorやdecompilerは混乱し、ディレクトリエントリによって実際のファイルを上書きまたは隠蔽することがあります。これは、`classes.dex`のようなcore APK名と衝突するエントリで確認されています。

Triageと安全な展開：
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
修正後のプログラムによる検出：
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
- local headers が encryption を示している（GPBF bit 0 = 1）にもかかわらず、install/run される APK を flag する。
- core entries にある大規模または未知の Extra fields を flag する（`JADXBLOCK` のような marker を探す）。
- 特に `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` について、path-collisions（`X` と `X/`）を flag する。

---

## その他の malicious ZIP tricks（2024–2026）

### Concatenated central directories（multi-EOCD evasion）

Recent phishing campaigns では、実際には **2つの ZIP files が連結された**単一の blob が送られている。それぞれが独自の End of Central Directory (EOCD) と central directory を持つ。extractor によって異なる directory が parse される（7zip は最初のものを読み、WinRAR は最後のものを読む）ため、攻撃者は一部の tools でしか表示されない payloads を隠せる。これは、最初の directory だけを inspect する basic mail gateway AV も bypass する。<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
複数の EOCD が存在する場合、または「data after payload」警告が表示される場合は、blob を分割して各部分を調査します:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs（非再帰）

Modern な「better zip bomb」build は、小さな **kernel**（高度に圧縮された DEFLATE block）を作成し、overlapping local headers を通じて再利用します。すべての central directory entry が同じ compressed data を指すため、archives をネストせずに >28M:1 の圧縮率を実現します。central directory のサイズを信頼する libraries（Python `zipfile`、Java `java.util.zip`、hardening 前の Info-ZIP）は、petabytes 単位のメモリ割り当てを強制される可能性があります。<sup>[[7]](#references)[[8]](#references)</sup>

**Quick detection（duplicate LFH offsets）**
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
**Handling**
- Dry-run walkを実行します: `zipdetails -v file.zip | grep -n "Rel Off"`。offsetが厳密に増加し、重複していないことを確認します。
- extraction前に、許容するtotal uncompressed sizeとentry countに上限を設定します（`zipdetails -t`またはcustom parser）。
- extractionが必要な場合は、CPUとdiskのlimitsを設定したcgroup/VM内で実行します（unbounded inflationによるcrashを回避）。

---

### Local-header vs central-directory parser confusion

Recent differential-parser researchでは、ZIPのambiguityがmodern toolchainsでも依然としてexploit可能であることが示されています。基本的な考え方は単純です。一部のsoftwareは**Local File Header (LFH)**を信頼する一方で、他のsoftwareは**Central Directory (CD)**を信頼するため、1つのarchiveが異なるtoolに対して異なるfilename、path、comment、offset、またはentry setを提示できます。<sup>[[9]](#references)</sup>

Practical offensive uses:
- upload filter、AV pre-scan、またはpackage validatorにはCD内のbenign fileを認識させ、extractorには異なるLFH name/pathを処理させます。
- duplicate names、片方のstructureにのみ存在するentries、またはambiguous Unicode path metadata（例: Info-ZIP Unicode Path Extra Field `0x7075`）を悪用し、異なるparserに異なるtreeを再構築させます。
- これをpath traversalと組み合わせ、"harmless"なarchive viewをextraction時のwrite-primitiveに変えます。extraction側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)を参照してください。

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
補足：
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ヒューリスティック:
- LFH/CD の名前が一致しないアーカイブ、重複するファイル名、複数の EOCD レコード、または最後の EOCD の後にバイト列があるアーカイブは拒否または隔離します。<sup>[[10]](#references)</sup>
- 特殊な Unicode-path extra fields を使用している ZIP や、異なるツールで展開された tree が一致しない場合の一貫性のないコメントは、suspicious として扱います。<sup>[[9]](#references)</sup>
- 元のバイト列の保持よりも分析が重要な場合は、sandbox 内で展開した後、strict parser を使用して archive を再パッケージし、生成された file list と元の metadata を比較します。

これは package ecosystems 以外にも関係します。同じ曖昧性の class により、mail gateways、static scanners、そして異なる extractor が archive を処理する前に ZIP の内容を「覗き見る」custom ingestion pipelines から payloads を隠すことができます。

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
