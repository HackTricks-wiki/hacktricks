# ZIPのトリック

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は**zipファイル**の診断、修復、crackingに必須です。主要なユーティリティは以下の通りです:

- **`unzip`**: zipファイルが解凍されない原因を表示します。
- **`zipdetails -v`**: zipフォーマットのフィールドを詳細解析します。
- **`zipinfo`**: 展開せずにzipファイルの内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** と **`zip -FF input.zip --out output.zip`**: 破損したzipファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zipパスワードをbrute-force crackingするツール。おおむね7文字程度までのパスワードに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) はzipファイルの構造と規格について包括的に記述しています。

重要なのは、パスワード保護されたzipファイルは内部のファイル名やファイルサイズを**暗号化しない**という点で、これはRARや7zがこの情報を暗号化するのとは異なるセキュリティ上の欠陥です。さらに、古いZipCrypto方式で暗号化されたzipは、圧縮済みファイルの非暗号化版が利用可能な場合に**plaintext attack**に対して脆弱です。この攻撃は既知の内容を利用してzipのパスワードを解くもので、[HackThisの記事](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)や[この学術論文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)で詳述されています。ただし、**AES-256**で保護されたzipファイルはこのplaintext attackに対して免疫があり、機密データには安全な暗号方式を選ぶ重要性を示しています。

---

## Manipulated ZIPヘッダを使ったAPK内でのアンチリバーストリック

現代のAndroidマルウェアのdropperは、MalformedなZIPメタデータを使って静的解析ツール（jadx/apktool/unzip）を壊しつつ、デバイス上ではAPKをインストール可能に保つ手法を使います。よく使われるトリックは次の通りです:

- ZIP General Purpose Bit Flag (GPBF) の bit 0 をセットしての偽暗号化
- パーサを混乱させる大きな/カスタムExtraフィールドの悪用
- 実ファイルを隠すためのファイル/ディレクトリ名の衝突（例: 実際の `classes.dex` の隣に `classes.dex/` というディレクトリを置く）

### 1) 偽の暗号化（GPBF bit 0がセット） — 実際の暗号は無し

症状:
- `jadx-gui` が以下のようなエラーで失敗する:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` がコアAPKファイルに対してパスワードを促す（ただし有効なAPKで `classes*.dex`、`resources.arsc`、`AndroidManifest.xml` が暗号化されることはあり得ない）:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetailsによる検出:
```bash
zipdetails -v sample.apk | less
```
local and central headers の General Purpose Bit Flag を確認してください。特徴的なのは、core entries に対しても bit 0 がセットされていること（Encryption）です:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APKがデバイス上にインストールされ実行されるが、コアエントリがツール上で「encrypted」と表示される場合、GPBFが改ざんされています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF のビット0 をクリアすることで修正します。最小限のバイトパッチャ:

<details>
<summary>最小限のGPBFビットクリアパッチャー</summary>
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

使い方:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
これでコアエントリに `General Purpose Flag  0000` が表示され、ツールは再び APK を解析します。

### 2) パーサを壊す大きな/カスタム Extra fields

攻撃者は、デコンパイラを混乱させるためにヘッダに過大な Extra fields や奇妙な ID を詰め込みます。実際には、カスタムマーカー（例: `JADXBLOCK` のような文字列）が埋め込まれていることがあります。

確認:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観測例: `0xCAFE` ("Java Executable") や `0x414A` ("JA:") のような不明な ID が大きなペイロードを含んでいる。

DFIR ヒューリスティクス:
- 主要エントリ (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) で Extra fields が異常に大きい場合はアラートする。
- これらのエントリ上の不明な Extra IDs を疑わしいものとして扱う。

実用的な緩和策: アーカイブを再構築する（例: 抽出したファイルを再圧縮する）ことで悪意ある Extra fields を除去できる。ツールが偽の暗号化のために抽出を拒否する場合は、まず上記のように GPBF bit 0 をクリアしてから再パッケージ化する:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実際のアーティファクトを隠す）

ZIP は、ファイル `X` とディレクトリ `X/` の両方を含めることができます。  
一部の extractors や decompilers は混乱し、ディレクトリエントリで実際のファイルを上書きしたり隠したりする可能性があります。  
この問題は、`classes.dex` のようなコア APK 名とエントリが衝突するケースで観察されています。

トリアージと安全な抽出：
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
プログラムによる検出の後処理:
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
- ローカルヘッダが暗号化を示す（GPBF bit 0 = 1）にもかかわらずインストール／実行されるAPKsにフラグを立てる。
- コアエントリの大きな/不明な Extra フィールドにフラグを立てる（`JADXBLOCK`のようなマーカーを探す）。
- 特に `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` に対するパス衝突（`X` と `X/`）にフラグを立てる。

---

## その他の悪意あるZIPトリック（2024–2026）

### 連結された central directories（multi-EOCD 回避）

最近のフィッシングキャンペーンでは、実際には **二つのZIPファイルが連結されたもの** を単一のバイナリとして配布することがある。各ZIPは独自の End of Central Directory (EOCD) + central directory を持つ。抽出ツールによって解析するディレクトリが異なり（7zipは最初を、WinRARは最後を読む）、攻撃者は一部のツールでしか表示されないペイロードを隠せる。これはまた、最初のディレクトリのみを検査する基本的な mail gateway AV を回避する。

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
もし複数の EOCD が出現する、または "data after payload" 警告が表示される場合は、blob を分割して各部分を検査してください:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" は小さな **kernel**（highly compressed DEFLATE block）を生成し、overlapping local headers を介して再利用します。各 central directory エントリは同じ圧縮データを指し、アーカイブをネストすることなく >28M:1 の比率を達成します。central directory のサイズを信頼するライブラリ（Python `zipfile`、Java `java.util.zip`、ハードニング前の Info-ZIP）はペタバイト単位の割り当てを強制され得ます。

**簡易検出 (duplicate LFH offsets)**
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
**処理**
- ドライランでの検査を実施: `zipdetails -v file.zip | grep -n "Rel Off"` を使い、オフセットが厳密に増加し一意であることを確認する。
- 抽出前に受け入れる合計の未圧縮サイズとエントリ数に上限を設ける（`zipdetails -t` またはカスタムパーサを使用）。
- 抽出が必要な場合は、CPU・ディスク制限を設定した cgroup/VM 内で実行する（無制限の膨張によるクラッシュを避ける）。

---

### Local-header と central-directory パーサの混乱

最近の差分パーサの研究では、ZIP の曖昧性が現代のツールチェーンでも依然として悪用可能であることが示された。主な考えは簡単で、あるソフトは **Local File Header (LFH)** を信頼し、別のソフトは **Central Directory (CD)** を信頼するため、1つのアーカイブがツールごとに異なるファイル名、パス、コメント、オフセット、またはエントリ集合を提示し得る。

実用的な攻撃用途:
- upload filter、AV のプリスキャン、または package validator に CD 内の無害なファイルを見せかけ、extractor が別の LFH 名/パスを使って解凍するようにする。
- 重複する名前、一方の構造にのみ存在するエントリ、または曖昧な Unicode パスメタデータ（例えば Info-ZIP Unicode Path Extra Field `0x7075`）を悪用して、異なるパーサが異なるツリーを再構築するようにする。
- これを path traversal と組み合わせることで、アーカイブの「無害な」表示を抽出時に書き込みプリミティブに変えられる。抽出側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) を参照。

DFIR トリアージ:
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
対象ファイル（src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md）の内容を送ってください。「Complement it with:」の後に補足したい具体的な内容があれば併せて指示してください。受け取ったら、指定ルールに従ってMarkdown/HTML構文を保持したまま英語→日本語に翻訳します。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ヒューリスティクス:
- LFH/CD 名が不一致、重複したファイル名、複数の EOCD レコード、または最終 EOCD の後に余分なバイトがあるアーカイブは拒否するか隔離する。
- 異常な Unicode-path extra fields を使用している、またはコメントが一貫しない ZIP は、異なるツールで抽出されたツリーが一致しない場合に疑わしいものとして扱う。
- 解析が元のバイト列を維持することより重要な場合は、サンドボックス内で抽出した後、厳格なパーサーでアーカイブを再パッケージし、生成されたファイル一覧を元のメタデータと比較する。

これはパッケージエコシステムにとどまらない。同じ曖昧さのクラスは、別の extractor がアーカイブを処理する前に ZIP の内容を "peek" するメールゲートウェイ、静的スキャナ、およびカスタム取り込みパイプラインからペイロードを隠すことができる。

---



## 参考文献

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
