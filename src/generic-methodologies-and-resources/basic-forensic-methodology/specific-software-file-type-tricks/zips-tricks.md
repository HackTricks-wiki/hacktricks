# ZIPのトリック

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール** は、**zipファイル** の診断、修復、クラッキングに不可欠です。主なユーティリティは次のとおりです:

- **`unzip`**: zipファイルが展開できない理由を明らかにします。
- **`zipdetails -v`**: zipファイルフォーマットのフィールドを詳細に解析します。
- **`zipinfo`**: 展開せずにzip内の内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 破損したzipファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zipパスワードのブルートフォースクラック用ツール。おおよそ7文字程度までのパスワードに有効です。

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

パスワード保護されたzipファイルはファイル名やファイルサイズを暗号化しない点に注意が必要です。これは、これらの情報を暗号化する RAR や 7z とは異なるセキュリティ上の欠陥です。さらに、古い ZipCrypto メソッドで暗号化されたzipは、圧縮ファイルの非暗号化コピーが利用可能な場合に既知平文攻撃 (known-plaintext attack) の影響を受けます。この攻撃は既知の内容を利用してzipのパスワードを解読するもので、詳細は [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) や [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) を参照してください。しかし、AES-256 で保護されたzipファイルはこの既知平文攻撃に対して耐性があり、機密データにはより安全な暗号方式を選択する重要性を示しています。

---

## 操作されたZIPヘッダを使ったAPKのアンチリバーストリック

現代のAndroidマルウェアドロッパーは、壊れたZIPメタデータを用いて静的解析ツール（jadx/apktool/unzip）を動作不能にしつつ、デバイス上ではAPKのインストールが可能なままにする手法を使います。一般的なトリックは以下の通りです:

- GPBF のビット0を立てて偽の暗号化を示す
- 解析器を混乱させるために大きな/カスタムの Extra フィールドを悪用する
- 実際のアーティファクトを隠すためのファイル/ディレクトリ名の衝突（例: 実際の `classes.dex` の隣に `classes.dex/` というディレクトリを置く）

### 1) 偽の暗号化（GPBF bit 0 がセット）— 実際の暗号なし

症状:
- `jadx-gui` は次のようなエラーで失敗することがあります:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` は主要なAPKファイルに対してパスワードを求めますが、有効なAPKでは `classes*.dex`、`resources.arsc`、または `AndroidManifest.xml` を暗号化できません:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
ローカルおよびセントラルヘッダーの General Purpose Bit Flag を見てください。特徴的なのは、コアエントリでもビット0（Encryption）が設定されていることです：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
経験則：APK がデバイスにインストールされて実行されるが、ツールでコアエントリが「encrypted」と表示される場合、GPBF が改ざんされています。

対処方法：Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF のビット0 をクリアしてください。最小限の byte-patcher：

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

使い方:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
コアエントリに `General Purpose Flag  0000` が表示され、ツールはAPKを再び解析できるはずです。

### 2) パーサを壊す大きな/カスタム Extra fields

攻撃者はデコンパイラを混乱させるために、ヘッダに大きすぎる Extra fields や奇妙な ID を詰め込みます。実際のサンプルでは、`JADXBLOCK` のような文字列などのカスタムマーカーが埋め込まれていることがあります。

検査:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観測例: 不明な ID (`0xCAFE` ("Java Executable") や `0x414A` ("JA:")) が大きなペイロードを含むことがある。

DFIR ヒューリスティクス:
- core エントリ（`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`）で Extra fields が異常に大きい場合にアラートする。
- これらのエントリの不明な Extra IDs を疑わしいものとして扱う。

実用的な対策: アーカイブを再構築する（例: 抽出したファイルを再圧縮する）と悪意のある Extra fields は削除される。ツールが偽の暗号化のために抽出を拒否する場合は、上記のようにまず GPBF bit 0 をクリアしてから再パッケージする:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突 (実際のアーティファクトを隠す)

ZIPはファイル`X`とディレクトリ`X/`の両方を含むことができます。いくつかの抽出ツールやデコンパイラは混乱し、ディレクトリエントリで実際のファイルを上書きまたは隠してしまう場合があります。これは`classes.dex`のようなコアAPK名とエントリが衝突するケースで観察されています。

トリアージと安全な抽出:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
プログラムによる検出用ポストフィックス:
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
- ローカルヘッダが暗号化を示す（GPBF bit 0 = 1）にもかかわらずインストール/実行される APK を検知/フラグする。
- コアエントリの大きな/不明な Extra フィールド（`JADXBLOCK` のようなマーカーを探す）を検知/フラグする。
- パス衝突（`X` と `X/`）を、特に `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` に対して検知/フラグする。

---

## その他の悪意あるZIPトリック（2024–2026）

### 結合された central directories (multi-EOCD evasion)

最近のフィッシングキャンペーンでは、実際には **2つのZIPファイルが連結された** 単一のバイナリを配布するケースがある。各ファイルはそれぞれ独自の End of Central Directory (EOCD) と central directory を持つ。抽出ツールによって解析されるディレクトリが異なる（7zip は最初を読む、WinRAR は最後を読む）ため、攻撃者は一部のツールにしか表示されないペイロードを隠せる。これにより、最初のディレクトリだけを検査する基本的な mail gateway AV も回避される。

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
EOCD が複数出現する、または "data after payload" 警告がある場合は、blob を分割して各部分を調査してください:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

現代の "better zip bomb" は小さな **kernel**（高度に圧縮された DEFLATE ブロック）を構築し、overlapping local headers を介して再利用します。各 central directory エントリが同じ圧縮データを指すことで、ネストしたアーカイブなしに >28M:1 の比率を達成します。central directory のサイズを信頼するライブラリ（Python `zipfile`、Java `java.util.zip`、Info-ZIP の hardened builds より前のバージョン）はペタバイト単位の割り当てを強いられる可能性があります。

**簡易検出（重複する LFH オフセット）**
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
- ドライランで走査する: `zipdetails -v file.zip | grep -n "Rel Off"` を実行し、オフセットが厳密に増加し一意であることを確認する。
- 抽出前に受け入れる総非圧縮サイズとエントリ数の上限を設ける（`zipdetails -t` またはカスタムパーサ）。
- 抽出が必要な場合は、CPU/ディスク制限を設定した cgroup/VM 内で行う（無限膨張によるクラッシュを避ける）。

---

### ローカルヘッダー vs セントラルディレクトリ パーサの混乱

最近の差分パーサの研究では、ZIP の曖昧性が現代のツールチェーンでも依然として悪用可能であることが示された。主な考え方は単純で、あるソフトウェアは **Local File Header (LFH)** を信頼し、別のソフトは **Central Directory (CD)** を信頼するため、同じアーカイブがツールによって異なるファイル名、パス、コメント、オフセット、またはエントリセットを示すことがある。

実務での攻撃的利用例:
- アップロードフィルタ、AV の事前スキャン、またはパッケージ検証が CD にある無害なファイルを検出する一方で、抽出側が別の LFH 名/パスを使用するようにできる。
- 重複した名前、片方の構造にのみ存在するエントリ、または曖昧な Unicode パスメタデータ（例: Info-ZIP Unicode Path Extra Field `0x7075`）を悪用し、異なるパーサが異なるディレクトリツリーを再構成するようにする。
- これを path traversal と組み合わせることで、「無害」に見えるアーカイブのビューを抽出時の書き込みプリミティブに変えることができる。抽出側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) を参照。

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
補足したい英語のテキスト（または該当する zips-tricks.md の部分）を送ってください。受け取った内容を指定のルールに従って日本語に翻訳して返します。
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ヒューリスティック:
- LFH/CD 名が不一致、重複したファイル名、複数の EOCD レコード、または最終 EOCD 後に余分なバイトがあるアーカイブは、拒否するか隔離する。
- 異常な Unicode-path 追加フィールドを使用している、またはコメントが一貫していない ZIP は、異なるツールが抽出したツリーで一致しない場合に疑わしいと扱う。
- 解析が元のバイト列の保存より重要であれば、サンドボックス内で抽出した後に厳格なパーサでアーカイブを再パッケージし、生成されたファイル一覧を元のメタデータと比較する。

これはパッケージエコシステムに限らない: 同じ曖昧性のクラスは、別の抽出器がアーカイブを処理する前に ZIP の内容を「覗き見」するメールゲートウェイ、静的スキャナ、カスタム取り込みパイプラインからペイロードを隠すことができる。

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
