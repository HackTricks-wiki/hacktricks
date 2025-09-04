# ZIPのトリック

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は**zipファイル**の診断、修復、パスワードクラッキングに不可欠です。主要なユーティリティは以下の通りです:

- **`unzip`**: zipファイルが展開できない理由を明らかにします。
- **`zipdetails -v`**: zipフォーマットのフィールドを詳細に解析します。
- **`zipinfo`**: 抽出せずにzipファイルの内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 破損したzipファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zipパスワードをブルートフォースで破るツール。およそ7文字までのパスワードに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) は、zipファイルの構造と標準に関する包括的な情報を提供します。

重要な点として、パスワード保護されたzipファイルは内部のファイル名やファイルサイズを**暗号化しない**ため、これはRARや7zが持つようなファイル名/サイズの暗号化を伴わないセキュリティ上の欠陥です。さらに、古いZipCrypto方式で暗号化されたzipは、圧縮ファイルの非暗号化コピーが利用可能な場合に**plaintext attack**（既知平文攻撃）に対して脆弱です。この攻撃は既知のコンテンツを利用してzipのパスワードを割るもので、詳細は[HackThisの記事](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)や[この学術論文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)で説明されています。しかし、**AES-256**で保護されたzipファイルはこの既知平文攻撃に対して免疫があるため、機密データには安全な暗号化方式を選ぶことが重要です。

---

## 改ざんされたZIPヘッダを使ったAPKの逆解析防止トリック

現代のAndroidマルウェアドロッパーは、APKを端末上でインストール可能なままにしつつ、壊れたZIPメタデータを使って静的ツール（jadx/apktool/unzip）を破壊します。最も一般的なトリックは次の通りです:

- ZIP General Purpose Bit Flag (GPBF) のビット0を立てて偽の暗号化を示す
- パーサを混乱させるために大きな/カスタムのExtraフィールドを悪用する
- 実際のアーティファクトを隠すためのファイル/ディレクトリ名の衝突（例: 実際の `classes.dex` の横に `classes.dex/` というディレクトリを置く）

### 1) 実際の暗号化なしの偽の暗号化（GPBF ビット0がセットされている）

症状:
- `jadx-gui` が次のようなエラーで失敗する:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` はコアAPKファイルに対してパスワードを求めますが、有効なAPKでは `classes*.dex`、`resources.arsc`、または `AndroidManifest.xml` が暗号化されることはありえません:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetailsでの検出:
```bash
zipdetails -v sample.apk | less
```
local および central headers の General Purpose Bit Flag を見てください。特徴的なのは、core エントリでさえ bit 0（Encryption）がセットされている値です：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APKがデバイス上でインストールおよび実行されるが、ツールに主要なエントリが「encrypted」と表示される場合、GPBFが改ざんされています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF の bit 0 をクリアすることで修正します。最小バイトパッチャー:
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
使い方:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
これでコアエントリに `General Purpose Flag  0000` が表示され、ツールは再び APK を解析します。

### 2) パーサを壊す大きな/カスタム Extra フィールド

攻撃者はヘッダに巨大な Extra フィールドや奇妙な ID を詰め込み、デコンパイラを誤作動させます。実際のサンプルでは、そこにカスタムマーカー（例: `JADXBLOCK` のような文字列）が埋め込まれていることがあります。

検査:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Examples observed: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- core エントリ（`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`）で Extra フィールドが異常に大きい場合にアラートを出す。
- それらのエントリで不明な Extra ID は疑わしいものとして扱う。

Practical mitigation: rebuilding the archive (e.g., re-zipping extracted files) strips malicious Extra fields. If tools refuse to extract due to fake encryption, first clear GPBF bit 0 as above, then repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実ファイルを隠す）

ZIPはファイル`X`とディレクトリ`X/`の両方を含めることができます。一部の抽出ツールやデコンパイラは混乱し、ディレクトリエントリで実際のファイルを上書きしたり隠してしまうことがあります。これは`classes.dex`のようなコアAPK名とエントリが衝突するケースで観測されています。

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
- APK のローカルヘッダで暗号化が示されている (GPBF bit 0 = 1) のにインストール/実行されているものを検出する。
- コアエントリの大きな/不明な Extra フィールドを検出する（`JADXBLOCK` のようなマーカーを探す）。
- パス衝突（`X` と `X/`）を、特に `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` に対して検出する。

---

## 参考資料

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
