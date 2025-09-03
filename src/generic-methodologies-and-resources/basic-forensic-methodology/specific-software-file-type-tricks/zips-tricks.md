# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は **zip files** の診断、修復、クラッキングに不可欠です。ここでは主要なユーティリティを示します:

- **`unzip`**: zip file が解凍されない理由を表示します。
- **`zipdetails -v`**: zip file format fields を詳細に解析します。
- **`zipinfo`**: 抽出せずに zip file の内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** と **`zip -FF input.zip --out output.zip`**: 破損した zip files の修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords のブルートフォース用ツール。おおよそ7文字までのパスワードに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) は zip files の構造と規格を包括的に説明しています。

重要なのは、パスワード保護された zip files はファイル名やファイルサイズを暗号化しないことです。これは、これらの情報を暗号化する RAR や 7z とは異なるセキュリティ上の欠陥です。さらに、古い ZipCrypto メソッドで暗号化された zip files は、圧縮済みファイルの未暗号化コピーが利用可能な場合に plaintext attack に対して脆弱です。この攻撃は既知の内容を利用して zip のパスワードを破るもので、詳細は [HackThis の記事](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) や [この学術論文](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) を参照してください。ただし、**AES-256** で保護された zip files はこの plaintext attack に対して耐性があり、機密データには安全な暗号方式を選ぶ重要性を示しています。

---

## 改変された ZIP ヘッダを利用した APK の逆解析防止トリック

Modern Android malware droppers は不正な ZIP メタデータを使って静的解析ツール（jadx/apktool/unzip など）を壊しつつ、デバイス上では APK をインストール可能にします。よく使われるトリックは次の通りです:

- ZIP General Purpose Bit Flag (GPBF) の bit 0 を立てて偽の暗号化を示す
- 大きな／カスタムの Extra fields を悪用してパーサを混乱させる
- ファイル／ディレクトリ名の衝突で実際のアーティファクトを隠す（例: 実際の `classes.dex` の横に `classes.dex/` というディレクトリを置く）

### 1) Fake encryption (GPBF bit 0 set) without real crypto

症状:
- `jadx-gui` が次のようなエラーで失敗する:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` が core APK ファイルに対してパスワードを要求する（ただし有効な APK は `classes*.dex`、`resources.arsc`、`AndroidManifest.xml` が暗号化されることはありえません）:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails による検出:
```bash
zipdetails -v sample.apk | less
```
local and central headers の General Purpose Bit Flag を見てください。特徴的な値は bit 0 がセットされていること（Encryption）で、core entries に対しても当てはまります:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APKがデバイスにインストールされ実行されるが、ツールから見るとコアエントリが "encrypted" のように見える場合、GPBFが改ざんされている。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF のビット0をクリアして修正する。最小限の byte-patcher:
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
使用法:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
コアエントリで `General Purpose Flag  0000` が表示され、ツールは再度 APK を解析します。

### 2) パーサを壊す大容量/カスタムのExtraフィールド

攻撃者はデコンパイラを混乱させるため、ヘッダに大きすぎるExtraフィールドや奇妙なIDを詰め込みます。実際には、そこにカスタムマーカー（例: `JADXBLOCK` のような文字列）が埋め込まれていることがあります。

解析:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観察例: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads。

DFIR heuristics:
- コアエントリ（`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`）の Extra fields が異常に大きい場合にアラートを上げる。
- それらのエントリにある不明な Extra ID を疑わしいものとして扱う。

Practical mitigation: アーカイブを再構築する（例: 抽出したファイルを再圧縮する）ことで悪意のある Extra fields を削除できる。ツールが偽の暗号化のため抽出を拒否する場合は、上記のようにまず GPBF bit 0 をクリアし、再パッケージする:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実ファイルを隠す）

ZIPはファイル `X` とディレクトリ `X/` の両方を含めることがあります。いくつかの抽出ツールやデコンパイラは混乱して、ディレクトリエントリで実ファイルを上書きまたは隠してしまうことがあります。これは `classes.dex` のようなコアAPK名とエントリが衝突するケースで観測されています。

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
Blue-team detection ideas:
- ローカルヘッダが暗号化を示している（GPBF bit 0 = 1）にもかかわらずインストール／実行されるAPKをフラグを立てる。
- コアエントリ上の大きい／不明な Extra fields をフラグする（`JADXBLOCK` のようなマーカーを探す）。
- `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` に関して、`X` と `X/` のようなパス衝突を特にフラグする。

---

## 参考資料

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
