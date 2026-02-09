# ZIPs のトリック

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** は **zip files** を診断、修復、クラッキングするために不可欠です。主なユーティリティは次の通りです:

- **`unzip`**: zip ファイルが解凍できない理由を表示します。
- **`zipdetails -v`**: zip ファイル形式のフィールドを詳細に解析します。
- **`zipinfo`**: 抽出せずに zip の内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** と **`zip -FF input.zip --out output.zip`**: 破損した zip ファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip パスワードを総当たりで割るツールで、概ね7文字程度までのパスワードに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) は zip ファイルの構造と規格に関する詳細を網羅しています。

重要な点として、パスワード保護された zip files はファイル名やファイルサイズを暗号化しない（**do not encrypt filenames or file sizes**）ため、これは RAR や 7z のようにこれらを暗号化する形式にはないセキュリティ上の欠陥です。さらに、古い ZipCrypto メソッドで暗号化された zip files は、圧縮ファイルの平文コピーがあれば **plaintext attack** に対して脆弱です。この攻撃は既知の内容を利用して zip のパスワードを割るもので、詳細は [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) や [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) に記載されています。一方で、**AES-256** 暗号化された zip files はこの plaintext attack に対して耐性があるため、機密データには安全な暗号化方式を選ぶことが重要です。

---

## 操作された ZIP ヘッダを使った APKs のアンチリバーストリック

近年の Android マルウェアドロッパーは、不正な ZIP メタデータを利用して静的解析ツール（jadx/apktool/unzip）を壊しつつ、APK をデバイス上でインストール可能なままにします。よく使われるトリックは次の通りです:

- ZIP General Purpose Bit Flag (GPBF) の bit 0 を設定して偽の暗号化を行う
- 解析器を混乱させるために大きな/カスタムの Extra フィールドを悪用する
- 実際のアーティファクトを隠すためのファイル/ディレクトリ名の衝突（例: 実際の `classes.dex` の隣に `classes.dex/` というディレクトリを置く）

### 1) Fake encryption (GPBF bit 0 set) without real crypto

症状:
- `jadx-gui` が次のようなエラーで失敗する:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` が core APK ファイルに対してパスワードを要求する（ただし有効な APK は `classes*.dex`、`resources.arsc`、`AndroidManifest.xml` を暗号化できない）:

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
local と central ヘッダの General Purpose Bit Flag を見てください。コアのエントリでも判別の手がかりになるのは、bit 0 がセットされていること（Encryption）です：
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APK がデバイス上にインストールされ実行されるが、ツールから見るとコアエントリが "encrypted" に見える場合、GPBF が改ざんされています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF の bit 0 をクリアして修正します。最小バイトパッチャ:

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

使用方法:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
これでコアエントリに `General Purpose Flag  0000` が表示され、ツールは APK を再度解析できるはずです。

### 2) 解析器を壊す大きな/カスタム Extra フィールド

攻撃者は巨大な Extra フィールドや奇妙な ID をヘッダに詰め込み、デコンパイラを誤作動させます。実際のサンプルでは、カスタムマーカー（例: `JADXBLOCK` のような文字列）が埋め込まれていることがあります。

検査:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観察された例: `0xCAFE` ("Java Executable") や `0x414A` ("JA:") のような未知のIDが大きなペイロードを含んでいる。

DFIR ヒューリスティクス:
- コアエントリ（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）の Extra フィールドが異常に大きい場合はアラートする。
- それらのエントリの未知の Extra ID を疑わしいものとして扱う。

Practical mitigation: アーカイブを再構築する（例: 抽出したファイルを再圧縮する）ことで悪意のある Extra フィールドを除去できる。ツールが偽の暗号化のために抽出を拒否する場合は、まず上記のように GPBF bit 0 をクリアし、次に再パッケージする:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) ファイル/ディレクトリ名の衝突（実際のアーティファクトを隠す）

A ZIP can contain both a file `X` and a directory `X/`. 一部の抽出ツールやデコンパイラは混乱し、ディレクトリエントリで実際のファイルを上書きまたは隠してしまうことがあります。これは、`classes.dex` のようなコア APK 名とエントリが衝突する場合に観察されています。

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
プログラムによる検出後の付加:
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
Blue-team 検出アイデア:
- ローカルヘッダが暗号化を示す（GPBF bit 0 = 1）にも関わらずインストール/実行される APK を検出する。
- コアエントリの大きな/不明な Extra fields（`JADXBLOCK` のようなマーカーを探す）を検出する。
- `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` に対して特に `X` と `X/` のようなパス衝突を検出する。

---

## その他の悪意ある ZIP トリック (2024–2025)

### 結合された central directories (multi-EOCD 回避)

最近のフィッシングキャンペーンでは、実際には **two ZIP files concatenated** 単一の blob が配布されることがある。それぞれが独自の End of Central Directory (EOCD) と central directory を持つ。抽出ツールによって異なるディレクトリを解析する（7zip は最初のものを読み、WinRAR は最後のものを読む）ため、攻撃者は一部のツールでしか表示されないペイロードを隠すことができる。これは、最初のディレクトリのみを検査する基本的なメールゲートウェイ AV を回避することにもなる。

**トリアージコマンド**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
EOCDが複数ある場合、または "data after payload" の警告が表示される場合は、blobを分割して各部分を検査する:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

現代の「better zip bomb」は小さな **kernel**（高圧縮のDEFLATEブロック）を構築し、オーバーラップするローカルヘッダを介して再利用します。中央ディレクトリの各エントリは同じ圧縮データを指し、アーカイブをネストすることなく >28M:1 の比率を達成します。中央ディレクトリのサイズを信用するライブラリ（Python `zipfile`、Java `java.util.zip`、Info-ZIP（hardened builds導入前））はペタバイト単位の領域を割り当てさせられる可能性があります。

**簡易検出 (重複した LFH オフセット)**
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
**取り扱い**
- ドライランで走査を実行： `zipdetails -v file.zip | grep -n "Rel Off"` とし、オフセットが厳密に増加し一意であることを確認する。
- 抽出前に受け入れる合計非圧縮サイズとエントリ数に上限を設ける（`zipdetails -t` またはカスタムパーサ）。
- 抽出が必要な場合は、CPU とディスクの制限を設けた cgroup/VM 内で行う（無制限の膨張によるクラッシュを避ける）。

---

## 参考

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
