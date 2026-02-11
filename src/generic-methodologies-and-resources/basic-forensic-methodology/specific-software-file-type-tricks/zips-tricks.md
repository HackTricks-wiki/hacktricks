# ZIPのトリック

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は、zip files の診断、修復、パスワードクラッキングに不可欠です。主なユーティリティは次の通りです:

- **`unzip`**: zip ファイルが展開できない理由を明らかにします。
- **`zipdetails -v`**: zip ファイル形式のフィールドを詳細に解析します。
- **`zipinfo`**: ファイルを抽出せずに zip の内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 破損した zip ファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip パスワードのブルートフォースクラッキング用ツール。およそ7文字程度までのパスワードに有効です。

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) は、zip ファイルの構造と標準に関する包括的な詳細を提供します。

重要なのは、パスワード保護された zip files は内部のファイル名やファイルサイズを**暗号化しない**点であり、これはこの情報を暗号化する RAR や 7z とは異なるセキュリティ上の欠陥です。さらに、古い ZipCrypto メソッドで暗号化された zip files は、圧縮されたファイルの暗号化されていないコピーが利用可能な場合に**plaintext attack**の脆弱性があります。この攻撃は既知の内容を利用して zip のパスワードを解読するもので、詳細は [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) や [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) に記載されています。しかし、**AES-256** で保護された zip files はこの plaintext attack に対して免疫があり、機密データに対して安全な暗号方式を選ぶ重要性を示しています。

---

## APKでのZIPヘッダー操作によるアンチリバース手法

Modern Android malware droppers は、APK をデバイス上でインストール可能なまま、破損した ZIP メタデータを利用して静的解析ツール（jadx/apktool/unzip）を壊す手法を使います。最も一般的なトリックは次のとおりです:

- ZIP General Purpose Bit Flag (GPBF) の bit 0 を立てての偽の暗号化
- パーサを混乱させるための大きな/カスタム Extra フィールドの悪用
- 実際のアーティファクトを隠すためのファイル/ディレクトリ名の衝突（例: 実体の `classes.dex` の隣に `classes.dex/` というディレクトリを置く）

### 1) 実際の暗号化を伴わない偽の暗号化（GPBF bit 0 がセット）

症状:
- `jadx-gui` が次のようなエラーで失敗する:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` が core APK ファイルに対してパスワードを要求する（ただし有効な APK は `classes*.dex`、`resources.arsc`、`AndroidManifest.xml` を暗号化できないはず）:

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
local and central headers の General Purpose Bit Flag を確認してください。特徴的な値は、core entries に対しても bit 0 がセットされている (Encryption) ことです:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ヒューリスティック: APKがデバイス上でインストールおよび実行されるが、コアエントリがツール上で "encrypted" と表示される場合、GPBFが改竄されています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで GPBF の bit 0 をクリアすることで修正します。最小バイトパッチャ:

<details>
<summary>最小限のGPBFビットクリアパッチャ</summary>
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
コアエントリに `General Purpose Flag  0000` が表示され、ツールは再び APK を解析できるはずです。

### 2) パーサを破壊する大きな/カスタム Extra フィールド

攻撃者はデコンパイラをトリップさせるために、ヘッダに過大な Extra フィールドや奇妙な ID を詰め込みます。実際のサンプルでは、`JADXBLOCK` のような文字列等のカスタムマーカーが埋め込まれていることがあります。

検査:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
観測された例: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR ヒューリスティクス:
- コアエントリ（`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`）の Extra fields が異常に大きい場合はアラートを出す。
- それらのエントリ上の不明な Extra IDs を疑わしいものとして扱う。

Practical mitigation: アーカイブを再構築する（例: 抽出したファイルを再-zipping/re-zipping）ことで悪意のある Extra fields を除去できる。ツールが偽の暗号化のために抽出を拒否する場合は、まず上記のように GPBF bit 0 をクリアし、その後再パッケージする:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (実際のアーティファクトを隠す)

A ZIP can contain both a file `X` and a directory `X/`. Some extractors and decompilers get confused and may overlay or hide the real file with a directory entry. This has been observed with entries colliding with core APK names like `classes.dex`.

Triage and safe extraction:
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
Blue-team 検出アイデア:
- ローカルヘッダが暗号化を示す (GPBF bit 0 = 1) のにインストール/実行される APK をフラグする。
- コアエントリ上の大きな／不明な Extra フィールド（`JADXBLOCK` のようなマーカーを探す）をフラグする。
- 特に `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` に対するパス衝突（`X` と `X/`）をフラグする。

---

## その他の悪意ある ZIP トリック (2024–2025)

### 連結された central directories (multi-EOCD evasion)

最近の phishing キャンペーンでは、1つの blob が実際には **two ZIP files concatenated** として配布されることがある。各ファイルはそれぞれ End of Central Directory (EOCD) + central directory を持つ。抽出ツールによって解析するディレクトリが異なる（7zip は最初のものを読み、WinRAR は最後のものを読み取る）ため、攻撃者は一部のツールでしか見えないペイロードを隠せる。これにより、最初のディレクトリのみを検査する基本的な mail gateway AV を回避できる。

**トリアージコマンド**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
EOCD が複数出現する場合や "data after payload" の警告がある場合は、blob を分割して各部分を検査してください:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

最近の "better zip bomb" は小さな **kernel**（高圧縮の DEFLATE ブロック）を生成し、overlapping local headers を通じて再利用します。各 central directory エントリは同じ圧縮データを指すため、アーカイブをネストせずに >28M:1 を超える比率を達成できます。central directory のサイズを信用するライブラリ（Python `zipfile`、Java `java.util.zip`、hardened build 前の Info-ZIP）は、ペタバイト単位の割り当てを強制される可能性があります。

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
**処理**
- ドライランで確認する: `zipdetails -v file.zip | grep -n "Rel Off"` と実行し、offset が厳密に増加して一意であることを確認する。
- 抽出前に、許容する合計展開サイズとエントリ数に上限を設ける（`zipdetails -t` またはカスタムパーサを使用）。
- 抽出が必須の場合は、CPUやディスクの制限を設定した cgroup/VM 内で行う（無制限の膨張によるクラッシュを回避）。

---

## 参考

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
