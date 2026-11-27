# ZIPのテクニック

{{#include ../../../banners/hacktricks-training.md}}

**コマンドラインツール**は、**zipファイル**の診断、修復、パスワード解析に不可欠です。主なユーティリティは次のとおりです。<sup>[[1]](#references)</sup>

- **`unzip`**: zipファイルを展開できない理由を確認できます。
- **`zipdetails -v`**: zipファイル形式のフィールドを詳細に分析できます。<sup>[[3]](#references)</sup>
- **`zipinfo`**: 展開せずにzipファイルの内容を一覧表示します。
- **`zip -F input.zip --out output.zip`** および **`zip -FF input.zip --out output.zip`**: 破損したzipファイルの修復を試みます。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ZIPパスワードへの辞書攻撃やブルートフォース攻撃に使うツールです。実行可能性はパスワードの探索空間によって異なります。<sup>[[15]](#references)</sup>

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)には、zipファイルの構造と標準に関する包括的な情報が記載されています。<sup>[[4]](#references)</sup>

従来のパスワード保護されたZIPファイルでは、RARや7zがサポートするヘッダー暗号化モードとは異なり、通常、ファイル名とファイルサイズが見える状態です。ZipCryptoの既知平文攻撃で復元されるのは**内部暗号鍵**であり、必ずしも元のパスワードではありません。この鍵があれば、同じパスワードで暗号化されたエントリを復号できます。<sup>[[13]](#references)</sup> この攻撃には、**暗号化前**のストリームの既知バイトが必要です。格納形式のメンバーでは元のファイルのバイト列ですが、DEFLATE形式のメンバーでは圧縮後のバイト列となるため、圧縮出力を完全に再現する必要がある場合があります。<sup>[[13]](#references)[[14]](#references)</sup> 実践的な手順については、[Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack)を参照してください。暗号解析の背景については、[論文](https://math.ucr.edu/~mike/zipattacks.pdf)と[解説](https://www.hackthissite.org/articles/read/793)を参照してください。<sup>[[11]](#references)[[12]](#references)</sup> このZipCrypto攻撃は、AESで暗号化されたZIPエントリには適用できません。<sup>[[13]](#references)</sup>

---

## 操作されたZIPヘッダーを使ったAPKのアンチリバース手法

最新のAndroidマルウェアドロッパーは、不正なZIPメタデータを使って静的解析ツール（jadx/apktool/unzip）を妨害しつつ、端末へのAPKのインストールを可能にします。よく使われる手法は次のとおりです。<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag（GPBF）のbit 0を設定して、暗号化されているように見せかける
- 大きな、または独自のExtraフィールドを悪用してパーサーを混乱させる
- ファイル名とディレクトリ名を衝突させて実際の成果物を隠す（例: 実際の`classes.dex`の隣に`classes.dex/`という名前のディレクトリを置く）

### 1) 実際の暗号化なしで暗号化を偽装する（GPBF bit 0を設定）

症状:
- `jadx-gui`が次のようなエラーで失敗する:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip`は、有効なAPKでは暗号化されているはずのない`classes*.dex`、`resources.arsc`、または`AndroidManifest.xml`が含まれるコアAPKファイルに対して、パスワードを要求します。
  
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

ローカルヘッダーとセントラルヘッダーの General Purpose Bit Flag を確認してください。core entries であっても bit 0 がセット（Encryption）されているのが、手がかりとなる値です:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

ヒューリスティック: APKを端末にインストールして実行できるのに、ツール上で主要なエントリが「暗号化」されているように見える場合、GPBFが改ざんされています。

Local File Headers (LFH) と Central Directory (CD) の両方のエントリで、GPBF bit 0をクリアして修正します。最小限のバイトパッチャー:

<details>
<summary>GPBF bitをクリアする最小限のパッチャー</summary>

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

使用方法：

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

ビット 0 だけを変更します。たとえば、`0A09` は `0000` ではなく `0A08` になります。この最小限の patcher は raw bytes 内のヘッダーシグネチャをスキャンするため、ファイルデータ内にシグネチャに似たバイト列があると誤検出する可能性があります。出力を使用する前に、コピー上で作業し、エントリーの一覧とヘッダーを確認してください。<sup>[[4]](#references)</sup>

### 2) パーサーを破る大きな／カスタム Extra fields

攻撃者は、逆コンパイラーを誤作動させるために、サイズの大きすぎる Extra fields や奇妙な ID をヘッダーに詰め込みます。実際の環境では、カスタムマーカー（例：`JADXBLOCK` のような文字列）が埋め込まれていることがあります。

確認方法：

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

観測された例: `0xCAFE`（「Java Executable」）や `0x414A`（「JA:」）などの未知の ID が、大きなペイロードを持つケース。<sup>[[2]](#references)</sup>

DFIR のヒューリスティック:
- コアエントリ（`classes*.dex`、`AndroidManifest.xml`、`resources.arsc`）の Extra fields が異常に大きい場合は警告する。
- これらのエントリにある未知の Extra ID は疑わしいものとして扱う。

実用的な緩和策: アーカイブを再構築する（例: 抽出したファイルを再圧縮する）と、悪意のある Extra fields が取り除かれます。偽の暗号化が原因でツールが抽出を拒否する場合は、まず上記のように GPBF bit 0 をクリアし、その後再パッケージします:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) ファイル/ディレクトリ名の衝突（実際のアーティファクトを隠す）

ZIPにはファイル `X` とディレクトリ `X/` の両方を含めることができます。一部の展開ツールや逆コンパイラは混乱し、ディレクトリエントリで実際のファイルを上書きしたり隠したりすることがあります。`classes.dex` のようなAPKの主要な名前と衝突するエントリで、これが確認されています。

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

Programmatic detection の修正後：

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
- ローカルヘッダーで暗号化がマークされている（GPBF bit 0 = 1）にもかかわらず、インストール／実行される APK を検出する。
- コアエントリに大きな／未知の Extra fields がある場合に検出する（`JADXBLOCK` などのマーカーを探す）。
- `AndroidManifest.xml`、`resources.arsc`、`classes*.dex` について、パスの衝突（`X` と `X/`）を検出する。

---

## その他の悪意ある ZIP tricks（2024–2026）

### 連結された central directories（複数 EOCD による回避）

2024 年のフィッシングキャンペーンで、攻撃者は実際には **2 つの ZIP files を連結した**単一の blob を送りつけました。それぞれに独自の End of Central Directory（EOCD）レコードと central directory があり、展開ツールによって異なるディレクトリが解析されました（7-Zip は最初のものを、WinRAR は最後のものを読み込みました）。これにより、攻撃者は一部のツールにしか表示されない payloads を隠すことができ、1 つのディレクトリだけを検査する scanner はもう一方の archive を見逃す可能性があります。<sup>[[5]](#references)[[6]](#references)</sup>

**トリアージ用コマンド**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

複数のEOCDが見つかる場合、または「payloadの後にデータがある」という警告が表示される場合は、blobを分割して各部分を調べます：

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs（非再帰型）

Quoted-overlap ZIP bombs は、小さな **kernel**（高圧縮の DEFLATE block）を構築し、重複するエントリ間で再利用します。Full-overlap 型は複数の central-directory エントリを1つの local header に向ける一方、quoted-overlap 型は DEFLATE stream 内に local header を引用します。公開された構成では、nested archive を使わずに 28M:1 を超える圧縮率を実現しています。<sup>[[7]](#references)</sup>

**簡易検出（LFH オフセットの重複）**

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

**対処**
- dry-runで走査します: `zipdetails -v file.zip | grep -n "Local Header Offset"` を実行し、参照されるローカルヘッダーオフセットと圧縮データ範囲を比較します。オフセットの重複は、完全に重複する亜種の兆候です。<sup>[[7]](#references)[[8]](#references)</sup>
- 展開前に、パーサーで許容する展開後の合計サイズとエントリー数に上限を設けます。`zipinfo -t file.zip` は合計を報告しますが、安全上限は強制しません。<sup>[[8]](#references)</sup>
- 展開が必要な場合は、CPUとディスクに制限を設けたcgroup/VM内で行います（無制限の展開によるクラッシュを避けます）。<sup>[[8]](#references)</sup>

---

### ローカルヘッダーとセントラルディレクトリのパーサー間の解釈の違い

近年の差分パーサー研究により、ZIPの曖昧さは最新のツールチェーンでも依然として悪用可能であることが示されました。基本的な考え方は単純です。一部のソフトウェアは**Local File Header (LFH)**を信頼し、別のソフトウェアは**Central Directory (CD)**を信頼するため、同じアーカイブでも、ツールによって異なるファイル名、パス、コメント、オフセット、またはエントリーセットを提示できます。<sup>[[9]](#references)</sup>

実践的な攻撃用途:
- アップロードフィルター、AVの事前スキャン、またはパッケージ検証ツールにはCD内の無害なファイルを認識させ、展開ツールには異なるLFHの名前/パスを使用させます。
- 重複する名前、一方の構造にのみ存在するエントリー、または曖昧なUnicodeパスメタデータ（たとえば、Info-ZIP Unicode Path Extra Field `0x7075`）を悪用し、異なるパーサーに異なるツリーを再構成させます。
- これをパストラバーサルと組み合わせ、展開時に「無害な」アーカイブの表示をファイル書き込みプリミティブに変えます。展開側については、[Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)を参照してください。

DFIRトリアージ:

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

次の内容で補完してください：

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

ヒューリスティクス:
- セキュリティ上重要な取り込み処理では、LFH/CD 名の不一致、重複ファイル名、複数の EOCD レコード、または最後の EOCD の後にバイト列が続くアーカイブを拒否するか、隔離します。<sup>[[9]](#references)[[10]](#references)</sup>
- 異なるツールで展開後のツリーが一致しない場合、通常とは異なる Unicode パスの追加フィールドや、一貫性のないコメントを含む ZIP は疑わしいものとして扱います。<sup>[[4]](#references)[[9]](#references)</sup>
- 元のバイト列の保持より分析を優先する場合は、サンドボックス内で展開した後、厳格なパーサーを使ってアーカイブを再パッケージし、生成されたファイル一覧と元のメタデータを比較します。

これはパッケージのエコシステムに限った話ではありません。同じ曖昧さを利用して、メールゲートウェイ、静的スキャナー、カスタム取り込みパイプラインからペイロードを隠せる可能性があります。これらは ZIP の内容を先に「覗き見」し、その後、別の展開ツールでアーカイブを処理します。<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF フォレンジック・フィールドガイド (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – 多段階ドロッパー (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP ファイル形式仕様 (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [ZIP アーカイブの柔軟な構造を悪用し、マルウェアを検知されないように隠す (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [ハッカーが新たな ZIP ファイル攻撃でマルウェアを隠す — 連結された ZIP 中央ディレクトリ](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [より優れた zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Zip Bomb の理解: 重複/引用重複カーネルの構築](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [私の ZIP はあなたの ZIP ではない: ZIP パーサー間の意味的なギャップの特定と悪用 (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Python パッケージインストーラーに対する ZIP パーサー混乱攻撃の防止](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [既知平文を削減した ZIP 攻撃 (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: 現実的な Web ミッション、レベル 15 (既知平文 ZIP 攻撃)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack の使い方](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack の既知平文チュートリアル](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip リポジトリ](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
