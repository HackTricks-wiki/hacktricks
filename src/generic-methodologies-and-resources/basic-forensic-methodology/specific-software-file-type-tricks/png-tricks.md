# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNGファイル**は、**可逆圧縮**で、**チャンクベース**であり、**追加のメタデータ**、**末尾に追加されたペイロード**、または**一部が破損したチャンク**を含んでいても、多くのツールで問題なく表示できるため、**CTF**、**インシデント対応**、**マルウェアのステージング**でよく使われます。

PNGは単なる画像ではなく、**コンテナ**として扱いましょう。

## 初動トリアージ

LSBステガノグラフィに取りかかる前に、まずコンテナレベルのチェックを行いましょう。ビットプレーン/LSBのワークフローについては、[専用の画像ステガノグラフィのページ](../../../stego/images/)を確認してください。

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

確認すべき項目:

- **予期しない補助チャンク**（`tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` など）
- **CRC エラー**または不正なチャンク長
- **`IEND` の後にある追加データ**
- **複数の `IEND` マーカー**、またはファイルの正式な終端後に復元可能な `IDAT` フラグメントがないか
- 有効な PNG であり、**かつ** carve すると ZIP/PDF/スクリプトのようにも見えるファイル

通常、最小限の有効な構造は次のとおりです:

- `IHDR`（先頭でなければならない）
- `IDAT`（1 つ以上の連続したチャンク）
- `IEND`（末尾でなければならない）

## `IEND` の後にある末尾データ

PNG で特に重要なアーティファクトの 1 つは、**最後の `IEND` チャンクの後に追加されたデータ**です。多くのデコーダーはこれを無視するため、次の用途に使われます:

- **単純な stego / 隠しペイロード**
- **PNG polyglot**
- **マルウェアのステージング**
- バグのあるエディターからの**古い画像データの復元**

簡単な検出方法:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

`IEND` のバイト列を検索するだけでは手がかりにしかなりません。同じバイト列がチャンクデータや偽造されたトレーラーに含まれる可能性があるためです。確実にカービングするには、PNG シグネチャから長さ付きチャンクをたどり、構造上最初の `IEND` で停止します。[以下のチャンクウォーカー](#extract-ancillary-chunk-payloads) はトレーラーも保存します。<sup>[[6]](#references)</sup>

汎用アーカイブパーサーを PNG やカービングしたトレーラーに直接適用する方法も試してください。

```bash
7z l suspect.png
unzip -l suspect.png
```

## Acropalypse風のトリミング／墨消し済みスクリーンショットの復元

実用性の高い最近のPNGフォレンジック手法として、スクリーンショット編集ツールが古いファイルを先に**切り詰めずに**PNGを**上書き**していないかを確認します。その場合、`IEND`の後に**以前の画像**のバイト列が残っていることがあり、追加の`IDAT`データを部分的に復元できる場合もあります。

これは**aCropalypse**（Google Pixel Markup）と、関連する**Windows Snipping Tool**の問題によって広く知られるようになりました。<sup>[[3]](#references)</sup> 実際、「トリミング済み」または「墨消し済み」のPNGに古い末尾データが残っていれば、元のスクリーンショットの一部を復元できる可能性があります。<sup>[[1]](#references)</sup>

実用的な手順：

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

深掘り分析を強く正当化する兆候:

- `pngcheck` が **`IEND` の後に追加データがある**と報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の終端より後に **余分な `IDAT` チャンク** が見つかる
- スクリーンショットが、影響を受けたことが知られているデバイス／エディターから取得された

このような場合、編集による隠蔽を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** にかけてください。

## 実際に重要なチャンク悪用

調査で最も興味深い PNG チャンクは、通常、明白な画像チャンクではなく、**テキスト**、**メタデータ**、または **ペイロードバイト**を含められるチャンクです。

- `tEXt` / `zTXt` / `iTXt` – テキストメタデータと圧縮テキスト
- `eXIf` – PNG 内の EXIF データ
- `iCCP` – 埋め込み ICC プロファイル
- `PLTE` – インデックスカラー画像のパレットデータ。ペイロードの隠蔽にも利用できる。<sup>[[2]](#references)</sup>

次のコマンドでダンプします:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

PNGチャンク（たとえば **PLTE**、**IDAT**、**tEXt** を使う手法）内での攻撃用payloadの永続化については、一部のPHP画像変換後も残る場合があります。詳しくは、アップロードに特化したこちらのノートを確認してください:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 補助チャンクのpayloadを抽出する

攻撃者は、`IEND` の前にある**未知の補助チャンク**に任意のバイト列を配置できます。通常のPNGデコーダーは未知の補助チャンクを無視できますが、画像をバイト列として取得するスクリプトはpayloadを読み取り、利用できます。PNGを開くだけでは実行されません。<sup>[[4]](#references)[[6]](#references)</sup> 元の研究では、圧縮・暗号化されたカスタムチャンクが実証されました。<sup>[[4]](#references)</sup> 後のブラウザーの例では、抽出したバイト列をHTMLやダウンロードに利用していました。<sup>[[5]](#references)</sup>

チャンクタイプの1文字目が小文字なら *補助チャンク*、2文字目が小文字なら *プライベート* です。たとえば、`paMP` はプライベートですが、`pAMP` はデモ用に作られたものであるにもかかわらず、パブリック名前空間を使用します。<sup>[[4]](#references)[[6]](#references)</sup> チャンクは `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)` の形式で、CRCの対象はtypeとdataです。圧縮された `IDAT` データ内でチャンク名をgrepするのではなく、この構造を解析してください。以下のウォーカーは境界とCRCを検証し、補助payloadを生バイト列として書き出します。また、構造上の `IEND` より後にあるバイト列は `png-trailer.bin` に書き込みます。<sup>[[6]](#references)</sup>

<details>
<summary>補助チャンクとPNGトレーラーを切り出す</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

切り出したバイト列を `file`、`strings`、`binwalk` で調べ、実際に圧縮されている場合にのみ展開します。<sup>[[4]](#references)</sup> 再エンコードによって carrier が取り除かれる可能性があるため、これに頼る前にアップロードしたバイト列と取得したバイト列を比較してください。<sup>[[2]](#references)[[6]](#references)</sup>

## 破損したPNGの修復

整合性の確認と、破損箇所の特定には、**pngcheck** が今も最初に試すツールとして有力です。

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

意図的な悪意あるファイルではなく、単に破損しているファイルの場合、**PCRT** は CTF やラボ作業で、ヘッダーの破損、不正な IHDR 値、CRC の問題、不正なチャンク配置など、よくある問題を修正するのに役立ちます。

不審なトレーラーデータを含む PNG を、表示される画像を保持したまま**サニタイズ**することが目的なら、ExifTool を使ってトレーラーを明示的に削除できます。

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

機密性の高い証拠を扱う場合は、修復を試みる前に必ず**コピー**を作成し、元のファイルのハッシュを保存してください。



## References

- [1] [aCropalypseの悪用：切り詰められたPNGの復元](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG内の永続的なPHP payload：画像にPHPコードを注入し、そこに保持する方法](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [補助チャンクは機密情報を格納するのに最適な場所](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [有効な補助チャンクを使用してエンドポイントにデータを密かに持ち込む](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG) 仕様（第3版）](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
