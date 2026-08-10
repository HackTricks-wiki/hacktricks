# PNG Tricks

**PNGファイル**は、**CTFs**、**インシデント対応**、**malware staging**で非常によく使われます。これは、**lossless**で**chunk-based**であり、**extra metadata**、**appended payloads**、**partially corrupted chunks**が含まれていても、多くのツールが問題なくレンダリングするためです。

PNGは単なる画像ではなく、**container**として扱ってください。

## 迅速なtriage

LSB stegoに進む前に、まずcontainer-levelのチェックを行います。bit-plane/LSB workflowについては、[専用のimage stegoページ](../../../stego/images/README.md)を確認してください。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
確認すべき有用な項目:

- `tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` などの **予期しない補助チャンク**
- **CRC エラー** または不正なチャンク長
- `IEND` の後にある **追加データ**
- **複数の `IEND` マーカー**、またはファイルの正式な終端後に復元可能な `IDAT` フラグメントがある
- 有効な PNG **でありながら**、carve すると ZIP/PDF/script のようにも見えるファイル

通常、最小限の有効な構造は次のとおりです:

- `IHDR` (最初でなければならない)
- `IDAT` (1 つ以上の連続したチャンク)
- `IEND` (最後でなければならない)

## `IEND` 後の末尾データ

PNG で最もシグナルの強い artefact の 1 つは、**最後の `IEND` チャンクの後に追加されたデータ**です。多くの decoder はこれを無視するため、次の用途に有用です:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- 不具合のある editor による **以前の画像データの復元**

簡単な検出方法:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
最後の `IEND` の後にあるすべてを `carve` したい場合:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
また、汎用アーカイブパーサーを PNG または切り出したトレーラーに対して直接試してください：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-styleでcrop/redactされたスクリーンショットの復元

非常に実用的な最近のPNG forensic trickは、スクリーンショット editorが古いファイルを先に**truncating**せずに、PNGを**overwriting**したかどうかを確認することです。そのような場合、**previous image**のbytesが`IEND`の後に残ることがあり、追加の`IDAT` dataを部分的にreconstructできる場合もあります。

これは**aCropalypse**（Google Pixel Markup）および関連する**Windows Snipping Tool** issueによって広く知られるようになりました。<sup>[[3]](#references)</sup> 実際に、"cropped"または"redacted"されたPNGに古いtrailing dataが残っていれば、元のスクリーンショットの一部をrecoverできる可能性があります。<sup>[[1]](#references)</sup>

実践的なworkflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
詳細な分析を強く正当化する兆候:

- `pngcheck` が **`IEND` の後に追加データがある** と報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の終端の後に **追加の `IDAT` チャンク** が見つかる
- スクリーンショットが、影響を受けたことが知られているデバイスやエディターから取得されたものである

このような場合は、redaction を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** にかけてください。

## 実際に重要なチャンク悪用

調査で最も興味深い PNG チャンクは、明白な画像チャンクではなく、通常、**テキスト**、**metadata**、または **payload bytes** を格納できるチャンクです:

- `tEXt` / `zTXt` / `iTXt` – テキスト metadata と圧縮テキスト
- `eXIf` – PNG 内の EXIF data
- `iCCP` – 埋め込まれた ICC profile
- `PLTE` – indexed image の palette data だが、payload-smuggling のシナリオでも有用。<sup>[[2]](#references)</sup>

次のコマンドで dump します:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG チャンク内の攻撃用 payload の永続化（例: 一部の PHP 画像変換を通過する **PLTE**、**IDAT**、**tEXt** の tricks）については、upload に重点を置いた、より詳細な notes をこちらで確認してください:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

整合性の確認と正確な破損箇所の特定には、**pngcheck** が今でも最初に使うツールとして最適です。

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

ファイルが意図的に悪意を持たされたものではなく破損している場合、**PCRT** は CTF や lab work で、壊れたヘッダー、誤った IHDR 値、CRC の問題、チャンクレイアウトの不正など、一般的な問題の修正に役立ちます。

目的が、表示される画像を維持しながら、不審な trailer data を含む PNG を**サニタイズ**することであれば、ExifTool で trailer を明示的に削除できます:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
機密性の高い証拠については、常に**コピー**上で作業し、修復を試みる前に元のファイルのハッシュを保持してください。

## References

- [1] [aCropalypseを悪用する: 切り詰められたPNGを復元する](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG内の永続的なPHP payload: 画像にPHP codeを注入し、そこに保持する方法](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
