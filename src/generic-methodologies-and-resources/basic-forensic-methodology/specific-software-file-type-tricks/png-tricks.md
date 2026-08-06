# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNGファイル**は、**可逆圧縮**であり、**チャンクベース**で、**追加のメタデータ**、**追加されたpayload**、または**部分的に破損したチャンク**を含んでいても多くのツールが問題なくレンダリングするため、**CTF**、**インシデントレスポンス**、**マルウェアのステージング**で非常によく使用されます。

PNGは単なる画像ではなく、**コンテナ**として扱ってください。

## Quick triage

LSB stegoに進む前に、まずコンテナレベルのチェックを行います。bit-plane/LSBワークフローについては、[専用の画像stegoページ](../../../stego/images/README.md)を確認してください。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
確認すべき有用な項目:

- `tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` などの**想定外の ancillary chunks**
- **CRC errors** または不正な chunk lengths
- **`IEND` の後にある追加データ**
- **複数の `IEND` markers**、またはファイルの正式な終端後に復元可能な `IDAT` fragments
- 有効な PNG **でありながら**、carve すると ZIP/PDF/script のようにも見えるファイル

通常、最小限の有効な構造は次のとおりです:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## `IEND` 後の trailing data

最も重要な PNG artefacts の1つは、**最後の `IEND` chunk の後に追加されたデータ**です。多くの decoders はこれを無視するため、以下の用途に有用です:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- バグのある editors からの**古い image data の復元**

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
最後の `IEND` の後にあるすべてを carve したい場合:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
また、PNG または切り出したトレーラーに対して、汎用アーカイブパーサーを直接試してください：
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-styleでcrop/redactされたscreenshotを復元する

非常に実用的な最近のPNG forensic trickは、screenshot editorが古いファイルを先に**truncating**せずにPNGを**overwritten**したか確認することです。このような場合、**previous image**のbytesが`IEND`の後に残っている可能性があり、追加の`IDAT` dataを部分的にreconstructできる場合もあります。

これは**aCropalypse**（Google Pixel Markup）および関連する**Windows Snipping Tool**のissueによって広く知られるようになりました。実際に、"cropped"または"redacted"されたPNGに古いtrailing dataが残っていれば、元のscreenshotの一部をrecoverできる可能性があります。<sup>[[1]](#references)</sup>

実際のworkflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
詳細な分析を強く検討すべき兆候：

- `pngcheck` が **`IEND` の後に追加データがある**と報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の末尾の後に **追加の `IDAT` chunks** が見つかる
- スクリーンショットが、影響を受けたことが知られているデバイスやエディタから取得された

この場合、redaction を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** にかけてください。

## 実際に重要な chunk abuse

調査で最も興味深い PNG chunks は、明白な画像用のものではなく、通常は **text**、**metadata**、または **payload bytes** を格納できる chunks です：

- `tEXt` / `zTXt` / `iTXt` – text metadata と compressed text
- `eXIf` – PNG 内の EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images の palette data。ただし、payload-smuggling scenarios でも有用<sup>[[2]](#references)</sup>

次のコマンドでダンプします：
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks（例: **PLTE**、**IDAT**、**tEXt**）内に offensive payload を永続化させる手法（いくつかの PHP image transformations を通過して残存するもの）については、より詳細な upload 関連の notes をこちらで確認してください<sup>[[2]](#references)</sup>:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 破損したPNGの修復

整合性を確認し、正確な破損箇所を特定するには、**pngcheck** が引き続き最初に使うツールとして最適です。

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

ファイルが意図的に malicious なのではなく破損している場合、CTF や lab work では、bad headers、誤った IHDR values、CRC problems、malformed chunk layouts などの一般的な問題を修正するために **PCRT** が役立ちます。

目的が、表示される画像を維持したまま suspicious trailer data を含む PNG を **sanitize** することであれば、ExifTool で trailer を明示的に削除できます。
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
機密性の高い証拠については、常に**コピー**を使って作業し、修復を試みる前に元データのハッシュを保持してください。

## 参考資料

- [1] [aCropalypseの悪用: 切り詰められたPNGの復元](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG内の永続的なPHP payload: 画像にPHP codeをinjectし、それを保持する方法](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
