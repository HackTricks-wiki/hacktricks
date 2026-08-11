# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** are very common in **CTFs**, **incident response**, and **malware staging** because they are **lossless**, **chunk-based**, and many tools will happily render them even when they contain **extra metadata**, **appended payloads**, or **partially corrupted chunks**.

PNGを単なる画像ではなく、**container**として扱いましょう。

## Quick triage

LSB stegoに進む前に、まずcontainerレベルのチェックを行います。bit-plane/LSB workflowについては、[専用の画像stegoページ](../../../stego/images/README.md)を確認してください。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
確認すべき有用な項目:

- `tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` などの **予期しない ancillary chunks**
- **CRC errors** または不正な chunk lengths
- `IEND` の後にある **追加データ**
- **複数の `IEND` markers**、またはファイルの正式な終端後に復元可能な `IDAT` fragments
- 有効な PNG **でありながら**、carve すると ZIP/PDF/script のようにも見えるファイル

通常、最小限の有効な構造は次のとおりです:

- `IHDR`（必ず最初）
- `IDAT`（1つ以上の連続した chunks）
- `IEND`（必ず最後）

## `IEND` 後の trailing data

PNG で最も signal の高い artefact の1つは、**最後の `IEND` chunk の後に追加された data** です。多くの decoders はこれを無視するため、次の用途に有効です:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Buggy editors** によって失われた古い image data の復元

簡易検出:
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
また、PNG または carve した trailer に対して、汎用アーカイブパーサーを直接試してください:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style の crop/redact された screenshot の復元

非常に実用的な最近の PNG forensic trick は、screenshot editor が古いファイルを先に **truncating** せずに PNG を **overwritten** したかどうかを確認することです。そのような場合、**previous image** の bytes が `IEND` の後に残っている可能性があり、追加の `IDAT` data を部分的に reconstruct できることもあります。

これは **aCropalypse**（Google Pixel Markup）と、関連する **Windows Snipping Tool** の issue によって広く知られるようになりました。<sup>[[3]](#references)</sup> 実際に、「cropped」または「redacted」された PNG に古い trailing data がまだ含まれている場合、元の screenshot の一部を recover できる可能性があります。<sup>[[1]](#references)</sup>

実用的な workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
深い分析を強く正当化する兆候:

- `pngcheck` が **`IEND` の後に追加データがある** と報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の末尾より後に **追加の `IDAT` チャンク** が見つかる
- スクリーンショットの取得元が、既知の影響を受けたデバイス/エディターである

このような場合は、redaction を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** にかけてください。

## 実際に重要な Chunk abuse

調査で最も興味深い PNG チャンクは、明白な画像チャンクではなく、通常は **text**、**metadata**、または **payload bytes** を保持できるチャンクです:

- `tEXt` / `zTXt` / `iTXt` – text metadata と compressed text
- `eXIf` – PNG 内の EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images の palette data。ただし、payload-smuggling scenarios でも有用です。<sup>[[2]](#references)</sup>

次のコマンドでダンプします:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks 内に offensive payload を persistence させる場合（例: 一部の PHP image transformation を経ても残る **PLTE**、**IDAT**、**tEXt** tricks）については、より詳しい upload-focused notes をこちらで確認してください:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 破損した PNG の修復

整合性の確認と正確な破損箇所の特定には、**pngcheck** が今でも最初に使うツールとして最適です。

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

ファイルが意図的に malicious なのではなく破損している場合、CTF や lab work では、bad headers、誤った IHDR values、CRC problems、malformed chunk layouts などの一般的な問題の修正に **PCRT** が役立ちます。

疑わしい trailer data を含む PNG を、表示される image を維持したまま **sanitize** することが目的なら、ExifTool で trailer を明示的に削除できます。
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
重要な証拠を扱う場合は、必ず**コピー**上で作業し、修復を試みる前に元データのハッシュを保持してください。

## References

- [1] [aCropalypseの悪用：切り詰められたPNGの復元](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG内の永続的なPHP payload：画像にPHPコードを注入し、そこに保持する方法](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
