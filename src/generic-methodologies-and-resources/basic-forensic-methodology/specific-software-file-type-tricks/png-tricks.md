# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** は **CTF**、**incident response**、および **malware staging** で非常に一般的です。これは、**lossless** で **chunk-based** であり、多くのツールが **extra metadata**、**appended payloads**、または **partially corrupted chunks** を含んでいても、問題なくレンダリングするためです。

PNG を単なる画像としてではなく、**container** として扱ってください。

## Quick triage

LSB stego に進む前に、まず container-level のチェックを行ってください。bit-plane/LSB ワークフローについては、[the dedicated image stego page](../../../stego/images/README.md) を確認してください。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
調べるべき有用なもの:

- `tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` などの**予期しない ancillary chunks**
- **CRC errors** または不正な chunk lengths
- **`IEND` の後の追加データ**
- **複数の `IEND` マーカー**、または正式なファイル終端の後に回収可能な `IDAT` fragments
- carving したときに、PNG として有効で、**かつ** ZIP/PDF/script のようにも見えるファイル

最小限の有効な構造は通常、次のとおりです:

- `IHDR`（最初でなければならない）
- `IDAT`（1つ以上の連続した chunks）
- `IEND`（最後でなければならない）

## `IEND` の後の trailing data

PNG の最もシグナルの高い artefacts の1つは、**最終 `IEND` chunk の後に追加された data** です。多くの decoder はこれを無視するため、次の用途に有用です:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **バグのある editor から古い image data を復元する**

簡易検出:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
最終の`IEND`の後ろをすべて切り出したい場合:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
また、PNG または carve された trailer に対して generic archive parser を直接試してください:
```bash
7z l suspect.png
unzip -l suspect.png
```
## クロップ/マスキングされたスクリーンショットの Acropalypse-style 復元

最近の非常に実用的な PNG フォレンジックのトリックは、スクリーンショットエディタが PNG を **上書き** したときに、古いファイルを先に **truncating** していなかったかを確認することです。そうした場合、**前の画像** のバイトが `IEND` の後に残ることがあり、場合によっては追加の `IDAT` データを部分的に復元できます。

これは **aCropalypse**（Google Pixel Markup）と、関連する **Windows Snipping Tool** の問題で広く知られるようになりました。実際には、「cropped」または「redacted」された PNG に古い末尾データがまだ含まれているなら、元のスクリーンショットの一部を復元できる可能性があります。

実用的なワークフロー:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
深い分析を強く正当化する兆候:

- `pngcheck` が **`IEND` の後に追加データ** を報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の終了後に **追加の `IDAT` chunk** がある
- そのスクリーンショットが、影響を受けたことで知られるデバイス/エディタから来ている

これが起きたら、redaction を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** に通すこと。

## 実務で重要な chunk abuse

調査で最も興味深い PNG chunk は、たいてい目立つ画像用のものではなく、**text**、**metadata**、または **payload bytes** を運べる chunk です:

- `tEXt` / `zTXt` / `iTXt` – text metadata と圧縮 text
- `eXIf` – PNG 内の EXIF data
- `iCCP` – 埋め込み ICC profile
- `PLTE` – indexed images の palette data だが、payload-smuggling シナリオでも有用

次でダンプする:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNGチャンク内で offensive payload を永続化する場合（たとえば、いくつかの PHP 画像変換をすり抜ける **PLTE**、**IDAT**、または **tEXt** のトリック）については、より詳しい upload-focused の注意点をこちらで確認してください:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 壊れた PNG の修復

整合性の確認と、壊れている箇所の正確な特定には、**pngcheck** は今でも最初に使うべき最良のツールのひとつです:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

ファイルが意図的な悪意ではなく破損している場合、**PCRT** は CTF や lab 作業で、bad headers、wrong IHDR values、CRC problems、malformed chunk layouts などの一般的な問題を修復するのに役立ちます。

目的が、表示される画像を保ったまま suspicious trailer data を含む PNG を **sanitize** することなら、ExifTool で trailer を明示的に削除できます:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
機密証拠については、修復を試みる前に必ず**コピー**で作業し、元のハッシュを保持してください。

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
