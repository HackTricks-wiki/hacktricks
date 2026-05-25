# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** は **CTFs**、**incident response**、および **malware staging** で非常に一般的です。というのも、**lossless** であり、**chunk-based** であり、多くのツールが **extra metadata**、**appended payloads**、または **partially corrupted chunks** を含んでいても問題なく表示するからです。

PNG は単なる画像ではなく、**container** として扱ってください。

## Quick triage

LSB stego に飛び込む前に、まず container-level のチェックを行ってください。bit-plane/LSB のワークフローについては、[the dedicated image stego page](../../../stego/images/README.md) を確認してください。
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
確認すべき有用なもの:

- `tEXt`、`zTXt`、`iTXt`、`eXIf`、`iCCP` などの**予期しない補助 chunk**
- **CRC エラー**または不正な chunk 長
- `IEND` の後ろの**追加データ**
- **複数の `IEND` マーカー**、または形式上の終了後にある復元可能な `IDAT` フラグメント
- 取り出したときに有効な PNG であり、かつ ZIP/PDF/script のようにも見えるファイル

最小の有効な構造は通常、次のとおり:

- `IHDR`（最初でなければならない）
- `IDAT`（1つ以上の連続する chunk）
- `IEND`（最後でなければならない）

## `IEND` の後ろの trailing data

PNG の中でも特にシグナルが強い artefact の1つは、**最後の `IEND` chunk の後ろに追加された data** です。多くの decoder はこれを無視するため、次の用途に有用です:

- **単純な stego / hidden payload**
- **PNG polyglots**
- **malware staging**
- **不具合のある editor から古い画像データを復元する**

簡単な検出:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
最終の `IEND` の後をすべて切り出したい場合は：
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
また、generic archive parsers をPNGそのもの、または carve した trailer に対して直接試してください:
```bash
7z l suspect.png
unzip -l suspect.png
```
## 切り抜き/伏せ字スクリーンショットのAcropalypse-style復元

最近のPNGフォレンジックで非常に実用的なトリックは、スクリーンショットエディタがPNGを保存する際に、先に古いファイルを**truncating**せずに**overwrote**していないかを確認することです。こうした場合、**previous image**のバイトが `IEND` の後に残ることがあり、さらに追加の `IDAT` データが部分的に再構築できることもあります。

これは **aCropalypse**（Google Pixel Markup）と、それに関連する **Windows Snipping Tool** の問題で広く知られるようになりました。実際には、「cropped」または「redacted」されたPNGに古い末尾データが残っていれば、元のスクリーンショットの一部を復元できる可能性があります。

実践的なワークフロー:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
深掘り分析を強く正当化する兆候:

- `pngcheck` が **`IEND` の後に追加データ** を報告する
- **複数の `IEND`** が見つかる
- 画像の見かけ上の終端の後に **余分な `IDAT` チャンク** が見つかる
- スクリーンショットの元が、影響を受けたことが知られているデバイス/エディタだった

これが起きたら、redaction を信頼できるものとして扱う前に、ファイルを **aCropalypse recovery tool** に通してください。

## 実務で重要なチャンクの悪用

調査で最も興味深い PNG チャンクは、たいてい明白な画像チャンクではなく、**text**、**metadata**、または **payload bytes** を運べるチャンクです:

- `tEXt` / `zTXt` / `iTXt` – text metadata と圧縮 text
- `eXIf` – PNG 内の EXIF データ
- `iCCP` – 埋め込み ICC profile
- `PLTE` – indexed images の palette data だが、payload-smuggling シナリオでも有用

以下でダンプします:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG チャンク内での offensive payload の永続化について（たとえば、**PLTE**、**IDAT**、または一部の PHP 画像変換を生き残る **tEXt** の trick など）は、より詳細なアップロード中心のノートをこちらで確認してください:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## 破損した PNG の修復

整合性の確認と、壊れている正確な箇所の特定には、**pngcheck** が今でも最良の最初のツールの一つです:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

ファイルが意図的に悪意あるものではなく、単に破損しているだけなら、**PCRT** は CTF やラボ作業で、壊れたヘッダー、誤った IHDR 値、CRC 問題、または不正なチャンク配置などの一般的な問題を修復するのに役立ちます。

PNG を **sanitize** したい、つまり表示画像を保ったまま suspicious な trailer data を含む PNG からそれを除去したい場合、ExifTool は trailer を明示的に削除できます:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
機密証拠については、必ず **コピー** で作業し、修復を試みる前に元データのハッシュを保持してください。

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
