# Stego ワークフロー

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、手当たり次第にツールを試すよりも、体系的な triage によって迅速に解決できます。

## 基本フロー

### Quick triage checklist

効率よく次の2つの質問に答えることが目標です。

1. 実際のコンテナ/format は何か？
2. payload は metadata、追加された bytes、埋め込まれた files、または content-level stego のどこにあるか？

#### 1) コンテナを特定する
```bash
file target
ls -lah target
```
`file`と拡張子が一致しない場合は、拡張子を信頼せず、シグネチャを調査してください。`file`もヒューリスティックなツールであり、壊れた入力やpolyglot入力によって誤判定することがあります。必要に応じて、一般的な形式をコンテナとして扱ってください（たとえば、OOXMLドキュメントはZIPパッケージです）。<sup>[[2]](#references)</sup>

#### 2) メタデータと明らかな文字列を探す
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
複数のエンコーディングを試す:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 追記データ / 埋め込みファイルを確認する
```bash
binwalk target
binwalk -e target
```
抽出に失敗しても signatures が報告される場合は、`dd` でオフセットを手動で carve し、carve した領域に対して `file` を再実行します。

#### 4) 画像の場合

- 異常を調査: `magick identify -verbose file`
- PNG/BMP の場合、bit-plane/LSB を列挙: `zsteg -a file.png`
- PNG 構造を検証: `pngcheck -v file.png`
- channel/plane の変換によって内容が明らかになる可能性がある場合は、視覚フィルター（Stegsolve / StegoVeritas）を使用

#### 5) audio の場合

- まず spectrogram を確認（Sonic Visualiser）
- stream を decode/検査: `ffmpeg -v info -i file -f null -`
- audio が構造化された tone に似ている場合は、DTMF decoding を試す

### 基本ツール

これらは、高頻度で発生する container レベルのケース（metadata payload、追加された bytes、拡張子を偽装した embedded file）を検出します。<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
プロジェクトリポジトリ: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### ファイル / 文字列
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### コンテナ、追加データ、ポリグロットのテクニック

多くのステガノグラフィーの challenge では、有効なファイルの後ろに追加されたバイトや、拡張子を偽装した埋め込みアーカイブが使われます。

#### 追加された payload

多くの形式は末尾のバイトを無視します。ZIP/PDF/script を画像や音声のコンテナに追加できます。

簡単な確認方法:
```bash
binwalk file
tail -c 200 file | xxd
```
オフセットが分かっている場合は、`dd` で carve します：
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

`file` が判別できない場合は、`xxd` で magic bytes を探し、既知のシグネチャと比較します:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

拡張子が zip でなくても、`7z` と `unzip` を試してください:
```bash
7z l file
unzip -l file
```
### Near-stegoの奇妙なパターン

stegoの近辺で定期的に現れるパターンへのクイックリンク（バイナリからのQR、点字など）。

#### バイナリからのQRコード

blobの長さが完全平方数の場合、画像やQRのraw pixelsである可能性があります。
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### 点字

- Branah 点字翻訳ツール.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 最も一般的なsteganography toolsをまとめたDocker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 オープンパッケージング規約](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — バイナリ画像](https://www.dcode.fr/binary-image)
- [6] [Branah — 点字翻訳ツール](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
