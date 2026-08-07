# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、ランダムにツールを試すよりも、体系的な triage によって迅速に解決できます。

## 基本的なフロー

### Quick triage checklist

目標は、次の2つの質問に効率よく答えることです。

1. 実際の container/format は何か？
2. payload は metadata、追加された bytes、埋め込まれた files、または content-level stego のどこにあるか？

#### 1) Identify the container
```bash
file target
ls -lah target
```
`file` と拡張子が一致しない場合は、`file` を信頼します。適切な場合は、一般的な形式をコンテナとして扱います（例：OOXML ドキュメントは ZIP ファイルです）。

#### 2) メタデータと明らかな文字列を探す
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
複数のエンコーディングを試す：
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) 追加データ / 埋め込まれたファイルを確認する
```bash
binwalk target
binwalk -e target
```
抽出に失敗しても signatures が報告される場合は、`dd` でオフセットを手動で carve し、carve した領域に対して `file` を再実行します。

#### 4) 画像の場合

- 異常を検査: `magick identify -verbose file`
- PNG/BMP の場合、bit-plane/LSB を列挙: `zsteg -a file.png`
- PNG 構造を検証: `pngcheck -v file.png`
- channel/plane の変換によってコンテンツが明らかになる可能性がある場合は、visual filters（Stegsolve / StegoVeritas）を使用

#### 5) 音声の場合

- まず spectrogram を確認（Sonic Visualiser）
- stream を decode/検査: `ffmpeg -v info -i file -f null -`
- 音声が structured tones に似ている場合は、DTMF decoding を試す

### 基本ツール

これらは、高頻度で発生する container-level のケース（metadata payload、末尾に追加された bytes、拡張子によって偽装された embedded files）を検出します。<sup>[[1]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
リポジトリ: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
リポジトリ: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### ファイル / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### コンテナ、付加データ、polyglot tricks

多くのステガノグラフィ challenge では、有効なファイルの後ろに追加されたバイトや、拡張子を偽装した埋め込み archive が使われます。

#### 付加された payload

多くの format は末尾のバイトを無視します。ZIP/PDF/script を image/audio container に追加できます。

高速チェック:
```bash
binwalk file
tail -c 200 file | xxd
```
オフセットがわかっている場合は、`dd`でcarveします:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

`file` が判別できない場合は、`xxd` で magic bytes を確認し、既知のシグネチャと比較します:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

拡張子が zip だと示していなくても、`7z` と `unzip` を試してください：
```bash
7z l file
unzip -l file
```
### Near-stego oddities

stego の周辺で定期的に見られるパターン（binary からの QR、点字など）へのクイックリンク。

#### binary からの QR codes

blob の長さが完全平方数の場合、画像や QR の raw pixels である可能性があります。
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### 点字

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 参考文献

- [1] [DominicBreuker/stego-toolkit - Docker image with the most popular steganography tools bundled together](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
