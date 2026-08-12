# Stego ワークフロー

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、ランダムなツールを試すよりも、体系的な triage によって迅速に解決できます。

## Core flow

### Quick triage checklist

目標は、次の2つの質問に効率的に答えることです。

1. 実際の container/format は何か？
2. payload は metadata、追加された bytes、embedded files、または content-level stego のどこにあるか？

#### 1) Identify the container
```bash
file target
ls -lah target
```
`file` と拡張子が一致しない場合は、サフィックスを信用せず、シグネチャを調査してください。`file` もヒューリスティックであり、不正な形式の入力や polyglot input によって誤判定されることがあります。必要に応じて、一般的な形式をコンテナとして扱ってください（たとえば、OOXML ドキュメントは ZIP パッケージです）。<sup>[[2]](#references)</sup>

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
#### 3) 付加データ / 埋め込みファイルを確認する
```bash
binwalk target
binwalk -e target
```
抽出に失敗したものの signatures が報告された場合は、`dd` でオフセットを手動で carve し、carve した領域に対して `file` を再実行します。

#### 4) 画像の場合

- 異常を調査します: `magick identify -verbose file`
- PNG/BMP の場合は、bit-plane/LSB を列挙します: `zsteg -a file.png`
- PNG 構造を検証します: `pngcheck -v file.png`
- channel/plane の変換でコンテンツが明らかになる可能性がある場合は、visual filters（Stegsolve / StegoVeritas）を使用します

#### 5) audio の場合

- 最初に spectrogram を確認します（Sonic Visualiser）
- streams を decode/inspect します: `ffmpeg -v info -i file -f null -`
- audio が構造化された tones に似ている場合は、DTMF decoding を試します

### 基本ツール

これらは、高頻度で発生する container-level のケース、つまり metadata payloads、appended bytes、拡張子を偽装した embedded files を検出します。<sup>[[1]](#references)[[3]](#references)</sup>

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
プロジェクトリポジトリ：`korczis/foremost`。<sup>[[4]](#references)</sup>

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
### Container、appended data、polyglot tricks

多くのsteganography challengeでは、有効なファイルの後ろに追加されたバイト列や、拡張子を偽装した埋め込みarchiveが使われます。

#### Appended payloads

多くの形式は末尾のバイト列を無視します。ZIP/PDF/scriptをimage/audio containerの末尾に追加できます。

簡易チェック:
```bash
binwalk file
tail -c 200 file | xxd
```
オフセットが分かっている場合は、`dd` で carve します:
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

拡張子が zip でなくても、`7z` と `unzip` を試してください：
```bash
7z l file
unzip -l file
```
### Near-stegoの奇妙な例

stegoの隣接領域で定期的に見られるパターンへのクイックリンク（バイナリからのQR、点字など）。

#### バイナリからのQRコード

blobの長さが完全平方数の場合、画像/QR用のraw pixelsである可能性があります。
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### 点字

- Branah Braille translator.<sup>[[6]](#references)</sup>

より幅広い steganography utilities と technique-specific resources については、同梱の stego-toolkit と 0xRick の curated list を参照してください。<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 最も人気のある steganography tools をまとめた Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography Resources](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
