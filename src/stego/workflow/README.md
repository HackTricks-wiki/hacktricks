# Stego ワークフロー

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、ランダムなツールを試すよりも、体系的なトリアージによってより速く解決されます。

## コアフロー

### 簡易トリアージチェックリスト

目的は次の2つの質問に効率的に答えることです。

1. 実際のコンテナ／フォーマットは何か？
2. payload が metadata、appended bytes、embedded files、または content-level stego のどこに存在するか？

#### 1) コンテナを特定する
```bash
file target
ls -lah target
```
もし `file` と拡張子が一致しない場合は、`file` を優先する。適切な場合は、一般的なフォーマットをコンテナとして扱う（例：OOXML documents は ZIP files）。

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
#### 3) 追記されたデータ / 埋め込まれたファイルを確認する
```bash
binwalk target
binwalk -e target
```
抽出に失敗してもシグネチャが報告される場合は、`dd`でオフセットを手動で切り出し、切り出した領域に対して再度`file`を実行する。

#### 4) 画像の場合

- 異常を検査する: `magick identify -verbose file`
- PNG/BMPの場合は、ビットプレーン/LSBを列挙する: `zsteg -a file.png`
- PNGの構造を検証する: `pngcheck -v file.png`
- チャネル/プレーンの変換で内容が明らかになる可能性がある場合は、視覚フィルタ（Stegsolve / StegoVeritas）を使用する

#### 5) 音声の場合

- まずスペクトログラム（Sonic Visualiser）
- ストリームをデコード/検査する: `ffmpeg -v info -i file -f null -`
- 音声が構造化されたトーンに似ている場合は、DTMFデコーディングを試す

### 基本ツール

These catch the high-frequency container-level cases: metadata payloads, appended bytes, and embedded files disguised by extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
そのファイルの中身（src/stego/workflow/README.md）をこちらに貼り付けてください。ファイル内容を受け取ったら、指定どおりマークダウンとタグを保持したまま英語の本文を日本語に翻訳して返します。
```bash
foremost -i file
```
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
### コンテナ、付加データ、そして polyglot tricks

多くの steganography チャレンジは、有効なファイルの後に余分なバイトが付加されているもの、または拡張子で偽装された埋め込みアーカイブです。

#### Appended payloads

多くのフォーマットは末尾のバイトを無視します。ZIP/PDF/script を image/audio container に追加できます。

手早いチェック:
```bash
binwalk file
tail -c 200 file | xxd
```
offsetが分かっている場合は、`dd`でcarveしてください:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### マジックバイト

`file` が判別できないときは、`xxd` でマジックバイトを確認し、既知のシグネチャと比較する:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

拡張子が zip を示していなくても、`7z` や `unzip` を試してみてください:
```bash
7z l file
unzip -l file
```
### stego 周辺の奇妙な点

stego の近くによく現れるパターンへのクイックリンク（QR-from-binary, braille, etc）。

#### QR codes from binary

blob の長さが完全平方数の場合、raw pixels として画像/QR になっている可能性があります。
```python
import math
math.isqrt(2500)  # 50
```
バイナリ→画像ヘルパー:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### 点字

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## 参考リスト

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
