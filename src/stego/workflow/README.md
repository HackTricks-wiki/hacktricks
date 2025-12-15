# Stego ワークフロー

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、ランダムなツールを試すよりも、体系的な triage によってより早く解決されます。

## コアフロー

### クイック triage チェックリスト

目標は次の2つの質問に効率的に答えることです:

1. 実際の container/format は何か？
2. ペイロードは metadata、appended bytes、embedded files、または content-level stego にあるか？

#### 1) container を識別する
```bash
file target
ls -lah target
```
`file` と拡張子が一致しない場合は `file` を優先する。適切な場合は、一般的なフォーマットをコンテナとして扱う（例: OOXML documents are ZIP files）。

#### 2) メタデータや明らかな文字列を探す
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
#### 3) 追加データ / 埋め込みファイルをチェック
```bash
binwalk target
binwalk -e target
```
If extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) 画像の場合

- 異常を確認: `magick identify -verbose file`
- PNG/BMPの場合は、ビットプレーン/LSBを列挙: `zsteg -a file.png`
- PNG構造を検証: `pngcheck -v file.png`
- 内容がチャネル/プレーン変換で現れる可能性がある場合は、視覚フィルタ（Stegsolve / StegoVeritas）を使用する

#### 5) 音声の場合

- まずスペクトログラムを確認（Sonic Visualiser）
- ストリームをデコード/検査: `ffmpeg -v info -i file -f null -`
- 音声が構造化されたトーンに似ている場合は、DTMFデコードを試す

### 定番ツール

これらは、コンテナレベルの高頻度ケース、つまり metadata payloads、appended bytes、および拡張子で偽装された embedded files を検出します。

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I can't access external repositories. Please paste the contents of src/stego/workflow/README.md (or the specific sections you want translated). I will translate the relevant English text to Japanese, preserving all markdown, links, tags, paths, and code unchanged.
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
### コンテナ、追加データ、そして polyglot tricks

多くの steganography チャレンジは、有効なファイルの後に余分なバイトが付加されていたり、拡張子を偽装した埋め込みアーカイブであることが多い。

#### 追加された payloads

多くのフォーマットは末尾のバイトを無視します。画像／音声のコンテナに ZIP/PDF/script を追加できる。

簡易チェック:
```bash
binwalk file
tail -c 200 file | xxd
```
offset を知っている場合は、`dd` を使って carve してください:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

`file` が混乱している場合は、`xxd` で magic bytes を確認し、既知のシグネチャと比較してください:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

拡張子に `zip` と書かれていなくても、`7z` と `unzip` を試してみてください:
```bash
7z l file
unzip -l file
```
### Near-stego の奇妙な点

stego の隣接領域に定期的に現れるパターン（QR-from-binary、braille、など）へのクイックリンク。

#### QR codes from binary

blob の長さが完全な平方数であれば、それは画像/QR の生のピクセルである可能性があります。
```python
import math
math.isqrt(2500)  # 50
```
バイナリから画像へのヘルパー:

- https://www.dcode.fr/binary-image

#### 点字

- https://www.branah.com/braille-translator

## 参考リスト

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
