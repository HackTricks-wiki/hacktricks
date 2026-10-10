# Stego ワークフロー

{{#include ../../banners/hacktricks-training.md}}

ほとんどの stego 問題は、手当たり次第にツールを試すより、体系的にトリアージするほうが速く解決できます。

## 基本的な流れ

### 初動トリアージのチェックリスト

効率よく次の2つの疑問に答えることが目的です。

1. 実際のコンテナ/フォーマットは何か？
2. ペイロードはメタデータ、追加バイト列、埋め込みファイル、コンテンツレベルの stego のどこにあるか？

#### 1) コンテナを特定する

```bash
file target
ls -lah target
```

`file`の判定と拡張子が一致しない場合は、拡張子を鵜呑みにせず、シグネチャを調べてください。`file`もヒューリスティックなツールであり、不正な形式の入力やポリグロット入力によって判定を誤ることがあります。一般的な形式は、適切にコンテナとして扱ってください（たとえば、OOXMLドキュメントはZIPパッケージです）。<sup>[[2]](#references)</sup>

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

抽出に失敗してもシグネチャが報告された場合は、`dd`でオフセットを手動で切り出し、切り出した領域に対して`file`を再実行します。

#### 4) 画像の場合

- 異常を調査: `magick identify -verbose file`
- PNG/BMPの場合、bit-plane/LSBを列挙: `zsteg -a file.png`
- PNGの構造を検証: `pngcheck -v file.png`
- チャネル/プレーン変換でコンテンツが明らかになる可能性がある場合は、視覚フィルター（Stegsolve / StegoVeritas）を使用

#### 5) 音声の場合

- まずスペクトログラムを確認（Sonic Visualiser）
- ストリームをデコード/調査: `ffmpeg -v info -i file -f null -`
- 音声が構造化されたトーンに似ている場合は、DTMFデコードを試す

### 基本的なツール

これらのツールで、高頻度のコンテナレベルのケース（メタデータペイロード、末尾に追加されたバイト、拡張子を偽装した埋め込みファイル）を検出できます。<sup>[[1]](#references)[[3]](#references)</sup>

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

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### コンテナ、追記データ、ポリグロットのテクニック

ステガノグラフィの課題では、有効なファイルの後ろに余分なバイトが付いていたり、拡張子を偽装したアーカイブが埋め込まれていたりすることがよくあります。

#### 追記されたペイロード

多くの形式では末尾のバイトが無視されます。ZIP/PDF/scriptを画像や音声のコンテナに追記できます。

簡単なチェック:

```bash
binwalk file
tail -c 200 file | xxd
```

オフセットが分かっている場合は、`dd`でデータを切り出します:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

`file`コマンドで判別できない場合は、`xxd`でmagic bytesを確認し、既知のシグネチャと比較します。

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

拡張子が zip でなくても、`7z` と `unzip` を試してください:

```bash
7z l file
unzip -l file
```

### stego周辺の奇妙なもの

stegoの近くによく現れるパターン（バイナリから生成されたQRコード、点字など）へのクイックリンク。

#### バイナリから生成されたQRコード

blobの長さが完全平方数なら、画像やQRコードの生ピクセルデータかもしれません。

```python
import math
math.isqrt(2500)  # 50
```

バイナリ画像ヘルパー:

- dCodeのバイナリ画像ヘルパー。<sup>[[5]](#references)</sup>

#### 点字

- Branahの点字翻訳ツール。<sup>[[6]](#references)</sup>

ステガノグラフィツールや手法別のリソースを幅広く探すには、同梱のstego-toolkitと0xRickがまとめたリストを参照してください。<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - 人気のステガノグラフィツールをまとめたDockerイメージ](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Office Open XMLパッケージ規約](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — バイナリ画像](https://www.dcode.fr/binary-image)
- [6] [Branah — 点字翻訳ツール](https://www.branah.com/braille-translator)
- [7] [0xRick - ステガノグラフィのリソース](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
