# テキストステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

## 実践手順

プレーンテキストが予期しない動作をする場合は、元の証拠を保全し、コードポイントを調べ、コピーに対してのみ正規化してください。

### 手法

テキストステガノグラフィでは、見た目が同じ、または不可視の文字が頻繁に利用されます。

- ホモグリフ: 見た目が似ている異なる Unicode コードポイント（例: ラテン文字の `a` とキリル文字の `а`）<sup>[[1]](#references)</sup>
- ゼロ幅文字: 接合子、非接合子、ゼロ幅スペース<sup>[[2]](#references)</sup>
- 空白エンコーディング: スペースとタブの使い分け、行末のスペースパターン、意図的な行長パターン<sup>[[3]](#references)[[4]](#references)</sup>

さらに、信号性の高い事例:

- テキストの表示順を視覚的に入れ替える双方向制御文字<sup>[[1]](#references)</sup>
- 表示テキストをほぼ変えずに隠れた状態を持たせる異体字セレクターと結合文字<sup>[[1]](#references)</sup>

### デコード用ツール

- [Unicode ホモグリフおよびゼロ幅文字のエンコーダー／デコーダー](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### コードポイントの確認

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## CSS `unicode-range` チャネル

`@font-face` ルールを悪用して、`unicode-range: U+..` エントリにバイトをエンコードできます。コードポイントを抽出し、16進数の値を連結してデコードします:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

各宣言に複数の値が含まれている場合は、まずカンマで分割し、正規化します（`tr ',+' '\n'`）。形式に一貫性がない場合は、Pythonで解析してバイト列を出力できます。<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicodeセキュリティに関する考慮事項](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: ゼロ幅文字とHomoglyphsを使ったUnicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — SantaのWishlist](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debianマニュアル: `stegsnow`による空白Steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
