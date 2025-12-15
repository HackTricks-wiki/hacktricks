# ドキュメントのステガノグラフィ

{{#include ../../banners/hacktricks-training.md}}

ドキュメントはしばしば単なるコンテナです：

- PDF（埋め込みファイル、ストリーム）
- Office OOXML (`.docx/.xlsx/.pptx` は ZIP です)
- RTF / OLE のレガシー形式

## PDF

### 手法

PDFはオブジェクト、ストリーム、オプションの埋め込みファイルを持つ構造化されたコンテナです。CTFsでは以下の操作がしばしば必要になります：

- 埋め込み添付ファイルを抽出する
- コンテンツを検索できるように、オブジェクトストリームを展開/フラット化する
- 隠されたオブジェクトを識別する（JS、埋め込み画像、異常なストリーム）

### クイックチェック
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
次に `out.pdf` の内部を検索して、疑わしいオブジェクトや文字列を探します。

## Office OOXML

### 手法

OOXML を ZIP + XML のリレーションシップ・グラフとして扱う。payloads はしばしばメディア、リレーションシップ、または奇妙なカスタムパーツに隠れる。

OOXML ファイルは ZIP コンテナです。つまり:

- ドキュメントは XML とアセットのディレクトリツリーになっている。
- `_rels/` の relationship ファイルは外部リソースや隠しパーツを指すことがある。
- 埋め込まれたデータは `word/media/`、カスタム XML パーツ、または異常なリレーションシップに存在することが多い。

### クイックチェック
```bash
7z l file.docx
7z x file.docx -oout
```
次に確認する:

- `word/document.xml`
- `word/_rels/`（外部リレーションシップ用）
- `word/media/` 内の埋め込みメディア

{{#include ../../banners/hacktricks-training.md}}
