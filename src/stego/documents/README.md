# 文書ステガノグラフィー

{{#include ../../banners/hacktricks-training.md}}

多くの文書形式は、単一のデータストリームではなく、構造化されたコンテナです:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF（埋め込みファイル、ストリーム）
- Office OOXML（`.docx/.xlsx/.pptx` は ZIP）
- レガシーな RTF および OLE/Compound File Binary 文書。RTF は制御語とグループをテキスト形式で格納します。一方、OLE 複合ファイルは、ファイルシステムのようなストレージオブジェクトとストリームの階層を公開します。どちらも、隠しデータや埋め込みデータを調べるには形式に応じた検査が必要です。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### 技法

PDF ファイルには、オブジェクト、ストリーム、JavaScript、埋め込みファイルを含めることができます。解析では、次のような作業が一般的です:

- 埋め込み添付ファイルの抽出。
- オブジェクトを調べやすくするためのオブジェクトストリームの展開。
- JavaScript、埋め込み画像、異常なストリームの特定。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### 簡易チェック

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

`--qdf --object-streams=disable` の組み合わせは、より読みやすい形式に変換し、object streamを削除するため、手動での調査が容易になります。<sup>[[2]](#references)</sup> 次に、`out.pdf` 内の不審なオブジェクトや文字列を検索します。

## Office OOXML

### 技法

Office Open XMLファイル（`.docx`、`.xlsx`、`.pptx`）は、パーツとXMLリレーションシップファイルで構成されるZIPベースのパッケージ、Open Packaging Conventionsを使用します。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> パッケージをリレーションシップグラフとして扱い、メディア、外部リレーションシップ、通常とは異なるカスタムパーツを調査します。

実際には:

- ドキュメントは、XMLとアセットからなるディレクトリツリーです。
- `_rels/` 内のリレーションシップファイルは、外部リソースや隠れたパーツを参照する場合があります。
- 埋め込みデータは、`word/media/`、カスタムXMLパーツ、または通常とは異なるリレーションシップ内に存在することがよくあります。

### 簡易チェック

```bash
7z l file.docx
7z x file.docx -oout
```

その後、以下を調べます：

- `word/document.xml`
- 外部リレーションシップが含まれる `word/_rels/`
- `word/media/` 内の埋め込みメディア

## References

- [1] [Poppler pdfdetach マニュアル](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf ドキュメント - QDF モードとオブジェクトストリーム](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions の基礎](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML ファイル形式](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format の概要](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF 仕様のリファレンス](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
