# ドキュメント・ステガノグラフィー

{{#include ../../banners/hacktricks-training.md}}

多くのドキュメント形式は、単一のデータストリームではなく、構造化されたコンテナです:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF（埋め込みファイル、ストリーム）
- Office OOXML（`.docx/.xlsx/.pptx` は ZIP）
- Legacy RTF および OLE/Compound File Binary ドキュメント。RTF はテキスト指向の形式で制御語とグループを保存し、OLE compound files はストレージオブジェクトとストリームからなるファイルシステムのような階層を公開します。いずれも、hidden または埋め込まれたデータを調査するには、形式固有の検査が必要です。<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF ファイルには、オブジェクト、ストリーム、JavaScript、埋め込みファイルを含めることができます。分析時の一般的な作業には、次のものがあります。

- 埋め込みアタッチメントの抽出。
- オブジェクトを検査しやすくするための、オブジェクトストリームの展開。
- JavaScript、埋め込み画像、通常とは異なるストリームの特定。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Quick checks
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
`--qdf --object-streams=disable` の組み合わせを使うと、より読みやすい形式で表示され、object streamsも削除されるため、手動での検査が容易になります。<sup>[[2]](#references)</sup> その後、`out.pdf` 内を検索して、疑わしいオブジェクトや文字列を探します。

## Office OOXML

### Technique

Office Open XML ファイル（`.docx`、`.xlsx`、`.pptx`）は、ZIP ベースのパッケージである Open Packaging Conventions を使用しており、parts と XML relationship files で構成されています。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> パッケージを relationship graph として扱い、media、external relationships、通常とは異なる custom parts を調査します。

実際には、次のようになっています。

- ドキュメントは XML と assets で構成されるディレクトリツリーです。
- `_rels/` の relationship files は、外部リソースや隠された parts を指すことがあります。
- Embedded data は、`word/media/`、custom XML parts、または通常とは異なる relationships に存在することがよくあります。

### Quick checks
```bash
7z l file.docx
7z x file.docx -oout
```
Then inspect:

- `word/document.xml`
- `word/_rels/` for external relationships
- embedded media in `word/media/`

## References

- [1] [Poppler pdfdetach マニュアル](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf ドキュメント - QDF mode と object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions の基礎](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format の概要](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification のリファレンス](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
