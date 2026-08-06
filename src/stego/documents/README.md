# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Documents は多くの場合、単なるコンテナです:

- PDF（embedded files、streams）
- Office OOXML（`.docx/.xlsx/.pptx` は ZIP）
- RTF / OLE legacy formats

## PDF

### Technique

PDF は objects、streams、optional embedded files を含む structured container です。CTF では、次の作業が必要になることがよくあります:

- embedded attachments を抽出する
- content を検索できるように object streams を decompress/flatten する
- hidden objects（JS、embedded images、odd streams）を特定する

### Quick checks
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
次に、`out.pdf` 内を検索して suspicious な objects/strings を探します。

## Office OOXML

### Technique

OOXML を ZIP + XML relationship graph として扱います。payload は media、relationships、または通常とは異なる custom parts に隠されていることがよくあります。

OOXML ファイルは ZIP containers です。つまり:

- document は XML と assets の directory tree です。
- `_rels/` relationship files は external resources や hidden parts を指すことがあります。
- Embedded data は、`word/media/`、custom XML parts、または通常とは異なる relationships に存在することがよくあります。

### Quick checks
```bash
7z l file.docx
7z x file.docx -oout
```
次に確認します:

- `word/document.xml`
- 外部リレーションシップの `word/_rels/`
- `word/media/` 内の埋め込みメディア


{{#include ../../banners/hacktricks-training.md}}
