# Esteganografia em documentos

{{#include ../../banners/hacktricks-training.md}}

Muitos formatos de documentos são contêineres estruturados, em vez de fluxos de dados únicos:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (arquivos incorporados, streams)
- Office OOXML (`.docx/.xlsx/.pptx` são ZIPs)
- Documentos RTF e OLE/Compound File Binary legados. O RTF armazena control words e grupos em um formato orientado a texto, enquanto os arquivos compostos OLE expõem uma hierarquia semelhante a um sistema de arquivos, composta por objetos de armazenamento e streams; ambos exigem uma inspeção específica do formato para identificar dados ocultos ou incorporados.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Técnica

Os arquivos PDF podem conter objetos, streams, JavaScript e arquivos incorporados. Durante a análise, as tarefas comuns incluem:

- Extrair anexos incorporados.
- Expandir object streams para facilitar a inspeção dos objetos.
- Identificar JavaScript, imagens incorporadas e streams incomuns.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Verificações rápidas
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
A combinação `--qdf --object-streams=disable` produz uma representação mais legível e remove os object streams, o que facilita a inspeção manual.<sup>[[2]](#references)</sup> Em seguida, pesquise `out.pdf` em busca de objetos e strings suspeitos.

## Office OOXML

### Técnica

Os arquivos Office Open XML (`.docx`, `.xlsx` e `.pptx`) usam Open Packaging Conventions: um pacote baseado em ZIP composto por parts e arquivos XML de relacionamento.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Trate o pacote como um grafo de relacionamentos e inspecione media, relacionamentos externos e custom parts incomuns.

Na prática:

- O documento é uma árvore de diretórios de XML e assets.
- Os arquivos de relacionamento em `_rels/` podem apontar para recursos externos ou parts ocultas.
- Dados incorporados frequentemente ficam em `word/media/`, custom XML parts ou relacionamentos incomuns.

### Verificações rápidas
```bash
7z l file.docx
7z x file.docx -oout
```
Em seguida, inspecione:

- `word/document.xml`
- `word/_rels/` para relacionamentos externos
- mídia incorporada em `word/media/`

## References

- [1] [Manual do Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Documentação do qpdf - modo QDF e fluxos de objetos](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - fundamentos das Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - formatos de arquivo Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - introdução ao Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - referência da especificação RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
