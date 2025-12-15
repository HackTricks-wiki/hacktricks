# Esteganografia de Documentos

{{#include ../../banners/hacktricks-training.md}}

Documentos são frequentemente apenas contêineres:

- PDF (arquivos incorporados, streams)
- Office OOXML (`.docx/.xlsx/.pptx` são ZIPs)
- Formatos legados RTF / OLE

## PDF

### Técnica

PDF é um contêiner estruturado com objetos, streams e arquivos incorporados opcionais. Em CTFs, você frequentemente precisa:

- Extrair anexos incorporados
- Descomprimir/achatar streams de objetos para poder buscar o conteúdo
- Identificar objetos ocultos (JS, imagens incorporadas, streams estranhos)

### Verificações rápidas
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Em seguida, procure dentro de `out.pdf` por objetos/strings suspeitos.

## Office OOXML

### Técnica

Trate OOXML como um grafo de relacionamento ZIP + XML; payloads frequentemente se escondem em media, relacionamentos ou em partes customizadas incomuns.

OOXML files are ZIP containers. That means:

- O documento é uma estrutura de diretórios de XML e assets.
- Os arquivos `_rels/` de relacionamento podem apontar para recursos externos ou partes ocultas.
- Dados embutidos frequentemente ficam em `word/media/`, em partes XML customizadas, ou em relacionamentos incomuns.

### Verificações rápidas
```bash
7z l file.docx
7z x file.docx -oout
```
Em seguida, inspecione:

- `word/document.xml`
- `word/_rels/` para relações externas
- mídia incorporada em `word/media/`

{{#include ../../banners/hacktricks-training.md}}
