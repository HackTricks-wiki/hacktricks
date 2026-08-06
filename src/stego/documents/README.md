# Esteganografia de Documentos

{{#include ../../banners/hacktricks-training.md}}

Documentos geralmente são apenas contêineres:

- PDF (arquivos incorporados, streams)
- Office OOXML (`.docx/.xlsx/.pptx` são ZIPs)
- Formatos legados RTF / OLE

## PDF

### Técnica

PDF é um contêiner estruturado com objetos, streams e arquivos incorporados opcionais. Em CTFs, geralmente é necessário:

- Extrair anexos incorporados
- Descompactar/achatar object streams para poder pesquisar o conteúdo
- Identificar objetos ocultos (JS, imagens incorporadas, streams incomuns)

### Verificações rápidas
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Então, pesquise dentro de `out.pdf` por objetos/strings suspeitos.

## Office OOXML

### Técnica

Trate OOXML como um grafo de relações entre ZIP + XML; os payloads geralmente ficam ocultos em mídias, relações ou partes customizadas incomuns.

Arquivos OOXML são contêineres ZIP. Isso significa que:

- O documento é uma árvore de diretórios de XML e assets.
- Os arquivos de relacionamento em `_rels/` podem apontar para recursos externos ou partes ocultas.
- Dados incorporados frequentemente ficam em `word/media/`, partes XML customizadas ou relações incomuns.

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
