# Steganografia dei documenti

{{#include ../../banners/hacktricks-training.md}}

I documenti sono spesso solo contenitori:

- PDF (file incorporati, stream)
- Office OOXML (`.docx/.xlsx/.pptx` sono ZIP)
- Formati legacy RTF / OLE

## PDF

### Tecnica

Il PDF è un contenitore strutturato con oggetti, stream e file incorporati opzionali. Nei CTFs spesso è necessario:

- Estrarre allegati incorporati
- Decomprimere/appiattire gli stream degli oggetti in modo da poter cercare il contenuto
- Identificare oggetti nascosti (JS, immagini incorporate, stream anomali)

### Controlli rapidi
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Poi cerca all'interno di `out.pdf` oggetti/stringhe sospette.

## Office OOXML

### Tecnica

Tratta OOXML come un grafo di relazioni ZIP + XML; i payload spesso si nascondono in media, relazioni o parti custom insolite.

OOXML files are ZIP containers. That means:

- The document is a directory tree of XML and assets.
- The `_rels/` relationship files can point to external resources or hidden parts.
- Embedded data frequently lives in `word/media/`, custom XML parts, or unusual relationships.

### Controlli rapidi
```bash
7z l file.docx
7z x file.docx -oout
```
Quindi ispeziona:

- `word/document.xml`
- `word/_rels/` per le relazioni esterne
- media incorporati in `word/media/`

{{#include ../../banners/hacktricks-training.md}}
