# Steganografia nei documenti

{{#include ../../banners/hacktricks-training.md}}

I documenti sono spesso solo contenitori:

- PDF (file incorporati, stream)
- Office OOXML (`.docx/.xlsx/.pptx` sono ZIP)
- Formati legacy RTF / OLE

## PDF

### Tecnica

PDF è un contenitore strutturato con oggetti, stream e file incorporati opzionali. Nei CTF è spesso necessario:

- Estrarre gli allegati incorporati
- Decomprimere/appiattire gli object stream per poter cercare il contenuto
- Identificare gli oggetti nascosti (JS, immagini incorporate, stream insoliti)

### Controlli rapidi
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Quindi cerca all'interno di `out.pdf` oggetti/stringhe sospetti.

## Office OOXML

### Tecnica

Tratta OOXML come un archivio ZIP + un grafo delle relazioni XML; i payload spesso si nascondono nei media, nelle relazioni o in parti personalizzate insolite.

I file OOXML sono contenitori ZIP. Ciò significa che:

- Il documento è un albero di directory contenente XML e asset.
- I file delle relazioni `_rels/` possono puntare a risorse esterne o a parti nascoste.
- I dati incorporati si trovano spesso in `word/media/`, nelle parti XML personalizzate o in relazioni insolite.

### Controlli rapidi
```bash
7z l file.docx
7z x file.docx -oout
```
Quindi esamina:

- `word/document.xml`
- `word/_rels/` per le relazioni esterne
- contenuti multimediali incorporati in `word/media/`


{{#include ../../banners/hacktricks-training.md}}
