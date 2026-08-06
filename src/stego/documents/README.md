# Steganografia ya Hati

{{#include ../../banners/hacktricks-training.md}}

Hati mara nyingi huwa ni kontena tu:

- PDF (faili zilizopachikwa, streams)
- Office OOXML (`.docx/.xlsx/.pptx` ni ZIPs)
- RTF / OLE legacy formats

## PDF

### Mbinu

PDF ni kontena lenye muundo linalojumuisha objects, streams, na faili zilizopachikwa kwa hiari. Katika CTFs mara nyingi unahitaji:

- Kutoa attachments zilizopachikwa
- Kudecompress/kuflatten object streams ili uweze kutafuta maudhui
- Kutambua objects zilizofichwa (JS, images zilizopachikwa, streams zisizo za kawaida)

### Ukaguzi wa haraka
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Kisha tafuta ndani ya `out.pdf` kwa ajili ya objects/strings zinazotia shaka.

## Office OOXML

### Technique

Chukulia OOXML kama ZIP + XML relationship graph; payloads mara nyingi hujificha kwenye media, relationships, au custom parts zisizo za kawaida.

Faili za OOXML ni ZIP containers. Hii inamaanisha:

- Hati ni directory tree ya XML na assets.
- Faili za relationships za `_rels/` zinaweza kuelekeza kwenye rasilimali za nje au parts zilizofichwa.
- Data iliyopachikwa mara nyingi hupatikana kwenye `word/media/`, custom XML parts, au relationships zisizo za kawaida.

### Ukaguzi wa haraka
```bash
7z l file.docx
7z x file.docx -oout
```
Kisha kagua:

- `word/document.xml`
- `word/_rels/` kwa external relationships
- media iliyopachikwa katika `word/media/`


{{#include ../../banners/hacktricks-training.md}}
