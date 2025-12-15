# Dokument Steganografie

{{#include ../../banners/hacktricks-training.md}}

Dokumente is dikwels net houers:

- PDF (ingeslote lêers, strome)
- Office OOXML (`.docx/.xlsx/.pptx` is ZIP-lêers)
- RTF / OLE ouer formate

## PDF

### Tegniek

PDF is 'n gestruktureerde houer met objekte, strome en opsionele ingeslote lêers. In CTFs moet jy dikwels:

- Ekstraheer ingeslote aanhangsels
- Dekomprimeer/vlakmaak objekstrome sodat jy inhoud kan deursoek
- Identifiseer verborge objekte (JS, ingeslote beelde, vreemde strome)

### Vinnige kontroles
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Soek dan binne `out.pdf` na verdagte objekte/strings.

## Office OOXML

### Tegniek

Behandel OOXML as 'n ZIP + XML relationship graph; payloads skuil dikwels in media, relationships, of vreemde custom parts.

OOXML-lêers is ZIP-containers. Dit beteken:

- Die dokument is 'n gidsboom van XML en assets.
- Die `_rels/` relationship-lêers kan na eksterne hulpbronne of verborge dele wys.
- Ingeslote data bevind dikwels in `word/media/`, custom XML parts, of ongewone relationships.

### Vinnige kontroles
```bash
7z l file.docx
7z x file.docx -oout
```
Inspekteer dan:

- `word/document.xml`
- `word/_rels/` vir eksterne verhoudings
- ingeslote media in `word/media/`

{{#include ../../banners/hacktricks-training.md}}
