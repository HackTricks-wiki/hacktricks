# Dokument-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Dokumente is dikwels bloot houers:

- PDF (ingebedde lêers, strome)
- Office OOXML (`.docx/.xlsx/.pptx` is ZIPs)
- RTF / OLE legacy-formate

## PDF

### Tegniek

PDF is ’n gestruktureerde houer met objekte, strome en opsionele ingebedde lêers. In CTFs moet jy dikwels:

- Ingebedde aanhegsels onttrek
- Objekstrome dekomprimeer/platmaak sodat jy inhoud kan soek
- Versteekte objekte identifiseer (JS, ingebedde beelde, vreemde strome)

### Vinnige kontroles
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Soek dan binne `out.pdf` vir verdagte objekte/stringe.

## Office OOXML

### Tegniek

Behandel OOXML as ’n ZIP + XML relationship graph; payloads versteek dikwels in media, relationships of vreemde custom parts.

OOXML-lêers is ZIP-containers. Dit beteken:

- Die dokument is ’n directory tree van XML en assets.
- Die `_rels/` relationship files kan na eksterne hulpbronne of versteekte parts wys.
- Embedded data is dikwels in `word/media/`, custom XML parts of ongewone relationships.

### Vinnige kontroles
```bash
7z l file.docx
7z x file.docx -oout
```
Inspekteer dan:

- `word/document.xml`
- `word/_rels/` vir eksterne verhoudings
- ingebedde media in `word/media/`


{{#include ../../banners/hacktricks-training.md}}
