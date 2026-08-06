# Steganografija dokumenata

{{#include ../../banners/hacktricks-training.md}}

Dokumenti su često samo containers:

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` su ZIPs)
- RTF / OLE legacy formats

## PDF

### Technique

PDF je strukturirani container sa objects, streams i optional embedded files. U CTFs često treba da:

- Extract embedded attachments
- Decompress/flatten object streams kako biste mogli da pretražujete sadržaj
- Identify hidden objects (JS, embedded images, odd streams)

### Brze provere
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Then search inside `out.pdf` for suspicious objects/strings.

## Office OOXML

### Technique

Tretirajte OOXML kao ZIP + XML graf odnosa; payloads se često skrivaju u medijima, relationship datotekama ili neobičnim prilagođenim delovima.

OOXML datoteke su ZIP kontejneri. To znači:

- Dokument je stablo direktorijuma XML datoteka i resursa.
- `_rels/` relationship datoteke mogu upućivati na spoljne resurse ili skrivene delove.
- Ugrađeni podaci se često nalaze u `word/media/`, prilagođenim XML delovima ili neobičnim relationship datotekama.

### Brze provere
```bash
7z l file.docx
7z x file.docx -oout
```
Zatim pregledajte:

- `word/document.xml`
- `word/_rels/` za spoljne relacije
- ugrađene medije u `word/media/`


{{#include ../../banners/hacktricks-training.md}}
