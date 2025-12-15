# Steganografija dokumenata

{{#include ../../banners/hacktricks-training.md}}

Dokumenti su često samo kontejneri:

- PDF (ugrađene datoteke, streamovi)
- Office OOXML (`.docx/.xlsx/.pptx` su ZIP arhive)
- RTF / OLE zastareli formati

## PDF

### Tehnika

PDF je strukturisani kontejner sa objektima, streamovima i opcionalnim ugrađenim datotekama. U CTF-ovima često treba da:

- Izvući ugrađene priloge
- Dekomprimovati/izravnati streamove objekata kako biste mogli pretraživati sadržaj
- Identifikovati skrivene objekte (JS, ugrađene slike, neobični streamovi)

### Brze provere
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Zatim pretraži `out.pdf` za sumnjive objekte/stringove.

## Office OOXML

### Tehnika

Posmatraj OOXML kao ZIP + XML relationship graph; payloads se često kriju u media, relationships ili u neobičnim custom delovima.

OOXML datoteke su ZIP kontejneri. To znači:

- Dokument je direktorijumsko stablo XML-a i resursa.
- `_rels/` relationship fajlovi mogu ukazivati na spoljašnje resurse ili skrivene delove.
- Ugrađeni podaci se često nalaze u `word/media/`, prilagođenim XML delovima, ili neobičnim relationships.
```bash
7z l file.docx
7z x file.docx -oout
```
Zatim pregledajte:

- `word/document.xml`
- `word/_rels/` za eksterne relacije
- ugrađeni mediji u `word/media/`

{{#include ../../banners/hacktricks-training.md}}
