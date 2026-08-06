# Steganografia dokumentów

{{#include ../../banners/hacktricks-training.md}}

Dokumenty często są jedynie kontenerami:

- PDF (osadzone pliki, strumienie)
- Office OOXML (`.docx/.xlsx/.pptx` to ZIP-y)
- RTF / starsze formaty OLE

## PDF

### Technika

PDF to ustrukturyzowany kontener zawierający obiekty, strumienie i opcjonalnie osadzone pliki. W CTF-ach często trzeba:

- Wyodrębnić osadzone załączniki
- Rozpakować/spłaszczyć strumienie obiektów, aby można było przeszukać zawartość
- Zidentyfikować ukryte obiekty (JS, osadzone obrazy, nietypowe strumienie)

### Szybkie sprawdzenia
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Następnie wyszukaj w `out.pdf` podejrzane obiekty/ciągi znaków.

## Office OOXML

### Technika

Traktuj OOXML jako graf relacji ZIP + XML; payloady często ukrywają się w plikach multimedialnych, relacjach lub nietypowych częściach niestandardowych.

Pliki OOXML to kontenery ZIP. Oznacza to, że:

- Dokument jest drzewem katalogów zawierającym XML i zasoby.
- Pliki relacji `_rels/` mogą wskazywać zewnętrzne zasoby lub ukryte części.
- Osadzone dane często znajdują się w `word/media/`, niestandardowych częściach XML lub nietypowych relacjach.

### Szybkie kontrole
```bash
7z l file.docx
7z x file.docx -oout
```
Następnie sprawdź:

- `word/document.xml`
- `word/_rels/` pod kątem zewnętrznych relacji
- osadzone multimedia w `word/media/`


{{#include ../../banners/hacktricks-training.md}}
