# Dokument Steganography

{{#include ../../banners/hacktricks-training.md}}

Dokumenty są często tylko kontenerami:

- PDF (osadzone pliki, strumienie)
- Office OOXML (`.docx/.xlsx/.pptx` są ZIPami)
- RTF / OLE — przestarzałe formaty

## PDF

### Technika

PDF to ustrukturyzowany kontener z obiektami, strumieniami i opcjonalnymi osadzonymi plikami. W CTFs często trzeba:

- Wyodrębnić osadzone załączniki
- Zdekompresować/spłaszczyć strumienie obiektów, aby móc przeszukiwać zawartość
- Zidentyfikować ukryte obiekty (JS, osadzone obrazy, nietypowe strumienie)

### Szybkie kontrole
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Następnie przeszukaj plik `out.pdf` w poszukiwaniu podejrzanych obiektów/ciągów.

## Office OOXML

### Technika

Traktuj OOXML jako graf zależności ZIP + XML; payloads często ukrywają się w mediach, relacjach lub w nietypowych częściach niestandardowych.

OOXML files are ZIP containers. That means:

- The document is a directory tree of XML and assets.
- The `_rels/` relationship files can point to external resources or hidden parts.
- Embedded data frequently lives in `word/media/`, custom XML parts, or unusual relationships.

### Szybkie sprawdzenia
```bash
7z l file.docx
7z x file.docx -oout
```
Następnie sprawdź:

- `word/document.xml`
- `word/_rels/` dla zewnętrznych relacji
- osadzone multimedia w `word/media/`

{{#include ../../banners/hacktricks-training.md}}
