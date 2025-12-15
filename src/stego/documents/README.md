# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Dokumente sind oft nur Container:

- PDF (eingebettete Dateien, Streams)
- Office OOXML (`.docx/.xlsx/.pptx` sind ZIPs)
- RTF / OLE Legacy-Formate

## PDF

### Technik

PDF ist ein strukturiertes Containerformat mit Objekten, Streams und optional eingebetteten Dateien. In CTFs musst du häufig:

- Eingebettete Anhänge extrahieren
- Objekt-Streams dekomprimieren/flatten, damit du Inhalte durchsuchen kannst
- Versteckte Objekte identifizieren (JS, eingebettete Bilder, ungewöhnliche Streams)

### Schnellchecks
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Suche dann in `out.pdf` nach verdächtigen Objekten/Strings.

## Office OOXML

### Technik

Betrachte OOXML als einen ZIP + XML relationship graph; payloads verbergen sich oft in media, relationships oder ungewöhnlichen custom parts.

OOXML-Dateien sind ZIP-Container. Das bedeutet:

- Das Dokument ist ein Verzeichnisbaum aus XML und assets.
- Die `_rels/` relationship-Dateien können auf externe Ressourcen oder versteckte Teile verweisen.
- Eingebettete Daten befinden sich häufig in `word/media/`, in custom XML parts oder in ungewöhnlichen relationships.

### Schnellchecks
```bash
7z l file.docx
7z x file.docx -oout
```
Untersuche anschließend:

- `word/document.xml`
- `word/_rels/` für externe Beziehungen
- eingebettete Medien in `word/media/`

{{#include ../../banners/hacktricks-training.md}}
