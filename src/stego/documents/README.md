# Dokument-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Dokumente sind oft nur Container:

- PDF (eingebettete Dateien, Streams)
- Office OOXML (`.docx/.xlsx/.pptx` sind ZIPs)
- RTF / OLE-Legacy-Formate

## PDF

### Technik

PDF ist ein strukturierter Container mit Objekten, Streams und optional eingebetteten Dateien. In CTFs musst du häufig:

- Eingebettete Anhänge extrahieren
- Objekt-Streams dekomprimieren/zusammenführen, damit du den Inhalt durchsuchen kannst
- Verborgene Objekte identifizieren (JS, eingebettete Bilder, ungewöhnliche Streams)

### Schnelle Prüfungen
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Dann durchsuche `out.pdf` nach verdächtigen Objekten/Strings.

## Office OOXML

### Technique

Behandle OOXML als ZIP- und XML-Relationship-Graph; Payloads verstecken sich häufig in Medien, Relationships oder ungewöhnlichen Custom Parts.

OOXML-Dateien sind ZIP-Container. Das bedeutet:

- Das Dokument ist ein Verzeichnisbaum aus XML und Assets.
- Die Relationship-Dateien in `_rels/` können auf externe Ressourcen oder versteckte Parts verweisen.
- Eingebettete Daten befinden sich häufig in `word/media/`, Custom-XML-Parts oder ungewöhnlichen Relationships.

### Schnelle Prüfungen
```bash
7z l file.docx
7z x file.docx -oout
```
Dann untersuche:

- `word/document.xml`
- `word/_rels/` auf externe Beziehungen
- eingebettete Medien in `word/media/`


{{#include ../../banners/hacktricks-training.md}}
