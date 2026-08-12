# Dokument-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Viele Dokumentformate sind strukturierte Container und keine einzelnen Datenströme:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (eingebettete Dateien, Datenströme)
- Office OOXML (`.docx/.xlsx/.pptx` sind ZIPs)
- Legacy-RTF- und OLE/Compound-File-Binary-Dokumente. RTF speichert Steuerwörter und Gruppen in einem textorientierten Format, während OLE-Compound-Files eine dateisystemähnliche Hierarchie aus Speicherobjekten und Datenströmen bereitstellen; beide erfordern eine formatspezifische Untersuchung auf versteckte oder eingebettete Daten.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technik

PDF-Dateien können Objekte, Datenströme, JavaScript und eingebettete Dateien enthalten. Bei der Analyse gehören folgende Aufgaben zu den üblichen Vorgehensweisen:

- Eingebettete Anhänge extrahieren.
- Objektdatenströme erweitern, damit Objekte leichter untersucht werden können.
- JavaScript, eingebettete Bilder und ungewöhnliche Datenströme identifizieren.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Schnellprüfungen
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Die Kombination `--qdf --object-streams=disable` erzeugt eine besser lesbare Darstellung und entfernt object streams, was die manuelle Prüfung erleichtert.<sup>[[2]](#references)</sup> Durchsuche anschließend `out.pdf` nach verdächtigen Objekten und Zeichenfolgen.

## Office OOXML

### Technik

Office Open XML-Dateien (`.docx`, `.xlsx` und `.pptx`) verwenden Open Packaging Conventions: ein ZIP-basiertes Paket aus Teilen und XML relationship files.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Betrachte das Paket als relationship graph und untersuche Medien, externe Beziehungen und ungewöhnliche custom parts.

In der Praxis:

- Das Dokument ist ein Verzeichnisbaum aus XML und Assets.
- Die `_rels/`-relationship files können auf externe Ressourcen oder versteckte Teile verweisen.
- Eingebettete Daten befinden sich häufig in `word/media/`, custom XML parts oder ungewöhnlichen Beziehungen.

### Schnellprüfungen
```bash
7z l file.docx
7z x file.docx -oout
```
Untersuche anschließend:

- `word/document.xml`
- `word/_rels/` auf externe Beziehungen
- eingebettete Medien in `word/media/`

## References

- [1] [Poppler-Handbuch zu pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf-Dokumentation – QDF-Modus und Objekt-Streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn – Grundlagen der Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 – Office Open XML-Dateiformate](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications – Einführung in das Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications – Referenz zur RTF-Spezifikation](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
