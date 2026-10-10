# Dokumenten-Steganografie

{{#include ../../banners/hacktricks-training.md}}

Viele Dokumentformate sind strukturierte Container und keine einzelnen Datenströme:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (eingebettete Dateien, Streams)
- Office OOXML (`.docx/.xlsx/.pptx` sind ZIP-Dateien)
- Ältere RTF- und OLE/Compound-File-Binary-Dokumente. RTF speichert Steuerwörter und Gruppen in einem textorientierten Format, während OLE-Compound-Files eine dateisystemähnliche Hierarchie aus Speicherobjekten und Streams bereitstellen; beide erfordern eine formatspezifische Prüfung auf versteckte oder eingebettete Daten.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technik

PDF-Dateien können Objekte, Streams, JavaScript und eingebettete Dateien enthalten. Zu den üblichen Aufgaben bei der Analyse gehören:

- Eingebettete Anhänge extrahieren.
- Objekt-Streams erweitern, damit sich Objekte leichter untersuchen lassen.
- JavaScript, eingebettete Bilder und ungewöhnliche Streams identifizieren.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Schnellprüfungen

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Die Kombination `--qdf --object-streams=disable` erzeugt eine besser lesbare Darstellung und entfernt Objekt-Streams, was die manuelle Prüfung erleichtert.<sup>[[2]](#references)</sup> Durchsuche anschließend `out.pdf` nach verdächtigen Objekten und Zeichenfolgen.

## Office OOXML

### Technik

Office Open XML-Dateien (`.docx`, `.xlsx` und `.pptx`) verwenden Open Packaging Conventions: ein ZIP-basiertes Paket aus Teilen und XML-Beziehungsdateien.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Betrachte das Paket als Beziehungsgraph und prüfe Medien, externe Beziehungen und ungewöhnliche benutzerdefinierte Teile.

In der Praxis:

- Das Dokument ist ein Verzeichnisbaum aus XML-Dateien und Assets.
- Die Beziehungsdateien in `_rels/` können auf externe Ressourcen oder verborgene Teile verweisen.
- Eingebettete Daten befinden sich häufig in `word/media/`, benutzerdefinierten XML-Teilen oder ungewöhnlichen Beziehungen.

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

- [1] [Poppler-pdfdetach-Handbuch](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf-Dokumentation – QDF-Modus und Objekt-Streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn – Grundlagen der Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 – Office Open XML-Dateiformate](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications – Einführung in das Compound File Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications – Referenz zur RTF-Spezifikation](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
