# PDF-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

**Für weitere Details siehe:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Das PDF-Format ist bekannt für seine Komplexität und das Potenzial, Daten zu verbergen, was es zu einem Schwerpunkt für CTF-Forensik-Herausforderungen macht. Es kombiniert Elemente im Klartext mit binären Objekten, die komprimiert oder verschlüsselt sein können, und kann Skripte in Sprachen wie JavaScript oder Flash enthalten. Um die PDF-Struktur zu verstehen, kann man auf Didier Stevens' [einführendes Material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) zurückgreifen oder Werkzeuge wie einen Texteditor oder einen PDF-spezifischen Editor wie Origami verwenden.

Für eine eingehende Untersuchung oder Manipulation von PDFs stehen Werkzeuge wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Versteckte Daten innerhalb von PDFs könnten verborgen sein in:

- Unsichtbaren Ebenen
- XMP-Metadatenformat von Adobe
- Inkrementellen Generationen
- Texten in der gleichen Farbe wie der Hintergrund
- Texten hinter Bildern oder überlappenden Bildern
- Nicht angezeigten Kommentaren

Für eine benutzerdefinierte PDF-Analyse können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) verwendet werden, um maßgeschneiderte Parsing-Skripte zu erstellen. Darüber hinaus ist das Potenzial von PDFs zur Speicherung versteckter Daten so groß, dass Ressourcen wie der NSA-Leitfaden zu PDF-Risiken und Gegenmaßnahmen, obwohl nicht mehr an seinem ursprünglichen Standort gehostet, weiterhin wertvolle Einblicke bieten. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [PDF-Format-Tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini können weitere Lektüre zu diesem Thema bieten.

## Häufige bösartige Konstrukte

Angreifer missbrauchen oft spezifische PDF-Objekte und Aktionen, die automatisch ausgeführt werden, wenn das Dokument geöffnet oder damit interagiert wird. Schlüsselwörter, nach denen man suchen sollte:

* **/OpenAction, /AA** – automatische Aktionen, die beim Öffnen oder bei bestimmten Ereignissen ausgeführt werden.
* **/JS, /JavaScript** – eingebettetes JavaScript (oft obfuskiert oder über Objekte verteilt).
* **/Launch, /SubmitForm, /URI, /GoToE** – externe Prozess- / URL-Launcher.
* **/RichMedia, /Flash, /3D** – Multimedia-Objekte, die Payloads verbergen können.
* **/EmbeddedFile /Filespec** – Dateianhänge (EXE, DLL, OLE usw.).
* **/ObjStm, /XFA, /AcroForm** – Objektströme oder Formulare, die häufig missbraucht werden, um Shell-Code zu verbergen.
* **Inkrementelle Updates** – mehrere %%EOF-Markierungen oder ein sehr großer **/Prev**-Offset können darauf hindeuten, dass Daten nach der Signatur angehängt wurden, um AV zu umgehen.

Wenn eines der vorherigen Tokens zusammen mit verdächtigen Zeichenfolgen (powershell, cmd.exe, calc.exe, base64 usw.) erscheint, verdient die PDF eine tiefere Analyse.

---

## Statistische Analyse-Checkliste
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Zusätzliche nützliche Projekte (aktiv gepflegt 2023-2025):
* **pdfcpu** – Go-Bibliothek/CLI, die in der Lage ist, PDFs zu *linten*, *entschlüsseln*, *extrahieren*, *komprimieren* und *sanitieren*.
* **pdf-inspector** – browserbasierter Visualisierer, der das Objektgraph und Streams rendert.
* **PyMuPDF (fitz)** – scriptbare Python-Engine, die Seiten sicher in Bilder rendern kann, um eingebettetes JS in einer gehärteten Sandbox auszulösen.

---

## Aktuelle Angriffstechniken (2023-2025)

* **MalDoc in PDF Polyglot (2023)** – JPCERT/CC beobachtete Bedrohungsakteure, die ein MHT-basiertes Word-Dokument mit VBA-Makros nach dem letzten **%%EOF** anfügten, wodurch eine Datei entstand, die sowohl ein gültiges PDF als auch ein gültiges DOC ist. AV-Engines, die nur die PDF-Schicht analysieren, übersehen das Makro. Statische PDF-Schlüsselwörter sind sauber, aber `file` gibt immer noch `%PDF` aus. Behandeln Sie jedes PDF, das auch die Zeichenfolge `<w:WordDocument>` enthält, als hochgradig verdächtig.
* **Shadow-incremental Updates (2024)** – Gegner missbrauchen die Funktion für inkrementelle Updates, um einen zweiten **/Catalog** mit schädlichem `/OpenAction` einzufügen, während die harmlose erste Revision signiert bleibt. Werkzeuge, die nur die erste xref-Tabelle inspizieren, werden umgangen.
* **Font Parsing UAF-Kette – CVE-2024-30284 (Acrobat/Reader)** – eine verwundbare **CoolType.dll**-Funktion kann von eingebetteten CIDType2-Schriftarten erreicht werden, was die Ausführung von Remote-Code mit den Rechten des Benutzers ermöglicht, sobald ein manipuliertes Dokument geöffnet wird. In APSB24-29, Mai 2024, gepatcht.

---

## YARA Schnellregelvorlage
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Defensive Tipps

1. **Schnell patchen** – Halten Sie Acrobat/Reader auf dem neuesten Continuous-Track; die meisten in der Wildnis beobachteten RCE-Ketten nutzen n-day Schwachstellen, die Monate zuvor behoben wurden.
2. **Aktive Inhalte am Gateway entfernen** – Verwenden Sie `pdfcpu sanitize` oder `qpdf --qdf --remove-unreferenced`, um JavaScript, eingebettete Dateien und Startaktionen aus eingehenden PDFs zu entfernen.
3. **Content Disarm & Reconstruction (CDR)** – Konvertieren Sie PDFs auf einem Sandbox-Host in Bilder (oder PDF/A), um die visuelle Treue zu bewahren und gleichzeitig aktive Objekte zu verwerfen.
4. **Selten genutzte Funktionen blockieren** – Unternehmens-„Enhanced Security“-Einstellungen in Reader ermöglichen das Deaktivieren von JavaScript, Multimedia und 3D-Rendering.
5. **Benutzerschulung** – Social Engineering (Rechnungs- & Lebenslaufköder) bleibt der anfängliche Vektor; schulen Sie Mitarbeiter, verdächtige Anhänge an IR weiterzuleiten.

## Referenzen

* JPCERT/CC – „MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file“ (Aug 2023)
* Adobe – Sicherheitsupdate für Acrobat und Reader (APSB24-29, Mai 2024)

{{#include ../../../banners/hacktricks-training.md}}
