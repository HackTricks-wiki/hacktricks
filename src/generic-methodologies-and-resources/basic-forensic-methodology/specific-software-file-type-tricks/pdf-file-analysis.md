# PDF-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

**Weitere Informationen findest du unter:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Das PDF-Format ist für seine Komplexität und sein Potenzial zum Verbergen von Daten bekannt und daher ein Schwerpunkt bei CTF-Forensics-Challenges. Es kombiniert Klartextelemente mit binären Objekten, die komprimiert oder verschlüsselt sein können, und kann Scripts in Sprachen wie JavaScript oder Flash enthalten. Um die Struktur von PDFs zu verstehen, kann man auf Didie[r] Stevens' [Einführungsmaterial](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) zurückgreifen oder Tools wie einen Texteditor bzw. einen PDF-spezifischen Editor wie Origami verwenden.

Für die detaillierte Untersuchung oder Manipulation von PDFs stehen Tools wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Verborgene Daten in PDFs können sich unter anderem an folgenden Stellen befinden:

- Unsichtbare Ebenen
- XMP-Metadatenformat von Adobe
- Inkrementelle Generationen
- Text mit derselben Farbe wie der Hintergrund
- Text hinter Bildern oder überlappende Bilder
- Nicht angezeigte Kommentare

Für benutzerdefinierte PDF-Analysen können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) verwendet werden, um maßgeschneiderte Parsing-Scripts zu erstellen. Darüber hinaus ist das Potenzial von PDFs zur Speicherung verborgener Daten so groß, dass Ressourcen wie der NSA-Leitfaden zu PDF-Risiken und Gegenmaßnahmen weiterhin wertvolle Einblicke bieten, obwohl er nicht mehr an seinem ursprünglichen Ort gehostet wird. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [PDF-Format-Tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini bieten weiterführende Informationen zu diesem Thema.

## Häufige bösartige Konstrukte

Angreifer missbrauchen häufig bestimmte PDF-Objekte und Aktionen, die automatisch ausgeführt werden, wenn das Dokument geöffnet oder mit ihm interagiert wird. Nach folgenden Keywords sollte gesucht werden:

* **/OpenAction, /AA** – automatische Aktionen, die beim Öffnen oder bei bestimmten Ereignissen ausgeführt werden.
* **/JS, /JavaScript** – eingebettetes JavaScript (häufig obfuskiert oder auf mehrere Objekte verteilt).
* **/Launch, /SubmitForm, /URI, /GoToE** – Launcher für externe Prozesse bzw. URLs.
* **/RichMedia, /Flash, /3D** – Multimedia-Objekte, die Payloads verbergen können.
* **/EmbeddedFile /Filespec** – Dateianhänge (EXE, DLL, OLE usw.).
* **/ObjStm, /XFA, /AcroForm** – Objekt-Streams oder Formulare, die häufig zum Verbergen von Shellcode missbraucht werden.
* **Inkrementelle Updates** – mehrere `%%EOF`-Marker oder ein sehr großer **/Prev**-Offset können darauf hindeuten, dass Daten nach dem Signieren angehängt wurden, um AV zu umgehen.

Wenn eines der oben genannten Tokens zusammen mit verdächtigen Strings (powershell, cmd.exe, calc.exe, base64 usw.) auftritt, verdient das PDF eine eingehendere Analyse.

---

## Cheat-Sheet zur statischen Analyse
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
Weitere nützliche Projekte (aktiv gepflegt 2023–2025):
* **pdfcpu** – Go-Bibliothek/CLI zum *lint*, *decrypt*, *extract*, *compress* und *sanitize* von PDFs.
* **pdf-inspector** – browserbasierter Visualizer, der den Objektgraphen und Streams rendert.
* **PyMuPDF (fitz)** – skriptfähige Python-Engine, die Seiten sicher als Bilder rendern kann, um eingebettetes JS in einer gehärteten Sandbox auszuführen.

---

## Aktuelle Angriffstechniken (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC beobachtete Threat Actors, die nach dem letzten **%%EOF** ein MHT-basiertes Word-Dokument mit VBA-Makros anhängten und dadurch eine Datei erzeugten, die sowohl ein gültiges PDF als auch ein gültiges DOC ist. AV-Engines, die nur die PDF-Schicht analysieren, übersehen das Makro. Statische PDF-Schlüsselwörter sind unauffällig, aber `file` gibt weiterhin `%PDF` aus. Jedes PDF, das außerdem die Zeichenkette `<w:WordDocument>` enthält, sollte als äußerst verdächtig eingestuft werden.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – Angreifer missbrauchen die Funktion für inkrementelle Updates, um einen zweiten **/Catalog** mit schädlichem `/OpenAction` einzufügen, während die gutartige erste Revision signiert bleibt. Tools, die nur die erste xref-Tabelle prüfen, werden dadurch umgangen.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – Eine verwundbare Funktion in **CoolType.dll** kann über eingebettete CIDType2-Schriftarten erreicht werden und ermöglicht Remote Code Execution mit den Rechten des Benutzers, sobald ein manipuliertes Dokument geöffnet wird. Gepatcht in APSB24-29, Mai 2024.<sup>[[3]](#references)</sup>

---

## Kurze Vorlage für YARA-Regeln
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

1. **Schnell patchen** – Acrobat/Reader auf dem neuesten Continuous-Track halten; die meisten in freier Wildbahn beobachteten RCE-Ketten nutzen n-day-Schwachstellen aus, die bereits Monate zuvor behoben wurden.
2. **Aktive Inhalte am Gateway entfernen** – `pdfcpu sanitize` oder `qpdf --qdf --remove-unreferenced` verwenden, um JavaScript, eingebettete Dateien und Launch-Aktionen aus eingehenden PDFs zu entfernen.
3. **Content Disarm & Reconstruction (CDR)** – PDFs auf einem Sandbox-Host in Bilder (oder PDF/A) konvertieren, um die visuelle Wiedergabetreue zu erhalten und gleichzeitig aktive Objekte zu verwerfen.
4. **Selten verwendete Funktionen blockieren** – Die Einstellungen für „Enhanced Security“ in Reader ermöglichen das Deaktivieren von JavaScript, Multimedia und 3D-Rendering.
5. **Benutzerschulung** – Social Engineering (Täuschungen mit Rechnungen und Lebensläufen) bleibt der initiale Vektor; Mitarbeitende darin schulen, verdächtige Anhänge an das IR-Team weiterzuleiten.

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
