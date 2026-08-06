# PDF-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

**Weitere Details finden Sie unter:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Das PDF-Format ist für seine Komplexität und sein Potenzial zum Verbergen von Daten bekannt und daher ein Schwerpunkt bei CTF-Forensik-Challenges. Es kombiniert Klartextelemente mit binären Objekten, die komprimiert oder verschlüsselt sein können, und kann Scripts in Sprachen wie JavaScript oder Flash enthalten. Um die Struktur von PDFs zu verstehen, kann man auf Didie​r Stevens' [einführendes Material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) zurückgreifen oder Tools wie einen Texteditor beziehungsweise einen PDF-spezifischen Editor wie Origami verwenden.

Für die eingehende Untersuchung oder Manipulation von PDFs stehen Tools wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Versteckte Daten in PDFs können sich unter anderem befinden in:

- Unsichtbaren Ebenen
- XMP-Metadatenformat von Adobe
- Inkrementellen Generationen
- Text mit derselben Farbe wie der Hintergrund
- Text hinter Bildern oder sich überlappenden Bildern
- Nicht angezeigten Kommentaren

Für benutzerdefinierte PDF-Analysen können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) verwendet werden, um maßgeschneiderte Parsing-Scripts zu erstellen. Darüber hinaus ist das Potenzial von PDFs zur Speicherung versteckter Daten so groß, dass Ressourcen wie der NSA-Leitfaden zu PDF-Risiken und Gegenmaßnahmen trotz seines nicht mehr verfügbaren ursprünglichen Speicherorts weiterhin wertvolle Erkenntnisse liefern. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [PDF-Format-Tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini bieten weiterführende Informationen zu diesem Thema.<sup>[[4]](#references)[[5]](#references)</sup>

## Häufige bösartige Konstrukte

Angreifer missbrauchen häufig bestimmte PDF-Objekte und Aktionen, die automatisch ausgeführt werden, wenn das Dokument geöffnet oder mit ihm interagiert wird. Nach folgenden Keywords sollte gesucht werden:

* **/OpenAction, /AA** – automatische Aktionen, die beim Öffnen oder bei bestimmten Ereignissen ausgeführt werden.
* **/JS, /JavaScript** – eingebettetes JavaScript (häufig obfuskiert oder auf mehrere Objekte verteilt).
* **/Launch, /SubmitForm, /URI, /GoToE** – Starter für externe Prozesse / URLs.
* **/RichMedia, /Flash, /3D** – Multimedia-Objekte, die Payloads verbergen können.
* **/EmbeddedFile /Filespec** – Dateianhänge (EXE, DLL, OLE usw.).
* **/ObjStm, /XFA, /AcroForm** – Objekt-Streams oder Formulare, die häufig missbraucht werden, um Shellcode zu verbergen.
* **Inkrementelle Updates** – mehrere %%EOF-Marker oder ein sehr großer **/Prev**-Offset können darauf hindeuten, dass nach dem Signieren Daten angehängt wurden, um AV zu umgehen.

Wenn eines der zuvor genannten Tokens zusammen mit verdächtigen Strings (powershell, cmd.exe, calc.exe, base64 usw.) auftritt, verdient das PDF eine eingehendere Analyse.

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
Additional nützliche Projekte (aktiv gepflegt 2023-2025):
* **pdfcpu** – Go-Bibliothek/CLI zum *lint*, *decrypt*, *extract*, *compress* und *sanitize* von PDFs.
* **pdf-inspector** – browserbasierter Visualizer, der den Objektgraphen und Streams rendert.
* **PyMuPDF (fitz)** – skriptfähige Python-Engine, die Seiten sicher als Bilder rendern kann, um eingebettetes JS in einer gehärteten Sandbox zu detonieren.

---

## Aktuelle Angriffstechniken (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC beobachtete, wie Threat Actors ein MHT-basiertes Word-Dokument mit VBA-Makros nach dem finalen **%%EOF** anhängen und dadurch eine Datei erzeugen, die sowohl ein gültiges PDF als auch ein gültiges DOC ist. AV-Engines, die nur die PDF-Schicht parsen, übersehen das Makro. Statische PDF-Schlüsselwörter sind unauffällig, aber `file` gibt weiterhin `%PDF` aus. Behandle jedes PDF, das außerdem den String `<w:WordDocument>` enthält, als äußerst verdächtig.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – Adversaries missbrauchen die Funktion für inkrementelle Updates, um einen zweiten **/Catalog** mit schädlichem `/OpenAction` einzufügen, während die gutartige erste Revision signiert bleibt. Tools, die nur die erste xref-Tabelle untersuchen, werden umgangen.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – Eine verwundbare Funktion in **CoolType.dll** kann über eingebettete CIDType2-Fonts erreicht werden und ermöglicht Remote Code Execution mit den Berechtigungen des Benutzers, sobald ein präpariertes Dokument geöffnet wird. Gepatcht in APSB24-29, Mai 2024.<sup>[[3]](#references)</sup>

---

## YARA-Kurzvorlage für Regeln
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
3. **Content Disarm & Reconstruction (CDR)** – PDFs auf einem Sandbox-Host in Bilder (oder PDF/A) konvertieren, um die visuelle Genauigkeit zu bewahren und gleichzeitig aktive Objekte zu verwerfen.
4. **Selten verwendete Funktionen blockieren** – Die Einstellungen für „Enhanced Security“ in Reader ermöglichen das Deaktivieren von JavaScript, Multimedia und 3D-Rendering.
5. **Schulung der Benutzer** – Social Engineering (Täuschungen mit Rechnungen und Lebensläufen) bleibt der anfängliche Angriffsvektor; Mitarbeiter anweisen, verdächtige Anhänge an das IR weiterzuleiten.

## Referenzen

- [1] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Erkennungsumgehung durch das Einbetten einer schädlichen Word-Datei in eine PDF-Datei](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Sicherheitsupdate für Adobe Acrobat und Reader verfügbar (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu – Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs – Tricks im PDF-Format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
