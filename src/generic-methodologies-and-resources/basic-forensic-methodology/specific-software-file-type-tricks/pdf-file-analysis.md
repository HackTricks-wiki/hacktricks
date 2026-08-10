# PDF-Dateianalyse

**Weitere Details finden Sie unter:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Das PDF-Format ist für seine Komplexität und sein Potenzial zur Datenverschleierung bekannt und daher ein Schwerpunkt bei CTF-Forensics-Challenges. Es kombiniert Klartextelemente mit binären Objekten, die komprimiert oder verschlüsselt sein können, und kann Skripte in Sprachen wie JavaScript oder Flash enthalten. Zum Verständnis der PDF-Struktur kann man auf Didier Stevens' [Einführungsmaterial](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) zurückgreifen oder Tools wie einen Texteditor beziehungsweise einen PDF-spezifischen Editor wie Origami verwenden.

Für die eingehende Untersuchung oder Manipulation von PDFs stehen Tools wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Versteckte Daten in PDFs können sich befinden in:

- Unsichtbaren Ebenen
- XMP-Metadatenformat von Adobe
- Inkrementellen Generationen
- Text mit derselben Farbe wie der Hintergrund
- Text hinter Bildern oder sich überlappenden Bildern
- Nicht angezeigten Kommentaren

Für benutzerdefinierte PDF-Analysen können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) verwendet werden, um maßgeschneiderte Parsing-Skripte zu erstellen. Darüber hinaus ist das Potenzial von PDFs zur Speicherung versteckter Daten so groß, dass Ressourcen wie der NSA-Leitfaden zu PDF-Risiken und Gegenmaßnahmen trotz seiner Entfernung vom ursprünglichen Speicherort weiterhin wertvolle Einblicke bieten. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini bieten weitere Informationen zu diesem Thema.<sup>[[4]](#references)[[5]](#references)</sup>

## Häufige bösartige Konstrukte

Angreifer missbrauchen häufig bestimmte PDF-Objekte und Aktionen, die automatisch ausgeführt werden, wenn das Dokument geöffnet oder mit ihm interagiert wird. Nach folgenden Schlüsselwörtern sollte gesucht werden:

* **/OpenAction, /AA** – automatische Aktionen, die beim Öffnen oder bei bestimmten Ereignissen ausgeführt werden.
* **/JS, /JavaScript** – eingebettetes JavaScript (oft verschleiert oder auf mehrere Objekte verteilt).
* **/Launch, /SubmitForm, /URI, /GoToE** – Starter für externe Prozesse / URLs.
* **/RichMedia, /Flash, /3D** – Multimediaobjekte, die Payloads verbergen können.
* **/EmbeddedFile /Filespec** – Dateianhänge (EXE, DLL, OLE usw.).
* **/ObjStm, /XFA, /AcroForm** – Objektströme oder Formulare, die häufig zum Verbergen von shell-code missbraucht werden.
* **Inkrementelle Aktualisierungen** – mehrere %%EOF-Markierungen oder ein sehr großer **/Prev**-Offset können darauf hinweisen, dass nach dem Signieren Daten angehängt wurden, um AV zu umgehen.

Wenn eines der vorherigen Tokens zusammen mit verdächtigen Zeichenfolgen (powershell, cmd.exe, calc.exe, base64 usw.) auftritt, verdient das PDF eine eingehendere Analyse.

---

## Cheat-Sheet zur statischen Analyse

Die folgenden Beispiele verwenden die dokumentierten Kommandozeilenschnittstellen von `pdf-parser.py`, qpdf und pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
Zusätzliche nützliche Projekte (aktiv gepflegt 2023–2025):
* **pdfcpu** – Go-Bibliothek/CLI zum Validieren, Entschlüsseln, Extrahieren, Optimieren und Bearbeiten von PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – browserbasierter Visualizer, der den Objektgraphen und Streams rendert.
* **PyMuPDF** – skriptfähige Python-Bindings zum Untersuchen von PDFs und Rendern von Seiten in Rasterbilder. Behandle den Parser/Renderer als Angriffsfläche für nicht vertrauenswürdige Dateien und führe ihn in einer entsprechend isolierten Analyseumgebung aus.<sup>[[8]](#references)</sup>

---

## Aktuelle Angriffstechniken (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC berichtete über eine Technik, bei der eine mit Word erstellte MHT-Datei mit VBA-Makros an ein PDF angehängt wird, wobei der PDF-Magic-String erhalten bleibt und die Datei gleichzeitig in Word geöffnet werden kann. PDF-only-Analysetools, Sandboxes oder Antivirussoftware übersehen das Makro möglicherweise, weil das schädliche Verhalten beim Öffnen als Word-Datei auftritt; suche neben anderen MHT-Indikatoren nach dem Marker `<w:WordDocument>`.<sup>[[2]](#references)</sup>
* **Shadow attacks auf signierte PDFs** – Angreifer können versteckte Inhalte in einem PDF platzieren, bevor es signiert wird, und anschließend ein inkrementelles Update anhängen, das Katalog- oder Objektreferenzen so ändert, dass Viewer die versteckten Inhalte anzeigen, während die ursprüngliche Signatur gültig bleibt. Die Technik kann Viewer umgehen, die solche Updates als harmlos einstufen.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe bewertet diese kritische Schwachstelle als Use-after-free, die zur Ausführung beliebigen Codes führen kann; APSB24-29 wurde am 14. Mai 2024 veröffentlicht.<sup>[[3]](#references)</sup>

---

## YARA-Schnellvorlage für Regeln
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

1. **Schnell patchen** – Acrobat/Reader auf dem neuesten Continuous-Track halten; die meisten in freier Wildbahn beobachteten RCE-Ketten nutzen N-Day-Schwachstellen aus, die bereits Monate zuvor behoben wurden.
2. **Aktive Inhalte am Gateway entfernen** – einen speziell entwickelten, richtliniengesteuerten Sanitizer oder ein CDR-Produkt verwenden, das JavaScript, eingebettete Dateien, Launch-Aktionen, Formulare und Multimedia explizit entfernt. `qpdf --qdf` macht PDF-Objekte leichter untersuchbar, während pdfcpu Validierungs- und Bearbeitungsfunktionen bietet; keiner der beiden Befehle allein beweist, dass aktive Inhalte entfernt wurden.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – PDFs auf einem Sandbox-Host in Bilder (oder PDF/A) konvertieren, um die visuelle Genauigkeit zu bewahren und gleichzeitig aktive Objekte zu verwerfen.
4. **Selten verwendete Funktionen blockieren** – die Einstellungen für „Enhanced Security“ in Reader ermöglichen das Deaktivieren von JavaScript, Multimedia und 3D-Rendering.
5. **Benutzerschulung** – Social Engineering (Köder wie Rechnungen und Lebensläufe) bleibt der initiale Angriffsvektor; Mitarbeiter anweisen, verdächtige Anhänge an das IR-Team weiterzuleiten.

## References

- [1] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Umgehung der Erkennung durch Einbettung einer schädlichen Word-Datei in eine PDF-Datei](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Sicherheitsupdate für Adobe Acrobat und Reader verfügbar (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu – Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs – Tricks zum PDF-Format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Verbergen und Ersetzen von Inhalten in signierten PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF-Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf-Kommandozeilenoptionen](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
