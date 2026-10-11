# PDF-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

**Weitere Details finden Sie unter:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Das PDF-Format ist für seine Komplexität und sein Potenzial zur Datenverschleierung bekannt und daher ein Schwerpunkt bei CTF-Forensik-Herausforderungen. Es kombiniert Klartextelemente mit Binärobjekten, die komprimiert oder verschlüsselt sein können, und kann Skripte in Sprachen wie JavaScript oder Flash enthalten. Zum Verständnis der PDF-Struktur kann man Didier Stevens' [Einführungsmaterial](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) heranziehen oder Tools wie einen Texteditor oder einen speziellen PDF-Editor wie Origami verwenden.

Für die eingehende Untersuchung oder Bearbeitung von PDFs stehen Tools wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Versteckte Daten in PDFs können sich unter anderem hier verbergen:

- Unsichtbare Ebenen
- Das XMP-Metadatenformat von Adobe
- Inkrementelle Generationen
- Text in derselben Farbe wie der Hintergrund
- Text hinter Bildern oder überlappende Bilder
- Nicht angezeigte Kommentare

Für eine maßgeschneiderte PDF-Analyse können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) zum Erstellen individueller Parsing-Skripte verwendet werden. Darüber hinaus ist das Potenzial von PDFs zur Speicherung versteckter Daten so groß, dass Ressourcen wie der Leitfaden der NSA zu PDF-Risiken und Gegenmaßnahmen weiterhin wertvolle Einblicke bieten, obwohl er nicht mehr unter seiner ursprünglichen Adresse gehostet wird. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [Tricks zum PDF-Format](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini bieten weiterführende Informationen zu diesem Thema.<sup>[[4]](#references)[[5]](#references)</sup>

## Häufige bösartige Konstrukte

Angreifer missbrauchen häufig bestimmte PDF-Objekte und Aktionen, die automatisch ausgeführt werden, wenn das Dokument geöffnet oder damit interagiert wird. Auf folgende Schlüsselwörter sollte man achten:

* **/OpenAction, /AA** – automatische Aktionen, die beim Öffnen oder bei bestimmten Ereignissen ausgeführt werden.
* **/JS, /JavaScript** – eingebettetes JavaScript (häufig verschleiert oder auf mehrere Objekte verteilt).
* **/Launch, /SubmitForm, /URI, /GoToE** – zum Starten externer Prozesse oder URLs.
* **/RichMedia, /Flash, /3D** – Multimediaobjekte, in denen sich Payloads verbergen können.
* **/EmbeddedFile /Filespec** – Dateianhänge (EXE, DLL, OLE usw.).
* **/ObjStm, /XFA, /AcroForm** – Objekt-Streams oder Formulare, die häufig zum Verbergen von Shellcode missbraucht werden.
* **Inkrementelle Aktualisierungen** – mehrere %%EOF-Markierungen oder ein sehr großer **/Prev**-Offset können darauf hindeuten, dass nach dem Signieren Daten angehängt wurden, um AV zu umgehen.

Wenn eines der genannten Tokens zusammen mit verdächtigen Zeichenfolgen (powershell, cmd.exe, calc.exe, base64 usw.) auftaucht, sollte das PDF eingehender analysiert werden.

---

## Spickzettel zur statischen Analyse

Die folgenden Beispiele verwenden die dokumentierten Befehlszeilenschnittstellen von `pdf-parser.py`, qpdf und pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Das Pixelieren eines Bildes in einer PDF entfernt nicht die zugrunde liegenden Pixel. Wenn ein lesbares Dokument auf diese Weise offenbar ein Zugangsdaten verbirgt, extrahiere das eingebettete Bild zur autorisierten Offline-Analyse; das Ergebnis hängt vom Bild und einer geeigneten Referenz ab, und eine visuelle Wiederherstellung ist nicht garantiert. Ein wiederhergestelltes Passwort muss weiterhin separat mit dem Konto überprüft werden, dessen Berechtigungen relevant sind. Nimm einen PDF-Extraktions- oder Bildwiederherstellungsschritt nicht in einen routinemäßigen Host-Enumerationsscan auf.

Weitere nützliche Projekte (aktiv gepflegt 2023–2025):
* **pdfcpu** – Go-Bibliothek/CLI zum Validieren, Entschlüsseln, Extrahieren, Optimieren und Bearbeiten von PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – browserbasierter Visualizer, der den Objektgraphen und Streams darstellt.
* **PyMuPDF** – skriptfähige Python-Bindings zum Untersuchen von PDFs und Rendern von Seiten als Rasterbilder. Behandle den Parser/Renderer als Angriffsfläche für nicht vertrauenswürdige Dateien und führe ihn in einer angemessen isolierten Analyseumgebung aus.<sup>[[8]](#references)</sup>

---

## Aktuelle Angriffstechniken (2023–2025)

* **MalDoc-in-PDF-Polyglot (2023)** – JPCERT/CC berichtete über eine Technik, bei der eine mit Word erstellte MHT-Datei mit VBA-Makros an eine PDF angehängt wird, sodass die PDF-Magic erhalten bleibt, die Datei aber auch in Word geöffnet werden kann. Tools zur reinen PDF-Analyse, Sandboxes oder Antivirus-Software können das Makro übersehen, weil das schädliche Verhalten beim Öffnen in Word auftritt; suche neben anderen MHT-Indikatoren nach dem Marker `<w:WordDocument>`.<sup>[[2]](#references)</sup>
* **Shadow-Angriffe auf signierte PDFs** – Angreifer können versteckte Inhalte in einer PDF platzieren, bevor sie signiert wird, und anschließend ein inkrementelles Update anhängen, das Katalog- oder Objektreferenzen ändert, sodass Viewer die versteckten Inhalte anzeigen, während die ursprüngliche Signatur gültig bleibt. Die Technik kann Viewer umgehen, die solche Updates als harmlos einstufen.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe bewertet diese kritische Sicherheitslücke als Use-after-free, die zur Ausführung beliebigen Codes führen kann; APSB24-29 wurde am 14. Mai 2024 veröffentlicht.<sup>[[3]](#references)</sup>

---

## YARA-Vorlage für eine schnelle Regel

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
2. **Aktive Inhalte am Gateway entfernen** – einen speziell dafür entwickelten, richtliniengesteuerten Sanitizer oder ein CDR-Produkt verwenden, das JavaScript, eingebettete Dateien, Launch-Aktionen, Formulare und Multimedia ausdrücklich entfernt. `qpdf --qdf` erleichtert die Untersuchung von PDF-Objekten, während pdfcpu Funktionen zur Validierung und Bearbeitung bietet; keiner der beiden Befehle allein beweist, dass aktive Inhalte entfernt wurden.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – PDFs auf einem Sandbox-Host in Bilder (oder PDF/A) umwandeln, um die visuelle Wiedergabetreue zu erhalten und gleichzeitig aktive Objekte zu verwerfen.
4. **Selten verwendete Funktionen blockieren** – Mit den unternehmensweiten „Enhanced Security“-Einstellungen in Reader lassen sich JavaScript, Multimedia und 3D-Rendering deaktivieren.
5. **Benutzerschulung** – Social Engineering (Köder mit Rechnungen und Lebensläufen) bleibt der erste Angriffsvektor; Mitarbeitende darin schulen, verdächtige Anhänge an IR weiterzuleiten.

## References

- [1] [CTF-Leitfaden für digitale Forensik](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Erkennung umgehen, indem eine schädliche Word-Datei in eine PDF-Datei eingebettet wird](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe-Sicherheitsbulletin – Sicherheitsupdate für Adobe Acrobat und Reader verfügbar (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu – Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs – Tricks zum PDF-Format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow-Angriffe: Inhalte in signierten PDFs verbergen und ersetzen](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF-Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Befehlszeilenoptionen von qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
