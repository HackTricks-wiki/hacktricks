# Office-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

Für weitere Informationen siehe [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:

Microsoft hat viele Office-Dokumentformate erstellt, wobei zwei Haupttypen **OLE-Formate** (wie RTF, DOC, XLS, PPT) und **Office Open XML (OOXML)-Formate** (wie DOCX, XLSX, PPTX) sind. Diese Formate können Makros enthalten, was sie zu Zielen für Phishing und Malware macht. OOXML-Dateien sind als Zip-Container strukturiert, was eine Inspektion durch Entpacken ermöglicht und die Datei- und Ordnerhierarchie sowie den Inhalt der XML-Dateien offenbart.

Um die OOXML-Dateistrukturen zu erkunden, werden der Befehl zum Entpacken eines Dokuments und die Ausgabe der Struktur angegeben. Techniken zum Verstecken von Daten in diesen Dateien sind dokumentiert, was auf eine fortlaufende Innovation bei der Datenverbergung innerhalb von CTF-Herausforderungen hinweist.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Werkzeugsätze zur Untersuchung sowohl von OLE- als auch von OOXML-Dokumenten. Diese Tools helfen bei der Identifizierung und Analyse eingebetteter Makros, die oft als Vektoren für die Bereitstellung von Malware dienen, typischerweise durch Herunterladen und Ausführen zusätzlicher bösartiger Payloads. Die Analyse von VBA-Makros kann ohne Microsoft Office durchgeführt werden, indem Libre Office verwendet wird, das das Debuggen mit Haltepunkten und Überwachungsvariablen ermöglicht.

Die Installation und Nutzung von **oletools** ist unkompliziert, mit Befehlen zum Installieren über pip und zum Extrahieren von Makros aus Dokumenten. Die automatische Ausführung von Makros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
