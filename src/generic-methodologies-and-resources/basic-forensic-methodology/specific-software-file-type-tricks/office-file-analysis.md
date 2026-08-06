# Analyse von Office-Dateien

{{#include ../../../banners/hacktricks-training.md}}


Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft hat viele Office-Dokumentformate erstellt. Die beiden Haupttypen sind **OLE-Formate** (wie RTF, DOC, XLS und PPT) sowie **Office Open XML (OOXML)-Formate** (wie DOCX, XLSX und PPTX). Diese Formate können Makros enthalten und sind dadurch Ziele für Phishing und Malware. OOXML-Dateien sind als zip-Container strukturiert und können durch Entpacken untersucht werden. Dadurch werden die Datei- und Ordnerhierarchie sowie die Inhalte der XML-Dateien sichtbar.

Zur Untersuchung der OOXML-Dateistrukturen werden der Befehl zum Entpacken eines Dokuments und die resultierende Struktur gezeigt. Techniken zum Verstecken von Daten in diesen Dateien wurden dokumentiert, was auf eine kontinuierliche Weiterentwicklung der Datenverschleierung in CTF-Herausforderungen hindeutet.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen dabei, eingebettete Makros zu identifizieren und zu analysieren, die häufig als Vektoren für die Zustellung von Malware dienen und typischerweise zusätzliche schädliche Payloads herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office durchgeführt werden, indem Libre Office verwendet wird. Damit sind Debugging mit Breakpoints und die Überwachung von Variablen möglich.

Installation und Verwendung von **oletools** sind unkompliziert. Es werden Befehle für die Installation über pip und das Extrahieren von Makros aus Dokumenten bereitgestellt. Die automatische Ausführung von Makros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Ausnutzung von OLE Compound Files: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit-RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (auch CFBF genannt) gespeichert. Das serialisierte Modell befindet sich unter storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtige Struktur von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierte Nutzdaten (der eigentliche serialisierte Objektgraph)
- Nullauffüllung
- Error-Correcting-Code-(ECC-)Trailer

Revit repariert kleine Änderungen am Stream automatisch mithilfe des ECC-Trailers und lehnt Streams ab, die nicht mit dem ECC übereinstimmen. Daher bleiben beim naiven Bearbeiten der komprimierten Bytes die Änderungen nicht erhalten: Entweder werden sie zurückgesetzt oder die Datei wird abgelehnt. Um eine bytegenaue Kontrolle darüber zu gewährleisten, was der Deserialisierer sieht, müssen Sie:

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten/akzeptierten komprimierten Bytes dem erwarteten Format entsprechen).
- Den ECC-Trailer über dem aufgefüllten Stream neu berechnen, damit Revit den modifizierten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE-Compound-Dokument expandieren
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` zerlegen: den Header beibehalten, den Payload entpacken, Bytes ändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder gzip-komprimieren.
- Zero-Padding beibehalten und den ECC-Trailer neu berechnen, damit die neuen Bytes von Revit akzeptiert werden.
- Wenn eine deterministische Byte-für-Byte-Reproduktion erforderlich ist, einen minimalen Wrapper um Revit-DLLs erstellen, um dessen gzip-/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder einen verfügbaren Helper wiederverwenden, der diese Semantik nachbildet.

3) Das OLE-Compound-Dokument neu erstellen
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool schreibt storages/streams mit Escaping für Zeichen in das filesystem, die in NTFS-Namen ungültig sind; der gewünschte stream path ist im output tree exakt `Global/Latest`.
- Wenn mass attacks über ecosystem plugins bereitgestellt werden, die RFAs aus cloud storage abrufen, stelle sicher, dass deine gepatchte RFA zunächst lokal die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor du eine network injection versuchst.

Exploitation insight (als Orientierung dafür, welche Bytes im gzip payload platziert werden sollen):<sup>[[1]](#references)</sup>

- Der Revit deserializer liest einen 16-bit class index und erstellt ein object. Bestimmte types sind non-polymorphic und verfügen über keine vtables; der Missbrauch der destructor-Behandlung führt zu einer type confusion, bei der die engine einen indirect call über einen vom Angreifer kontrollierten pointer ausführt.
- Die Auswahl von `AString` (class index `0x1F`) platziert einen vom Angreifer kontrollierten heap pointer an object offset 0. Während der destructor loop führt Revit effektiv Folgendes aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und richte einen stack pivot in eine konventionelle x64-ROP chain ein.

Details zum Windows-x64-Pivot/Gadget-Building findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

und allgemeine ROP-Hinweise hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tools:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Expandieren und Rekonstruieren von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere den Page Heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Bereitstellung simulieren, indem er zu Testzwecken RFAs im Plugin-Traffic austauscht.

## References

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
