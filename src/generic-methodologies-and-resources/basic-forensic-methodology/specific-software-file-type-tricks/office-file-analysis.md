# Analyse von Office-Dateien

{{#include ../../../banners/hacktricks-training.md}}

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist lediglich eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft-Office-Dokumente liegen häufig in Legacy-Formaten wie RTF und OLE/CFBF-basierten DOC-, XLS- und PPT-Dateien oder in neueren **Office Open XML (OOXML)**-Formaten wie DOCX, XLSX und PPTX vor. Office-Dokumente können aktive Inhalte wie Makros enthalten, wodurch sie zu häufigen Trägern für Phishing und Malware werden. OOXML-Dateien sind ZIP-Container, deren Dateihierarchie und XML-Inhalte durch Entpacken untersucht werden können.<sup>[[3]](#references)[[4]](#references)</sup>

Zur Untersuchung von OOXML-Dateistrukturen werden der Befehl zum Entpacken eines Dokuments und die Ausgabestruktur angegeben. Techniken zum Verstecken von Daten in diesen Dateien wurden dokumentiert, was auf eine fortlaufende Innovation bei der Datenverbergung in CTF-Challenges hinweist.<sup>[[4]](#references)</sup>

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen beim Identifizieren und Analysieren eingebetteter Makros, die häufig als Vektoren für die Zustellung von Malware dienen und typischerweise zusätzliche schädliche Payloads herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office mithilfe von Libre Office durchgeführt werden, das Debugging mit Breakpoints und Beobachtungsvariablen ermöglicht.<sup>[[4]](#references)</sup>

Die Installation und Verwendung von **oletools** ist unkompliziert. Es werden Befehle zur Installation über pip und zum Extrahieren von Makros aus Dokumenten bereitgestellt. In Word umfassen automatische Makros `AutoExec` und `AutoOpen`, während `Document_Open` eine Open-Event-Prozedur ist.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Ausnutzung von OLE Compound Files: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit-RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (auch CFBF genannt) gespeichert. Das serialisierte Modell befindet sich unter Storage/Stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierte Nutzdaten (der tatsächlich serialisierte Objektgraph)
- Nullauffüllung
- ECC-Trailer (Error-Correcting Code)

Revit repariert kleine Änderungen am Stream mithilfe des ECC-Trailers automatisch und lehnt Streams ab, die nicht mit dem ECC übereinstimmen. Daher bleiben naiv bearbeitete komprimierte Bytes nicht dauerhaft bestehen: Deine Änderungen werden entweder rückgängig gemacht oder die Datei wird abgelehnt. Um eine bytegenaue Kontrolle darüber sicherzustellen, was der Deserialisierer sieht, musst du:<sup>[[1]](#references)</sup>

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten/akzeptierten komprimierten Bytes den erwarteten Bytes entsprechen).
- Den ECC-Trailer über den aufgefüllten Stream neu berechnen, damit Revit den geänderten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE Compound Document expandieren.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` zerlegen: Den Header beibehalten, den Payload mit gunzip dekomprimieren, Bytes ändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder mit gzip komprimieren.
- Zero-Padding beibehalten und den ECC-Trailer neu berechnen, damit Revit die neuen Bytes akzeptiert.
- Wenn eine deterministische Byte-für-Byte-Reproduktion erforderlich ist, einen minimalen Wrapper um Revit’s DLLs erstellen, um dessen gzip-/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder einen verfügbaren Helper wiederverwenden, der diese Semantik nachbildet.

3) Das OLE-Compound-Dokument neu erstellen.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Hinweise:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool schreibt storages/streams mit Escaping für Zeichen, die in NTFS-Namen ungültig sind, in das Dateisystem; der gewünschte stream path ist im output tree exakt `Global/Latest`.
- Beim Ausliefern von mass attacks über ecosystem plugins, die RFAs aus cloud storage abrufen, muss sichergestellt werden, dass die gepatchte RFA zunächst lokal die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor eine network injection versucht wird.

Exploitation insight (um anzuleiten, welche Bytes im gzip payload platziert werden sollen):<sup>[[1]](#references)</sup>

- Der Revit deserializer liest einen 16-Bit-class index und erstellt ein object. Bestimmte types sind non-polymorphic und verfügen über keine vtables; der Missbrauch der destructor handling führt zu einer type confusion, bei der die engine einen indirect call über einen vom attacker kontrollierten pointer ausführt.
- Die Auswahl von `AString` (class index `0x1F`) platziert einen vom attacker kontrollierten heap pointer an object offset 0. Während der destructor loop führt Revit effektiv Folgendes aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und richte einen Stack pivot in eine konventionelle x64-ROP chain ein.

Details zum Windows-x64-Pivot- und Gadget-Aufbau findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

und allgemeine ROP-Anleitungen hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Erweitern/Neuaufbauen von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere den Page Heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Zustellung simulieren, indem RFAs im Plugin-Traffic zu Testzwecken ausgetauscht werden.

## References

- [1] [Erstellen eines vollständigen RCE-Exploits aus einem Crash bei der Analyse von Autodesk-Revit-RFA-Dateien (ZDI-Blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Dokumentation zu OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-Dokumentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
