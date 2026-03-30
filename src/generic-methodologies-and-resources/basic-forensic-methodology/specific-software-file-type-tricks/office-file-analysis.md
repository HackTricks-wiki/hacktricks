# Office-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}


Für weitere Informationen siehe [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:

Microsoft hat viele Office-Dokumentformate geschaffen, wobei zwei Haupttypen **OLE formats** (wie RTF, DOC, XLS, PPT) und **Office Open XML (OOXML) formats** (wie DOCX, XLSX, PPTX) sind. Diese Formate können macros enthalten, wodurch sie Ziele für Phishing und malware werden. OOXML-Dateien sind als zip-Container strukturiert, was eine Inspektion durch Entpacken (unzip) ermöglicht und die Datei-/Ordnerhierarchie sowie die XML-Inhalte offenlegt.

Um OOXML-Dateistrukturen zu erkunden, werden der Befehl zum Entpacken eines Dokuments und die ausgegebene Struktur gezeigt. Techniken zum Verstecken von Daten in diesen Dateien wurden dokumentiert und zeigen anhaltende Innovationen bei der Datenverbergung in CTF-Challenges.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung sowohl von OLE- als auch OOXML-Dokumenten. Diese Tools helfen beim Erkennen und Analysieren eingebetteter macros, die häufig als Vektoren für die Auslieferung von malware dienen und typischerweise zusätzliche bösartige payloads herunterladen und ausführen. Die Analyse von VBA macros kann ohne Microsoft Office mit Libre Office durchgeführt werden, das Debugging mit breakpoints und watch variables ermöglicht.

Installation und Verwendung von **oletools** sind unkompliziert; Befehle zum Installieren via pip und zum Extrahieren von macros aus Dokumenten werden bereitgestellt. Die automatische Ausführung von macros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Speicher: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet bei Revit 2025):

- Header
- GZIP-komprimierte Nutzlast (der eigentliche serialisierte Objektgraph)
- Null-Padding
- Error-Correcting Code (ECC) trailer

Revit repariert automatisch kleine Veränderungen am Stream mithilfe des ECC-Trailers und verwirft Streams, die nicht mit dem ECC übereinstimmen. Daher bleiben naiv bearbeitete komprimierte Bytes nicht erhalten: Ihre Änderungen werden entweder zurückgesetzt oder die Datei wird abgelehnt. Um byte-genaue Kontrolle darüber zu haben, was der Deserialisierer sieht, müssen Sie:

- Mit einer Revit-kompatiblen gzip-Implementation neu komprimieren (so dass die von Revit erzeugten/akzeptierten komprimierten Bytes mit dem übereinstimmen, was Revit erwartet).
- Den ECC-Trailer über den gepaddeten Stream neu berechnen, damit Revit den modifizierten Stream ohne automatische Reparatur akzeptiert.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:

1) Das OLE Compound-Dokument entpacken
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Bearbeite `Global\Latest` unter Beachtung der gzip/ECC-Vorgaben

- Zerlege `Global/Latest`: behalte den Header, entpacke den Payload mit gunzip, verändere Bytes, und komprimiere dann wieder mit gzip unter Verwendung von Revit-kompatiblen Deflate-Parametern.
- Bewahre zero-padding und berechne den ECC-Trailer neu, sodass die neuen Bytes von Revit akzeptiert werden.
- Falls du eine deterministische Byte-für-Byte-Reproduktion benötigst, baue einen minimalen Wrapper um Revit’s DLLs, um dessen gzip/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder verwende einen verfügbaren Helper, der diese Semantik nachbildet.

3) Baue das OLE-Compounddokument neu auf
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Hinweise:

- CompoundFileTool schreibt storages/streams auf das Dateisystem mit Escaping für Zeichen, die in NTFS-Namen ungültig sind; der Stream-Pfad, den Sie benötigen, ist genau `Global/Latest` im Ausgabe-Baum.
- Beim Ausliefern von Massenangriffen über ecosystem plugins, die RFAs aus cloud storage abrufen, stellen Sie sicher, dass Ihre gepatchte RFA zunächst lokal die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor Sie network injection versuchen.

Exploitation insight (zur Anleitung, welche Bytes im gzip payload platziert werden sollen):

- Der Revit deserializer liest einen 16-bit class index und konstruiert ein Objekt. Bestimmte Typen sind non‑polymorphic und haben keine vtables; das Ausnutzen der destructor-Handhabung führt zu einer type confusion, bei der die engine einen indirekten Aufruf über einen attacker-controlled pointer ausführt.
- Die Wahl von `AString` (class index `0x1F`) platziert einen attacker-controlled heap pointer bei object offset 0. Während der destructor-Schleife führt Revit effektiv aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein gadget (“weird machine”) ausführt, und arrangiere einen stack pivot in eine konventionelle x64 ROP chain.

Siehe Details zum Windows x64 pivot/gadget building hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

und allgemeine ROP-Anleitung hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Werkzeuge:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; disable page heap with TTD to keep traces compact.
- A local proxy (e.g., Fiddler) can simulate supply-chain delivery by swapping RFAs in plugin traffic for testing.

## Referenzen

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
