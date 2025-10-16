# Office-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}


Für weitere Informationen siehe [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:

Microsoft hat viele Office-Dokumentformate geschaffen, wobei zwei Haupttypen **OLE formats** (wie RTF, DOC, XLS, PPT) und **Office Open XML (OOXML) formats** (wie DOCX, XLSX, PPTX) sind. Diese Formate können Makros enthalten, wodurch sie Ziele für Phishing und Malware darstellen. OOXML-Dateien sind als zip-Container strukturiert, was eine Untersuchung durch Entpacken ermöglicht und die Datei- und Ordnerhierarchie sowie den XML-Inhalt offenlegt.

Um OOXML-Dateistrukturen zu untersuchen, werden der Befehl zum Entpacken eines Dokuments und die Ausgabe-Struktur angegeben. Techniken zum Verstecken von Daten in diesen Dateien wurden dokumentiert, was auf fortlaufende Innovationen bei der Datenverbergung in CTF-Challenges hinweist.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung sowohl von OLE- als auch OOXML-Dokumenten. Diese Tools helfen, eingebettete Makros zu identifizieren und zu analysieren, die oft als Vektoren zur Malware-Auslieferung dienen und typischerweise zusätzliche bösartige Nutzlasten herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office mit Libre Office durchgeführt werden, das Debugging mit Breakpoints und Watch-Variablen ermöglicht.

Installation und Nutzung von **oletools** sind unkompliziert; es werden Befehle angegeben, um via pip zu installieren und Makros aus Dokumenten zu extrahieren. Die automatische Ausführung von Makros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) gespeichert. Das serialisierte Modell befindet sich unter storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit repariert kleine Störungen im Stream automatisch mithilfe des ECC trailer und lehnt Streams ab, die nicht mit dem ECC übereinstimmen. Daher bleiben naive Änderungen an den komprimierten Bytes nicht bestehen: Ihre Änderungen werden entweder zurückgesetzt oder die Datei wird abgelehnt. Um eine byte-genaue Kontrolle darüber zu gewährleisten, was der Deserializer sieht, müssen Sie:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:

1) Das OLE compound document erweitern
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest mit gzip/ECC-Disziplin bearbeiten

- Zerlege `Global/Latest`: behalte den Header, gunzip das payload, verändere Bytes, und gzip es dann wieder unter Verwendung Revit-kompatibler Deflate-Parameter.
- Bewahre zero-padding und berechne den ECC-Trailer neu, damit die neuen Bytes von Revit akzeptiert werden.
- Falls du eine deterministische byte-for-byte-Reproduktion brauchst, baue einen minimalen Wrapper um Revit’s DLLs, um dessen gzip/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder verwende einen verfügbaren Helfer, der diese Semantik repliziert.

3) Das OLE-Compound-Dokument neu aufbauen
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Hinweise:

- CompoundFileTool schreibt storages/streams auf das Dateisystem mit escaping für Zeichen, die in NTFS-Namen ungültig sind; der Stream-Pfad, den Sie benötigen, ist genau `Global/Latest` im Ausgabebaum.
- Beim Ausliefern von mass attacks über ecosystem plugins, die RFAs aus cloud storage abrufen, stellen Sie sicher, dass Ihr gepatchtes RFA lokal zuerst Revit’s integrity checks besteht (gzip/ECC korrekt), bevor Sie network injection versuchen.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Der Revit deserializer liest einen 16-bit class index und konstruiert ein object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Die Wahl von `AString` (class index `0x1F`) platziert einen attacker-controlled heap pointer bei object offset 0. Während der destructor loop führt Revit effektiv aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein gadget (“weird machine”) ausführt, und arrangiere einen stack pivot in eine konventionelle x64 ROP chain.

Siehe Windows x64 pivot/gadget building details hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

und allgemeine ROP guidance hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Werkzeuge:

- CompoundFileTool (OSS) zum Erweitern/Wiederaufbauen von OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD für reverse/taint; deaktiviere page heap mit TTD, um Traces kompakt zu halten.
- Ein lokaler Proxy (z. B. Fiddler) kann supply-chain delivery simulieren, indem RFAs im plugin traffic für Tests ausgetauscht werden.

## Referenzen

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
