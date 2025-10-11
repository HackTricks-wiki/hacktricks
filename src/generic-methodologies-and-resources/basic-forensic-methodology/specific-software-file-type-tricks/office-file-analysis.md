# Office-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:

Microsoft hat viele Office-Dokumentformate geschaffen, wobei zwei Haupttypen **OLE formats** (wie RTF, DOC, XLS, PPT) und **Office Open XML (OOXML) formats** (z. B. DOCX, XLSX, PPTX) sind. Diese Formate können macros enthalten und sind daher häufig Ziel von Phishing und Malware. OOXML-Dateien sind als zip-Container strukturiert und erlauben durch Unzipping die Inspektion, wobei die Datei- und Ordnerhierarchie sowie die XML-Inhalte sichtbar werden.

Um OOXML-Dateistrukturen zu erkunden, werden der Befehl zum Unzippen eines Dokuments und die resultierende Struktur angegeben. Techniken zum Verstecken von Daten in diesen Dateien sind dokumentiert, was auf fortlaufende Innovationen in der Datenversteckung bei CTF-Challenges hinweist.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung sowohl von OLE- als auch OOXML-Dokumenten. Diese Tools helfen dabei, embedded macros zu identifizieren und zu analysieren, die oft als Vektoren für Malware-Auslieferung fungieren und typischerweise zusätzliche bösartige Payloads herunterladen und ausführen. Die Analyse von VBA-macros kann ohne Microsoft Office mit Libre Office durchgeführt werden, das Debugging mit Breakpoints und Watch-Variablen ermöglicht.

Installation und Nutzung von **oletools** sind unkompliziert; es werden Befehle zum Installieren via pip und zum Extrahieren von macros aus Dokumenten bereitgestellt. Die automatische Ausführung von macros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File Ausnutzung: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) gespeichert. Das serialisierte Modell liegt unter storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierte Nutzlast (der tatsächlich serialisierte Objektgraph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit repariert kleine Störungen im Stream automatisch mittels des ECC-Trailers und lehnt Streams ab, die nicht mit dem ECC übereinstimmen. Daher führen naive Änderungen an den komprimierten Bytes nicht zu dauerhaften Änderungen: Deine Änderungen werden entweder rückgängig gemacht oder die Datei wird abgelehnt. Um byte-genauen Einfluss darauf zu haben, was der Deserialisierer sieht, musst du:

- Mit einer Revit-kompatiblen gzip-Implementierung neu komprimieren (sodass die komprimierten Bytes, die Revit erzeugt/akzeptiert, denen entsprechen, die es erwartet).
- Den ECC-Trailer über den gepaddeten Stream neu berechnen, damit Revit den modifizierten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:

1) Expandiere das OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Bearbeite Global\Latest mit gzip/ECC-Disziplin

- Zerlege `Global/Latest`: behalte den Header, gunzip das Payload, verändere die Bytes und gzip es dann wieder unter Verwendung von Revit-kompatiblen Deflate-Parametern.
- Bewahre zero-padding und berechne den ECC-Trailer neu, damit die neuen Bytes von Revit akzeptiert werden.
- Wenn du eine deterministische Byte-für-Byte-Reproduktion brauchst, baue einen minimalen Wrapper um Revit’s DLLs, um dessen gzip/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder verwende einen vorhandenen Helfer, der diese Semantik repliziert.

3) Baue das OLE compound document neu auf
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Hinweise:

- CompoundFileTool schreibt storages/streams auf das Dateisystem mit Escaping für Zeichen, die in NTFS-Namen ungültig sind; der Stream-Pfad, den du brauchst, ist genau `Global/Latest` im Ausgabe-Baum.
- Beim Ausliefern von Massenangriffen über ecosystem plugins, die RFAs aus cloud storage abrufen, stelle sicher, dass dein gepatchtes RFA lokal zuerst Revit’s Integritätsprüfungen besteht (gzip/ECC korrekt), bevor du eine network injection versuchst.

Hinweis zur Ausnutzung (zur Anleitung, welche Bytes in die gzip-Payload zu platzieren sind):

- Der Revit deserializer liest einen 16‑Bit class index und konstruiert ein Objekt. Bestimmte Typen sind non‑polymorphic und besitzen keine vtables; das Ausnutzen der destructor‑Behandlung führt zu einer type confusion, bei der die engine einen indirect call über einen attacker-controlled pointer ausführt.
- Die Wahl von `AString` (class index `0x1F`) platziert einen attacker-controlled heap pointer bei object offset 0. Während der destructor loop führt Revit effektiv aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solche Objekte im serialized graph, sodass jede Iteration der destructor loop ein gadget (“weird machine”) ausführt und einen stack pivot in eine konventionelle x64 ROP chain arrangiert.

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
- IDA Pro + WinDBG TTD für reverse/taint; deaktiviere page heap mit TTD, um Spuren kompakt zu halten.
- Ein lokaler Proxy (z. B. Fiddler) kann supply-chain delivery simulieren, indem RFAs im Plugin-Traffic zum Testen ausgetauscht werden.

## Referenzen

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
