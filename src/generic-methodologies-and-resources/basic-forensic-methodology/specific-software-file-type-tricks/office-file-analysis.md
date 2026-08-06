# Analyse von Office-Dateien

{{#include ../../../banners/hacktricks-training.md}}


Weitere Informationen findest du unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist lediglich eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft hat viele Office-Dokumentformate erstellt. Die beiden Haupttypen sind **OLE-Formate** (wie RTF, DOC, XLS, PPT) und **Office Open XML (OOXML)-Formate** (wie DOCX, XLSX, PPTX). Diese Formate können Makros enthalten und sind dadurch Ziele für Phishing und Malware. OOXML-Dateien sind als ZIP-Container strukturiert, wodurch sie durch das Entpacken untersucht werden können. Dabei werden die Datei- und Ordnerhierarchie sowie die Inhalte der XML-Dateien sichtbar.

Um die Strukturen von OOXML-Dateien zu untersuchen, werden der Befehl zum Entpacken eines Dokuments und die resultierende Struktur gezeigt. Techniken zum Verstecken von Daten in diesen Dateien wurden dokumentiert, was auf eine fortlaufende Weiterentwicklung der Datenverschleierung in CTF-Challenges hindeutet.

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen dabei, eingebettete Makros zu identifizieren und zu analysieren, die häufig als Vektoren für die Bereitstellung von Malware dienen und typischerweise zusätzliche bösartige Payloads herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office durchgeführt werden, indem Libre Office verwendet wird. Dies ermöglicht das Debugging mit Breakpoints und Watch-Variablen.

Installation und Verwendung von **oletools** sind unkompliziert. Es werden Befehle zur Installation über pip und zum Extrahieren von Makros aus Dokumenten bereitgestellt. Die automatische Ausführung von Makros wird durch Funktionen wie `AutoOpen`, `AutoExec` oder `Document_Open` ausgelöst.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Ausnutzung von OLE Compound Files: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit-RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (auch CFBF genannt) gespeichert. Das serialisierte Modell befindet sich unter storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierte Nutzlast (der tatsächlich serialisierte Objektgraph)
- Nullpadding
- Error-Correcting-Code-(ECC-)Trailer

Revit repariert kleine Änderungen am Stream automatisch mithilfe des ECC-Trailers und weist Streams zurück, die nicht zum ECC passen. Daher bleiben naive Änderungen an den komprimierten Bytes nicht erhalten: Deine Änderungen werden entweder rückgängig gemacht oder die Datei wird zurückgewiesen. Um eine bytegenaue Kontrolle darüber sicherzustellen, was der Deserializer sieht, musst du:

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten/akzeptierten komprimierten Bytes den erwarteten Bytes entsprechen).
- Den ECC-Trailer über den aufgefüllten Stream neu berechnen, damit Revit den geänderten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE-Compound-Dokument erweitern
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) `Global\Latest` mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` dekonstruieren: Den Header beibehalten, den Payload mit gunzip entpacken, Bytes ändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder gzip-komprimieren.
- Zero-Padding beibehalten und den ECC-Trailer neu berechnen, damit Revit die neuen Bytes akzeptiert.
- Für eine deterministische Byte-für-Byte-Reproduktion einen minimalen Wrapper um Revit-DLLs erstellen, um dessen gzip-/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder einen verfügbaren Helper wiederverwenden, der diese Semantik nachbildet.

3) Das OLE-Compound-Dokument neu erstellen
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool schreibt Storages/Streams mit Escaping für Zeichen, die in NTFS-Namen ungültig sind, in das Dateisystem; der gewünschte Stream-Pfad lautet im Ausgabe tree exakt `Global/Latest`.
- Stelle bei der Bereitstellung von Mass Attacks über Ecosystem-Plugins, die RFAs aus Cloud Storage abrufen, sicher, dass deine gepatchte RFA zunächst lokal die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor du eine Network Injection versuchst.

Exploitation insight (als Orientierung dafür, welche Bytes im gzip-Payload platziert werden sollen):<sup>[[1]](#references)</sup>

- Der Revit-Deserializer liest einen 16-Bit-Class-Index und erstellt ein Objekt. Bestimmte Typen sind nicht polymorph und verfügen über keine Vtables; der Missbrauch der Destruktorbehandlung führt zu einer Type Confusion, bei der die Engine einen indirekten Aufruf über einen vom Angreifer kontrollierten Pointer ausführt.
- Die Auswahl von `AString` (Class-Index `0x1F`) platziert einen vom Angreifer kontrollierten Heap-Pointer am Objekt-Offset 0. Während der Destruktor-Schleife führt Revit effektiv Folgendes aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und richte einen Stack pivot in eine konventionelle x64-ROP-Kette ein.

Details zum Windows-x64-Pivot- und Gadget-Aufbau findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

Allgemeine Hinweise zu ROP findest du hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Werkzeuge:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Erweitern und Neuerstellen von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere den page heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Zustellung simulieren, indem RFAs im Plugin-Datenverkehr zu Testzwecken ausgetauscht werden.

## Referenzen

- [1] [Erstellen eines vollständigen RCE-Exploits aus einem Crash beim Parsen von Autodesk-Revit-RFA-Dateien (ZDI-Blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE-Compound-Datei-(CFBF)-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
