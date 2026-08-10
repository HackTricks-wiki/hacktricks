# Analyse von Office-Dateien

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft-Office-Dokumente treten häufig als Legacy-Formate wie RTF und OLE/CFBF-basierte DOC-, XLS- und PPT-Dateien oder als neuere **Office Open XML (OOXML)**-Formate wie DOCX, XLSX und PPTX auf. Office-Dokumente können aktive Inhalte wie Makros enthalten, wodurch sie häufig als Phishing- und Malware-Träger verwendet werden. OOXML-Dateien sind ZIP-Container, deren Dateihierarchie und XML-Inhalte durch das Entpacken untersucht werden können.<sup>[[3]](#references)[[4]](#references)</sup>

Um die Strukturen von OOXML-Dateien zu untersuchen, werden der Befehl zum Entpacken eines Dokuments und die Ausgabestruktur angegeben. Techniken zum Verbergen von Daten in diesen Dateien wurden dokumentiert, was auf eine fortlaufende Innovation bei der Datenverschleierung in CTF-Herausforderungen hinweist.<sup>[[4]](#references)</sup>

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen beim Identifizieren und Analysieren eingebetteter Makros, die häufig als Vektoren für die Zustellung von Malware dienen und typischerweise zusätzliche schädliche Payloads herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office durchgeführt werden, indem Libre Office verwendet wird, das Debugging mit Breakpoints und Watch-Variablen ermöglicht.<sup>[[4]](#references)</sup>

Die Installation und Verwendung von **oletools** ist unkompliziert. Es werden Befehle für die Installation über pip und das Extrahieren von Makros aus Dokumenten bereitgestellt. In Word gehören `AutoExec` und `AutoOpen` zu den automatischen Makros, während `Document_Open` eine Open-Event-Prozedur ist.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
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
- GZIP-komprimierte Nutzdaten (der eigentliche serialisierte Objektgraph)
- Null-Padding
- Trailer mit Error-Correcting Code (ECC)

Revit repariert kleine Änderungen am Stream automatisch mithilfe des ECC-Trailers und weist Streams zurück, die nicht mit dem ECC übereinstimmen. Daher bleiben naive Änderungen an den komprimierten Bytes nicht bestehen: Die Änderungen werden entweder rückgängig gemacht oder die Datei wird zurückgewiesen. Um eine bytegenaue Kontrolle darüber zu gewährleisten, was der Deserializer sieht, musst du:<sup>[[1]](#references)</sup>

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten bzw. akzeptierten komprimierten Bytes den erwarteten Bytes entsprechen).
- Den ECC-Trailer über den aufgefüllten Stream neu berechnen, damit Revit den geänderten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE-Compound-Dokument erweitern.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) `Global/Latest` mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` dekonstruieren: den Header beibehalten, die Nutzdaten mit `gunzip` dekomprimieren, Bytes verändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder mit `gzip` komprimieren.
- Die Nullauffüllung beibehalten und den ECC-Trailer neu berechnen, damit Revit die neuen Bytes akzeptiert.
- Wenn eine deterministische bytegenaue Reproduktion erforderlich ist, einen minimalen Wrapper um Revit’s DLLs erstellen, um dessen gzip/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder einen verfügbaren Helper wiederverwenden, der diese Semantik nachbildet.

3) Das OLE-Verbunddokument neu erstellen.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool schreibt storages/streams mit Escaping für Zeichen in das Dateisystem, die in NTFS-Namen ungültig sind; der gewünschte Stream-Pfad ist im Ausgabebaum genau `Global/Latest`.
- Bei der Bereitstellung von Mass Attacks über Ecosystem-Plugins, die RFAs aus Cloud Storage abrufen, muss sichergestellt werden, dass die gepatchte RFA zunächst lokal Revit’s Integrity Checks besteht (gzip/ECC korrekt), bevor eine Network Injection versucht wird.

Exploitation Insight (als Hinweis darauf, welche Bytes im gzip-Payload platziert werden sollen):<sup>[[1]](#references)</sup>

- Der Revit-Deserializer liest einen 16-Bit-Class-Index und erstellt ein Objekt. Bestimmte Typen sind nicht polymorph und besitzen keine Vtables; der Missbrauch der Destruktorbehandlung führt zu einer Type Confusion, bei der die Engine einen indirekten Aufruf über einen vom Angreifer kontrollierten Pointer ausführt.
- Die Auswahl von `AString` (Class Index `0x1F`) platziert einen vom Angreifer kontrollierten Heap-Pointer an Objekt-Offset 0. Während der Destruktorschleife führt Revit effektiv Folgendes aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und arrangiere einen Stack Pivot in eine konventionelle x64-ROP-Kette.

Details zum Erstellen von Windows-x64-Pivots/Gadgets findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

und allgemeine ROP-Anleitungen hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tools:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Erweitern/Neuerstellen von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere den Page Heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Zustellung simulieren, indem RFAs im Plugin-Traffic zu Testzwecken ausgetauscht werden.

## References

- [1] [Erstellen eines vollständigen RCE-Exploits aus einem Crash bei der Analyse von Autodesk-Revit-RFA-Dateien (ZDI-Blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF)-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-Dokumentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
