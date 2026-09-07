# Analyse von Office-Dateien

{{#include ../../../banners/hacktricks-training.md}}

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist lediglich eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft-Office-Dokumente treten häufig als ältere Formate wie RTF und OLE/CFBF-basierte DOC-, XLS- und PPT-Dateien oder als neuere **Office Open XML (OOXML)**-Formate wie DOCX, XLSX und PPTX auf. Office-Dokumente können aktive Inhalte wie Makros enthalten, wodurch sie häufig als Träger für Phishing und Malware dienen. OOXML-Dateien sind ZIP-Container, deren Dateihierarchie und XML-Inhalte durch das Entpacken untersucht werden können.<sup>[[3]](#references)[[4]](#references)</sup>

Um OOXML-Dateistrukturen zu untersuchen, werden der Befehl zum Entpacken eines Dokuments und die Ausgabestruktur angegeben. Techniken zum Verbergen von Daten in diesen Dateien wurden dokumentiert, was auf fortlaufende Innovationen bei der Datenverschleierung in CTF-Herausforderungen hinweist.<sup>[[4]](#references)</sup>

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung sowohl von OLE- als auch von OOXML-Dokumenten. Diese Tools helfen dabei, eingebettete Makros zu identifizieren und zu analysieren, die häufig als Vektoren für die Zustellung von Malware dienen und typischerweise zusätzliche bösartige Payloads herunterladen und ausführen. Die Analyse von VBA-Makros kann ohne Microsoft Office durchgeführt werden, indem Libre Office verwendet wird, das Debugging mit Breakpoints und Watch-Variablen ermöglicht.<sup>[[4]](#references)</sup>

Installation und Verwendung von **oletools** sind unkompliziert. Es werden Befehle für die Installation via pip und das Extrahieren von Makros aus Dokumenten bereitgestellt. In Word gehören `AutoExec` und `AutoOpen` zu den automatischen Makros, während `Document_Open` eine Open-Event-Prozedur ist.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Für password-encrypted Office-Dokumente siehe den [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit-RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (auch CFBF genannt) gespeichert. Das serialisierte Modell befindet sich unter storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Wichtiger Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierter Payload (der tatsächlich serialisierte Objektgraph)
- Null-Padding
- Error-Correcting-Code-(ECC-)Trailer

Revit repariert kleine Änderungen am Stream mithilfe des ECC-Trailers automatisch und weist Streams zurück, die nicht mit dem ECC übereinstimmen. Daher bleiben naiv vorgenommene Änderungen an den komprimierten Bytes nicht erhalten: Deine Änderungen werden entweder zurückgesetzt oder die Datei wird abgewiesen. Um bytegenau zu kontrollieren, was der Deserializer sieht, musst du:<sup>[[1]](#references)</sup>

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten/akzeptierten komprimierten Bytes den erwarteten Bytes entsprechen).
- Den ECC-Trailer über den gepaddeten Stream neu berechnen, damit Revit den modifizierten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE-Compound-Dokument expandieren.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) `Global\Latest` mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` dekonstruieren: Den Header beibehalten, den Payload entpacken, die Bytes ändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder gzip-komprimieren.
- Zero-Padding beibehalten und den ECC-Trailer neu berechnen, damit die neuen Bytes von Revit akzeptiert werden.
- Wenn eine deterministische Byte-für-Byte-Reproduktion erforderlich ist, einen minimalen Wrapper um die Revit-DLLs erstellen, um deren gzip-/gunzip-Pfade und ECC-Berechnung aufzurufen (wie in der Forschung demonstriert), oder einen verfügbaren Helper wiederverwenden, der diese Semantik nachbildet.

3) Das OLE-Compound-Dokument neu erstellen.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Hinweise:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool schreibt Storages/Streams mit Escaping für Zeichen, die in NTFS-Namen ungültig sind, in das Dateisystem; der gewünschte Stream-Pfad ist im Ausgabe-Baum exakt `Global/Latest`.
- Wenn du massenhafte Angriffe über Ecosystem-Plugins bereitstellst, die RFAs aus Cloud-Speicher abrufen, stelle sicher, dass deine gepatchte RFA zunächst lokal die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor du eine Netzwerk-Injection versuchst.

Exploitation insight (als Orientierung dafür, welche Bytes im gzip-Payload platziert werden sollen):<sup>[[1]](#references)</sup>

- Der Revit-Deserializer liest einen 16-Bit-Klassenindex und erstellt ein Objekt. Bestimmte Typen sind nicht polymorph und besitzen keine Vtables; der Missbrauch der Destruktorbehandlung führt zu einer Type Confusion, bei der die Engine einen indirekten Aufruf über einen vom Angreifer kontrollierten Pointer ausführt.
- Die Auswahl von `AString` (Klassenindex `0x1F`) platziert einen vom Angreifer kontrollierten Heap-Pointer an Objekt-Offset 0. Während der Destruktor-Schleife führt Revit effektiv Folgendes aus:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und richte einen Stack Pivot in eine konventionelle x64-ROP-Kette ein.

Details zum Windows-x64-Pivot- und Gadget-Building findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

und allgemeine ROP-Anleitungen hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Werkzeuge:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Erweitern/Neuaufbauen von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere den Page Heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Zustellung simulieren, indem RFAs im Plugin-Traffic zu Testzwecken ausgetauscht werden.

## References

- [1] [Erstellen eines vollständigen RCE-Exploits aus einem Crash bei der Analyse von Autodesk-Revit-RFA-Dateien (ZDI-Blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF)-Dokumentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics-CTF-Feldleitfaden](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-Dokumentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open-Ereignis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
