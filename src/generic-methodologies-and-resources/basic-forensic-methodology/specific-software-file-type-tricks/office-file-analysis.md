# Analyse von Office-Dateien

{{#include ../../../banners/hacktricks-training.md}}

Weitere Informationen finden Sie unter [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dies ist nur eine Zusammenfassung:<sup>[[4]](#references)</sup>

Microsoft-Office-Dokumente liegen häufig in älteren Formaten wie RTF und OLE/CFBF-basierten DOC-, XLS- und PPT-Dateien oder in neueren **Office Open XML (OOXML)**-Formaten wie DOCX, XLSX und PPTX vor. Office-Dokumente können aktive Inhalte wie Makros enthalten und sind daher häufige Träger von Phishing-Angriffen und Malware. OOXML-Dateien sind ZIP-Container, deren Dateihierarchie und XML-Inhalte sich durch Entpacken untersuchen lassen.<sup>[[3]](#references)[[4]](#references)</sup>

Zum Erkunden der Strukturen von OOXML-Dateien werden der Befehl zum Entpacken eines Dokuments und die resultierende Verzeichnisstruktur gezeigt. Techniken zum Verstecken von Daten in diesen Dateien sind dokumentiert und zeigen, dass die Datenverschleierung in CTF-Challenges ständig weiterentwickelt wird.<sup>[[4]](#references)</sup>

Für die Analyse bieten **oletools** und **OfficeDissector** umfassende Toolsets zur Untersuchung von OLE- und OOXML-Dokumenten. Diese Tools helfen dabei, eingebettete Makros zu erkennen und zu analysieren, die häufig als Vektoren für die Verbreitung von Malware dienen und üblicherweise zusätzliche schädliche Payloads herunterladen und ausführen. VBA-Makros lassen sich ohne Microsoft Office analysieren, indem Libre Office verwendet wird. Damit ist das Debuggen mit Breakpoints und Watch-Variablen möglich.<sup>[[4]](#references)</sup>

**oletools** lässt sich einfach installieren und verwenden. Die entsprechenden Befehle zur Installation mit pip und zum Extrahieren von Makros aus Dokumenten werden angegeben. In Word gehören `AutoExec` und `AutoOpen` zu den automatischen Makros, während `Document_Open` eine Prozedur für das Öffnungsereignis ist.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Für passwortverschlüsselte Office-Dokumente siehe den [grammatikgesteuerten Offline-Recovery-Workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## OLE Compound File-Exploitation: Autodesk Revit RFA – ECC-Neuberechnung und kontrolliertes gzip

Revit-RFA-Modelle werden als [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (auch CFBF genannt) gespeichert. Das serialisierte Modell befindet sich in Storage/Stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Aufbau von `Global\Latest` (beobachtet in Revit 2025):

- Header
- GZIP-komprimierte Payload (der tatsächlich serialisierte Objektgraph)
- Null-Padding
- ECC-Trailer (Error-Correcting Code)

Revit repariert mithilfe des ECC-Trailers automatisch kleinere Änderungen am Stream und weist Streams zurück, die nicht mit dem ECC übereinstimmen. Daher bleiben Änderungen nicht erhalten, wenn man die komprimierten Bytes naiv bearbeitet: Entweder werden die Änderungen rückgängig gemacht oder die Datei wird zurückgewiesen. Damit der Deserializer bytegenau kontrollieren kann, was er vorfindet, musst du:<sup>[[1]](#references)</sup>

- Mit einer Revit-kompatiblen gzip-Implementierung erneut komprimieren (damit die von Revit erzeugten bzw. akzeptierten komprimierten Bytes den erwarteten Bytes entsprechen).
- Den ECC-Trailer über den gepaddeten Stream neu berechnen, damit Revit den geänderten Stream akzeptiert, ohne ihn automatisch zu reparieren.

Praktischer Workflow zum Patchen/Fuzzing von RFA-Inhalten:<sup>[[1]](#references)</sup>

1) Das OLE-Compound-Dokument entpacken.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) `Global\Latest` mit gzip/ECC-Disziplin bearbeiten

- `Global/Latest` zerlegen: Header beibehalten, Payload dekomprimieren, Bytes ändern und anschließend mit Revit-kompatiblen Deflate-Parametern wieder komprimieren.
- Zero-Padding beibehalten und den ECC-Trailer neu berechnen, damit Revit die neuen Bytes akzeptiert.
- Für eine deterministische, bytegenaue Reproduktion einen minimalen Wrapper um Revits DLLs erstellen, der die Gzip-/Gunzip-Pfade und die ECC-Berechnung aufruft (wie in der Forschung gezeigt), oder einen verfügbaren Helper verwenden, der diese Semantik nachbildet.

3) Das OLE-Compound-Dokument neu erstellen.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Hinweise:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool schreibt Storages/Streams mit Escaping für Zeichen, die in NTFS-Namen ungültig sind, in das Dateisystem; der Stream-Pfad, den du benötigst, lautet im Ausgabebaum genau `Global/Latest`.
- Wenn du Massenangriffe über Ökosystem-Plugins auslieferst, die RFAs aus Cloud-Speichern abrufen, stelle zuerst lokal sicher, dass deine gepatchte RFA die Integritätsprüfungen von Revit besteht (gzip/ECC korrekt), bevor du eine Netzwerkinjection versuchst.

Exploitation-Einblick (als Orientierung dafür, welche Bytes in den gzip-Payload eingefügt werden sollen):<sup>[[1]](#references)</sup>

- Der Revit-Deserialisierer liest einen 16-Bit-Klassenindex und erstellt ein Objekt. Bestimmte Typen sind nicht polymorph und haben keine Vtables; durch Missbrauch der Destruktorbehandlung entsteht eine type confusion, bei der die Engine einen indirekten Aufruf über einen vom Angreifer kontrollierten Pointer ausführt.
- Die Auswahl von `AString` (Klassenindex `0x1F`) platziert einen vom Angreifer kontrollierten Heap-Pointer am Objekt-Offset 0. Während der Destruktor-Schleife führt Revit effektiv Folgendes aus:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Platziere mehrere solcher Objekte im serialisierten Graphen, sodass jede Iteration der Destruktor-Schleife ein Gadget („weird machine“) ausführt, und richte einen Stack-Pivot in eine herkömmliche x64-ROP-Chain ein.

Details zum Windows-x64-Pivot/Gadget-Aufbau findest du hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

Allgemeine Hinweise zu ROP findest du hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Werkzeuge:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) zum Entpacken und Neuerstellen von OLE-Compound-Dateien: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD für Reverse Engineering/Taint-Analyse; deaktiviere Page Heap mit TTD, damit die Traces kompakt bleiben.
- Ein lokaler Proxy (z. B. Fiddler) kann die Supply-Chain-Auslieferung simulieren, indem er zum Testen RFAs im Plugin-Traffic austauscht.

## References

- [1] [Erstellung eines vollständigen RCE-Exploits aus einem Crash beim Parsen von Autodesk-Revit-RFA-Dateien (ZDI-Blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE-Compound-File-Dokumentation (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensik-CTF-Leitfaden](https://trailofbits.github.io/ctf/forensics/)
- [5] [Dokumentation zu olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Automakros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open-Ereignis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
