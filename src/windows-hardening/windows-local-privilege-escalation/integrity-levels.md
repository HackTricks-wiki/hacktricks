# Integritätsstufen

{{#include ../../banners/hacktricks-training.md}}

## Integritätsstufen

In Windows Vista und späteren Versionen können sicherbare Objekte mit einer **Integritätsstufen**-Kennzeichnung versehen werden. Die meisten Objekte werden als Integrität auf mittlerer Stufe behandelt, während bestimmte Speicherorte, die für Anwendungen mit niedriger Integrität vorgesehen sind, als niedrig gekennzeichnet werden können. Von Standardbenutzern gestartete Prozesse laufen normalerweise mit mittlerer Integrität, Anwendungen mit erhöhten Rechten mit hoher Integrität und viele Dienste mit Systemintegrität.<sup>[[1]](#references)</sup>

Eine wichtige Regel lautet, dass Objekte nicht von Prozessen mit einer niedrigeren Integritätsstufe als der des Objekts verändert werden können. Windows wendet diese Prüfung durch Mandatory Integrity Control (MIC) an, bevor die Discretionary Access Control List (DACL) des Objekts ausgewertet wird. Die häufig anzutreffenden Stufen sind:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Die niedrigste Stufe, dargestellt durch `SECURITY_MANDATORY_UNTRUSTED_RID`. Als Beispiel aus der Praxis weist die Windows-Sandbox von Chromium Sandbox-Zielen zunächst die Integritätsstufe Low zu und senkt anschließend nach dem Start die Integritätsstufe von Renderer-Zielen auf Untrusted.<sup>[[5]](#references)</sup>
- **Low**: Hauptsächlich für Internetinteraktionen, insbesondere im geschützten Modus von Internet Explorer, wobei zugehörige Dateien und Prozesse sowie bestimmte Ordner wie der **Temporary Internet Folder** betroffen sind. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, darunter kein Schreibzugriff auf die Registry und ein eingeschränkter Schreibzugriff auf das Benutzerprofil.
- **Medium**: Die standardmäßige Stufe für die meisten Aktivitäten, die Standardbenutzern und Objekten ohne spezifische Integritätsstufen zugewiesen wird. Selbst Mitglieder der Gruppe Administrators arbeiten standardmäßig auf dieser Stufe.
- **High**: Administratoren vorbehalten. Sie ermöglicht das Ändern von Objekten mit niedrigeren Integritätsstufen, einschließlich solcher auf der Stufe High selbst.
- **System**: Die höchste operative Stufe für den Windows-Kernel und zentrale Dienste. Sie ist selbst für Administratoren nicht erreichbar und gewährleistet den Schutz wichtiger Systemfunktionen.

Windows definiert außerdem einen Integritätswert für geschützte Prozesse oberhalb von System. **TrustedInstaller** ist jedoch eine Windows-Dienstidentität und keine separate MIC-Stufe; die Fähigkeit, geschützte Betriebssystemressourcen zu ändern, ergibt sich aus den dieser Identität gewährten Berechtigungen.

Sie können die Integritätsstufe eines Prozesses mit **Process Explorer** aus **Sysinternals** ermitteln, indem Sie die Eigenschaften des Prozesses öffnen und die Registerkarte **Security** anzeigen:<sup>[[3]](#references)</sup>

![Integritätsstufen - Integritätsstufen: Sie können die Integritätsstufe eines Prozesses mit Process Explorer aus Sysinternals ermitteln, indem Sie die Eigenschaften des Prozesses öffnen und die Registerkarte "... anzeigen](<../../images/image (824).png>)

Sie können Ihre **aktuelle Integritätsstufe** auch mit `whoami /groups` ermitteln:

![Integritätsstufen - Integritätsstufen: Sie können Ihre aktuelle Integritätsstufe auch mit whoami /groups ermitteln](<../../images/image (325).png>)

### Integritätsstufen im Dateisystem

Ein Objekt im Dateisystem kann eine **Mindestanforderung an die Integritätsstufe** besitzen. Ein Prozess unterhalb dieser Stufe unterliegt der obligatorischen Richtlinie des Objekts, selbst wenn seine DACL ansonsten Zugriff gewähren würde. Erstellen Sie beispielsweise eine reguläre Datei über eine Konsole eines Standardbenutzers und überprüfen Sie ihre Berechtigungen:<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Weisen Sie der Datei nun eine minimale Integritätsstufe von **High** zu. Dies **muss über eine als **Administrator** ausgeführte Konsole** erfolgen, da eine reguläre Konsole mit mittlerer Integrität ausgeführt wird und **High**-Integrität für ein Objekt **nicht zuweisen darf**:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
Der Benutzer `DESKTOP-IDJHTKP\user` verfügt über **FULL privileges** für die Datei, da dieser Benutzer sie erstellt hat. Das mandatory label verhindert jedoch, dass der Benutzer die Datei ändern kann, solange der Prozess nicht mit hoher Integrität ausgeführt wird. Der Benutzer kann sie dennoch lesen, da die angezeigte mandatory policy `(NW)` lautet, also no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Wenn eine Datei daher über eine minimale Integritätsstufe verfügt, müssen Sie mindestens mit dieser Integritätsstufe ausgeführt werden, um sie zu ändern.**

### Integritätsstufen in Binärdateien

Das folgende Beispiel verwendet eine Kopie von `cmd.exe` unter `C:\Windows\System32\cmd-low.exe` und weist ihr **über eine Administratorkonsole die Integritätsstufe Low** zu:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Wenn ich nun `cmd-low.exe` ausführe, wird es **mit einem niedrigen Integritätslevel** statt mit einem mittleren ausgeführt:

![Integritätslevel im Dateisystem – Integritätslevel in Binärdateien: Wenn ich nun cmd-low.exe ausführe, wird es mit einem niedrigen Integritätslevel statt mit einem mittleren ausgeführt](<../../images/image (313).png>)

Das Zuweisen eines hohen Integritätslabels zu einer Binärdatei (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) führt nicht automatisch dazu, dass sie mit hohem Integritätslevel ausgeführt wird. Wird sie von einem Prozess mit mittlerem Integritätslevel aufgerufen, wird sie mit mittlerem Integritätslevel ausgeführt, da ein neuer Prozess den niedrigeren der beiden Integritätslevel der ausführbaren Datei und des aufrufenden Prozesses erhält.<sup>[[1]](#references)</sup>

### Integritätslevel in Prozessen

Nicht alle Dateien und Ordner verfügen über ein explizites Mindestintegritätslabel, **aber jeder Prozess wird mit einem Integritätslevel ausgeführt**. Wie bei Dateisystemobjekten gilt: **Ein Prozess, der Schreibzugriff auf einen anderen Prozess haben möchte, muss mindestens über dasselbe Integritätslevel verfügen**. Daher kann ein Prozess mit niedrigem Integritätslevel einen Prozess mit mittlerem Integritätslevel nicht mit vollständigem Zugriff öffnen.<sup>[[1]](#references)</sup>

Aufgrund dieser Einschränkungen ist es am sichersten, **jeden Prozess mit dem niedrigsten Integritätslevel auszuführen, mit dem er seine vorgesehene Aufgabe noch erfüllen kann**.

## References

- [1] [Microsoft Learn – Obligatorische Integritätskontrolle](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Aufzählung MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium-Quellcode – Standardmäßige Windows-Sandbox-Integritätsrichtlinie](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
