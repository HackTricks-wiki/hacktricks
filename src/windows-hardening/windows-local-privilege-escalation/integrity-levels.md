# Integritätsstufen

{{#include ../../banners/hacktricks-training.md}}

## Integritätsstufen

In Windows Vista und späteren Versionen können sicherbare Objekte ein Label für eine **Integritätsstufe** tragen. Die meisten Objekte werden als Integrität „Medium“ behandelt, während bestimmte für Anwendungen mit niedriger Integrität vorgesehene Speicherorte als „Low“ gekennzeichnet werden können. Von Standardbenutzern gestartete Prozesse werden normalerweise mit mittlerer Integrität ausgeführt, erhöhte Anwendungen mit hoher Integrität und viele Dienste mit Systemintegrität.<sup>[[1]](#references)</sup>

Eine wichtige Regel besagt, dass Objekte nicht von Prozessen geändert werden können, deren Integritätsstufe niedriger ist als die des Objekts. Windows wendet diese Prüfung durch Mandatory Integrity Control (MIC) an, bevor die Discretionary Access Control List (DACL) des Objekts ausgewertet wird. Die häufig anzutreffenden Stufen sind:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Die niedrigste Stufe, dargestellt durch `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Verwechsle dieses Integritätslabel nicht mit der Identität **Anonymous Logon** (`S-1-5-7`); Authentifizierungsidentitäten und MIC-Labels sind separate SID-Namespaces. Ein Beispiel aus der Praxis: Die Windows-Sandbox von Chromium weist Sandbox-Zielen zunächst die Integrität „Low“ zu und stuft Renderer-Ziele nach dem Start auf die Integrität „Untrusted“ herab.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: Hauptsächlich für Internetinteraktionen, insbesondere im Protected Mode von Internet Explorer, wodurch zugehörige Dateien und Prozesse sowie bestimmte Ordner wie der **Temporary Internet Folder** betroffen sind. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, darunter kein Schreibzugriff auf die Registry und ein eingeschränkter Schreibzugriff auf das Benutzerprofil.
- **Medium**: Die Standardstufe für die meisten Aktivitäten, die Standardbenutzern und Objekten ohne spezifische Integritätsstufe zugewiesen wird. Auch Mitglieder der Gruppe Administrators arbeiten standardmäßig auf dieser Stufe.
- **High**: Administratoren vorbehalten und ermöglicht ihnen, Objekte mit niedrigeren Integritätsstufen zu ändern, einschließlich solcher auf der Stufe „High“ selbst.
- **System**: Die höchste operative Stufe für den Windows-Kernel und zentrale Dienste. Sie ist selbst für Administratoren nicht erreichbar und schützt dadurch wichtige Systemfunktionen.

Windows definiert außerdem einen Integritätswert für geschützte Prozesse, der über „System“ liegt. **TrustedInstaller** ist jedoch eine Windows-Serviceidentität und keine separate MIC-Stufe. Die Berechtigung zum Ändern geschützter Betriebssystemressourcen ergibt sich aus den dieser Identität gewährten Berechtigungen.

Gehe nicht davon aus, dass ein Speicherort wie das Stammverzeichnis eines Systemlaufwerks immer ein festes Integritätslabel „High“ besitzt. Überprüfe die effektive DACL und jedes explizite Mandatory Label mit `icacls`; ein Objekt ohne Label wird für MIC als „Medium“ behandelt, während seine DACL und sein Besitz den Zugriff weiterhin unabhängig voneinander einschränken können.<sup>[[1]](#references)[[4]](#references)</sup>

Du kannst die Integritätsstufe eines Prozesses mit **Process Explorer** von **Sysinternals** ermitteln, indem du die Prozesseigenschaften öffnest und die Registerkarte **Security** aufrufst:<sup>[[3]](#references)</sup>

![Integritätsstufen - Integritätsstufen: Du kannst die Integritätsstufe eines Prozesses mit Process Explorer von Sysinternals ermitteln, indem du die Eigenschaften des Prozesses öffnest und ... aufrufst](<../../images/image (824).png>)

Du kannst deine **aktuelle Integritätsstufe** auch mit `whoami /groups` ermitteln:

![Integritätsstufen - Integritätsstufen: Du kannst deine aktuelle Integritätsstufe auch mit whoami /groups ermitteln](<../../images/image (325).png>)

### Integritätsstufen im Dateisystem

Ein Objekt im Dateisystem kann eine **Mindestanforderung an die Integritätsstufe** besitzen. Ein Prozess unterhalb dieser Stufe unterliegt der Mandatory Policy des Objekts, selbst wenn seine DACL ansonsten Zugriff gewähren würde. Erstelle beispielsweise eine normale Datei über eine Konsole eines Standardbenutzers und überprüfe ihre Berechtigungen:<sup>[[1]](#references)[[4]](#references)</sup>
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
Weisen Sie der Datei nun eine minimale Integritätsstufe von **High** zu. Dies **muss über eine Konsole** erfolgen, die als **Administrator** ausgeführt wird, da eine reguläre Konsole mit mittlerer Integrität ausgeführt wird und es **nicht erlaubt sein wird**, einem Objekt die Integritätsstufe High zuzuweisen:
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
Der Benutzer `DESKTOP-IDJHTKP\user` verfügt über **FULL privileges** für die Datei, da dieser Benutzer sie erstellt hat. Das Mandatory Label verhindert jedoch, dass der Benutzer die Datei verändert, solange der Prozess nicht mit High integrity ausgeführt wird. Der Benutzer kann sie weiterhin lesen, da die angezeigte Mandatory Policy `(NW)` lautet, also no-write-up:
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
Wenn ich nun `cmd-low.exe` ausführe, wird es **unter einer niedrigen Integritätsstufe** statt unter einer mittleren ausgeführt:

![Integritätsstufen im Dateisystem – Integritätsstufen in Binärdateien: Wenn ich nun cmd-low.exe ausführe, wird es unter einer niedrigen Integritätsstufe statt unter einer mittleren ausgeführt](<../../images/image (313).png>)

Das Zuweisen einer hohen Integritätskennzeichnung zu einer Binärdatei (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) führt nicht automatisch dazu, dass sie mit hoher Integrität ausgeführt wird. Wird sie von einem Prozess mit mittlerer Integrität gestartet, wird sie mit mittlerer Integrität ausgeführt, da ein neuer Prozess die niedrigere der Integritätsstufen der ausführbaren Datei und des aufrufenden Prozesses erhält.<sup>[[1]](#references)</sup>

### Integritätsstufen in Prozessen

Nicht alle Dateien und Ordner verfügen über eine explizite minimale Integritätskennzeichnung, **aber jeder Prozess wird mit einer Integritätsstufe ausgeführt**. Wie bei Dateisystemobjekten gilt: **Ein Prozess, der Schreibzugriff auf einen anderen Prozess erhalten möchte, muss mindestens über dieselbe Integritätsstufe verfügen**. Daher kann ein Prozess mit niedriger Integrität einen Prozess mit mittlerer Integrität nicht mit vollständigem Zugriff öffnen.<sup>[[1]](#references)</sup>

Aufgrund dieser Einschränkungen besteht der sicherste Ansatz darin, **jeden Prozess mit der niedrigsten Integritätsstufe auszuführen, die noch die vorgesehene Aufgabe ermöglicht**.

## References

- [1] [Microsoft Learn – Obligatorische Integritätskontrolle](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Aufzählung MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium-Quellcode – Standardintegritätsrichtlinie der Windows-Sandbox](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Bekannte SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
