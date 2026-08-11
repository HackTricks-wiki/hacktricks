# Integritätsstufen

{{#include ../../banners/hacktricks-training.md}}

## Integritätsstufen

In Windows Vista und späteren Versionen können sicherbare Objekte mit einer **Integritätsstufen**-Kennzeichnung versehen werden. Die meisten Objekte werden als Objekte mit mittlerer Integrität behandelt, während bestimmte Speicherorte, die für Anwendungen mit niedriger Integrität vorgesehen sind, als „Low“ gekennzeichnet werden können. Von Standardbenutzern gestartete Prozesse werden normalerweise mit mittlerer Integrität ausgeführt, Anwendungen mit erhöhten Rechten mit hoher Integrität und viele Dienste mit Systemintegrität.<sup>[[1]](#references)</sup>

Eine wichtige Regel besagt, dass Objekte nicht von Prozessen mit einer niedrigeren Integritätsstufe als der des Objekts geändert werden können. Windows wendet diese Prüfung durch Mandatory Integrity Control (MIC) an, bevor die Discretionary Access Control List (DACL) des Objekts ausgewertet wird. Die häufig vorkommenden Stufen sind:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: Die niedrigste Stufe, dargestellt durch `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Hauptsächlich für Interaktionen mit dem Internet, insbesondere im Protected Mode von Internet Explorer. Sie betrifft zugehörige Dateien und Prozesse sowie bestimmte Ordner wie den **Temporary Internet Folder**. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, darunter kein Schreibzugriff auf die Registry und ein eingeschränkter Schreibzugriff auf Benutzerprofile.
- **Medium**: Die Standardstufe für die meisten Aktivitäten. Sie wird Standardbenutzern und Objekten ohne spezifische Integritätsstufe zugewiesen. Selbst Mitglieder der Gruppe Administrators arbeiten standardmäßig auf dieser Stufe.
- **High**: Administratoren vorbehalten. Sie können damit Objekte auf niedrigeren Integritätsstufen ändern, einschließlich Objekten auf der hohen Integritätsstufe selbst.
- **System**: Die höchste operative Stufe für den Windows-Kernel und zentrale Dienste. Sie liegt selbst außerhalb der Reichweite von Administratoren und gewährleistet den Schutz wichtiger Systemfunktionen.

Windows definiert außerdem einen Integritätswert für geschützte Prozesse, der über System liegt. **TrustedInstaller** ist jedoch eine Windows-Dienstidentität und keine separate MIC-Stufe. Die Fähigkeit, geschützte Betriebssystemressourcen zu ändern, ergibt sich aus den Berechtigungen, die dieser Identität gewährt werden.

Die Integritätsstufe eines Prozesses kann mit **Process Explorer** von **Sysinternals** ermittelt werden, indem die Eigenschaften des Prozesses geöffnet und die Registerkarte **Security** angezeigt wird:<sup>[[3]](#references)</sup>

![Integritätsstufen - Integritätsstufen: Sie können die Integritätsstufe eines Prozesses mit Process Explorer von Sysinternals ermitteln, indem Sie auf die Eigenschaften des Prozesses zugreifen und die ...](<../../images/image (824).png>)

Sie können Ihre **aktuelle Integritätsstufe** auch mit `whoami /groups` ermitteln:

![Integritätsstufen - Integritätsstufen: Sie können Ihre aktuelle Integritätsstufe auch mit whoami /groups ermitteln](<../../images/image (325).png>)

### Integritätsstufen im Dateisystem

Ein Objekt im Dateisystem kann eine **Mindestanforderung an die Integritätsstufe** besitzen. Ein Prozess unterhalb dieser Stufe unterliegt der Mandatory Policy des Objekts, selbst wenn seine DACL andernfalls Zugriff gewähren würde. Erstellen Sie beispielsweise eine reguläre Datei über eine Konsole mit einem Standardbenutzer und überprüfen Sie deren Berechtigungen:<sup>[[1]](#references)[[4]](#references)</sup>
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
Weisen Sie der Datei nun eine minimale Integritätsstufe von **High** zu. Dies **muss über eine Konsole** erfolgen, die als **Administrator** ausgeführt wird, da eine reguläre Konsole mit mittlerer Integrität ausgeführt wird und **nicht berechtigt ist**, einem Objekt die Integritätsstufe High zuzuweisen:
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
Der Benutzer `DESKTOP-IDJHTKP\user` verfügt über **FULL privileges** für die Datei, da dieser Benutzer sie erstellt hat. Das Mandatory Label verhindert jedoch, dass der Benutzer die Datei ändert, solange der Prozess nicht mit hoher Integrität ausgeführt wird. Der Benutzer kann sie weiterhin lesen, da die angezeigte Mandatory Policy `(NW)` lautet, also no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Wenn eine Datei daher eine minimale Integritätsstufe besitzt, müssen Sie mindestens mit dieser Integritätsstufe ausgeführt werden, um sie zu ändern.**

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
Jetzt wird `cmd-low.exe` bei der Ausführung **unter einer niedrigen Integritätsstufe** statt unter einer mittleren ausgeführt:

![Integritätsstufen im Dateisystem – Integritätsstufen in Binärdateien: Jetzt wird cmd-low.exe bei der Ausführung unter einer niedrigen Integritätsstufe statt unter einer mittleren ausgeführt](<../../images/image (313).png>)

Das Zuweisen einer hohen Integritätsmarkierung zu einer Binärdatei (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) sorgt nicht automatisch dafür, dass sie mit hoher Integrität ausgeführt wird. Wird sie von einem Prozess mit mittlerer Integrität gestartet, wird sie mit mittlerer Integrität ausgeführt, da ein neuer Prozess die niedrigere der Integritätsstufen der ausführbaren Datei und des aufrufenden Prozesses erhält.<sup>[[1]](#references)</sup>

### Integritätsstufen in Prozessen

Nicht alle Dateien und Ordner verfügen über eine explizite minimale Integritätsmarkierung, **aber jeder Prozess wird mit einer Integritätsstufe ausgeführt**. Wie bei Dateisystemobjekten gilt auch hier: **Ein Prozess, der Schreibzugriff auf einen anderen Prozess erhalten möchte, muss mindestens dieselbe Integritätsstufe besitzen**. Daher kann ein Prozess mit niedriger Integrität keinen Prozess mit mittlerer Integrität mit vollständigem Zugriff öffnen.<sup>[[1]](#references)</sup>

Aufgrund dieser Einschränkungen ist es am sichersten, **jeden Prozess mit der niedrigsten Integritätsstufe auszuführen, die ihm noch die vorgesehene Arbeit ermöglicht**.

## References

- [1] [Microsoft Learn – Obligatorische Integritätskontrolle](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Aufzählung MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
