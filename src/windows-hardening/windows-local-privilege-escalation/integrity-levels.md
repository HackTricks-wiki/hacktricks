# Integritätsstufen

{{#include ../../banners/hacktricks-training.md}}

## Integritätsstufen

In Windows Vista und späteren Versionen verfügen alle geschützten Elemente über ein **Integritätsstufen**-Tag. Diese Konfiguration weist Dateien und Registrierungsschlüsseln größtenteils eine Integritätsstufe von „mittel“ zu, mit Ausnahme bestimmter Ordner und Dateien, in die Internet Explorer 7 mit einer niedrigen Integritätsstufe schreiben kann. Standardmäßig verfügen von Standardbenutzern gestartete Prozesse über eine mittlere Integritätsstufe, während Dienste typischerweise mit einer Systemintegritätsstufe ausgeführt werden. Ein Label mit hoher Integrität schützt das Stammverzeichnis.

Eine wichtige Regel lautet, dass Objekte nicht von Prozessen mit einer niedrigeren Integritätsstufe als der des Objekts verändert werden können. Die Integritätsstufen sind:

- **Untrusted**: Diese Stufe gilt für Prozesse mit anonymen Logins. Beispiel: Chrome
- **Low**: Wird hauptsächlich für Internetinteraktionen verwendet, insbesondere im geschützten Modus von Internet Explorer. Sie betrifft zugehörige Dateien und Prozesse sowie bestimmte Ordner wie den **Temporary Internet Folder**. Prozesse mit niedriger Integrität unterliegen erheblichen Einschränkungen, darunter kein Schreibzugriff auf die Registry und ein eingeschränkter Schreibzugriff auf das Benutzerprofil.
- **Medium**: Die Standardstufe für die meisten Aktivitäten. Sie wird Standardbenutzern und Objekten ohne bestimmte Integritätsstufe zugewiesen. Selbst Mitglieder der Administratorengruppe arbeiten standardmäßig mit dieser Stufe.
- **High**: Administratoren vorbehalten. Sie ermöglicht ihnen, Objekte mit niedrigeren Integritätsstufen zu ändern, einschließlich Objekten auf der hohen Stufe selbst.
- **System**: Die höchste operative Stufe für den Windows-Kernel und zentrale Dienste. Sie ist selbst für Administratoren unerreichbar und schützt dadurch wichtige Systemfunktionen.
- **Installer**: Eine einzigartige Stufe, die über allen anderen liegt und es Objekten auf dieser Stufe ermöglicht, jedes andere Objekt zu deinstallieren.

Du kannst die Integritätsstufe eines Prozesses mit **Process Explorer** von **Sysinternals** ermitteln, indem du die **Eigenschaften** des Prozesses öffnest und den Tab "**Security**" aufrufst:

![Integritätsstufen - Integritätsstufen: Du kannst die Integritätsstufe eines Prozesses mit Process Explorer von Sysinternals ermitteln, indem du die Eigenschaften des Prozesses öffnest und den "...](<../../images/image (824).png>)

Du kannst deine **aktuelle Integritätsstufe** auch mit `whoami /groups` ermitteln.

![Integritätsstufen - Integritätsstufen: Du kannst deine aktuelle Integritätsstufe auch mit whoami /groups ermitteln](<../../images/image (325).png>)

### Integritätsstufen im Dateisystem

Ein Objekt innerhalb des Dateisystems kann eine **Mindestanforderung an die Integritätsstufe** besitzen. Wenn ein Prozess nicht über diese Integritätsstufe verfügt, kann er nicht mit dem Objekt interagieren.\
Zum Beispiel **erstellen wir über eine Konsole eines Standardbenutzers eine reguläre Datei und überprüfen die Berechtigungen**:
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
Weisen wir der Datei nun eine minimale Integritätsstufe von **High** zu. Dies **muss über eine Konsole** erfolgen, die als **Administrator** ausgeführt wird, da eine **reguläre Konsole** mit der Integritätsstufe „Medium“ ausgeführt wird und **nicht berechtigt ist**, einem Objekt die Integritätsstufe „High“ zuzuweisen:
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
Hier wird es interessant. Wie du sehen kannst, hat der Benutzer `DESKTOP-IDJHTKP\user` **FULL privileges** für die Datei (tatsächlich war dies der Benutzer, der die Datei erstellt hat). Aufgrund der implementierten minimalen Integrity Level kann er die Datei jedoch nicht mehr ändern, es sei denn, er läuft innerhalb eines High Integrity Level (beachte, dass er sie lesen kann):
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

Ich habe eine Kopie von `cmd.exe` unter `C:\Windows\System32\cmd-low.exe` erstellt und sie **über eine Administratorkonsole auf eine niedrige Integritätsstufe gesetzt:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Jetzt wird `cmd-low.exe` beim Ausführen **unter einer niedrigen Integritätsstufe** statt unter einer mittleren ausgeführt:

![Integritätsstufen im Dateisystem – Integritätsstufen in Binärdateien: Jetzt wird cmd-low.exe beim Ausführen unter einer niedrigen Integritätsstufe statt unter einer mittleren ausgeführt](<../../images/image (313).png>)

Für neugierige Personen: Wenn Sie einer Binary eine hohe Integritätsstufe zuweisen (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), wird sie nicht automatisch mit einer hohen Integritätsstufe ausgeführt (wenn Sie sie aus einer mittleren Integritätsstufe heraus aufrufen – standardmäßig –, wird sie unter einer mittleren Integritätsstufe ausgeführt).

### Integritätsstufen in Prozessen

Nicht alle Dateien und Ordner verfügen über eine minimale Integritätsstufe, **aber alle Prozesse werden unter einer Integritätsstufe ausgeführt**. Und ähnlich wie im Dateisystem gilt: **Wenn ein Prozess in einen anderen Prozess schreiben möchte, muss er mindestens dieselbe Integritätsstufe besitzen**. Das bedeutet, dass ein Prozess mit niedriger Integritätsstufe keinen Handle mit vollständigem Zugriff auf einen Prozess mit mittlerer Integritätsstufe öffnen kann.

Aufgrund der in diesem und im vorherigen Abschnitt erläuterten Einschränkungen wird aus Sicherheitssicht stets **empfohlen, einen Prozess mit der niedrigstmöglichen Integritätsstufe auszuführen**.

{{#include ../../banners/hacktricks-training.md}}
