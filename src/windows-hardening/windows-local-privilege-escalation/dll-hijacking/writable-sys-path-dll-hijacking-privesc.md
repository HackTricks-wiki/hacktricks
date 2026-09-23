# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Wenn du **in ein Verzeichnis im systemweiten `PATH` schreiben kannst** (nicht nur in deinen Benutzer-`PATH`), kannst du möglicherweise **deine Privilegien auf dem System eskalieren**.

Dies kann durch **DLL hijacking** ausgenutzt werden, wenn ein privilegierterer Dienst oder Prozess versucht, eine DLL zu laden, die an den vorherigen Suchorten nicht existiert, und schließlich das beschreibbare Verzeichnis im System-`PATH` durchsucht.

Ein beschreibbarer Machine-`PATH`-Eintrag ist lediglich ein **Primitive** und kein Beweis für Codeausführung. Bei einer nicht paketierten Anwendung, die die standardmäßige Suchreihenfolge verwendet, wird `PATH` erst nach Redirection, API sets, SxS, der Liste geladener Module, KnownDLLs, den Anwendungs- und Windows-Verzeichnissen sowie dem aktuellen Verzeichnis erreicht. Ein vollständiger Pfad oder eine `LOAD_LIBRARY_SEARCH_*`- / `SetDefaultDllDirectories`-Richtlinie kann `PATH` vollständig ausschließen.<sup>[[4]](#references)</sup>

Weitere Informationen zu **DLL hijacking** findest du unter:

{{#ref}}
./
{{#endref}}

## Privesc mit DLL Hijacking

### Eine fehlende DLL finden

Identifiziere zunächst **einen Prozess**, der mit **höheren Privilegien** ausgeführt wird und versucht, **eine DLL aus einem beschreibbaren System-`PATH`-Verzeichnis zu laden**.

Denke daran, dass diese Technik von einem **Machine-/System-`PATH`**-Eintrag abhängt, nicht nur von deinem **User-`PATH`**. Daher lohnt es sich, vor dem Einsatz von Procmon die **Machine-`PATH`**-Einträge aufzulisten und zu prüfen, welche davon beschreibbar sind:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
ACL-Text kann irreführend sein, da sich Gruppenmitgliedschaften, verweigernde ACEs und geerbte Berechtigungen auf das Ergebnis auswirken. In einem autorisierten Test prüft eine Create/Delete-Probe den **effektiven Zugriff des aktuellen Tokens** (sie ist invasiv und kann Warnmeldungen auslösen):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Den effektiven `PATH` des Ziels bestätigen

Der aus der Registry gelesene Machine-`PATH` ist Konfigurationsdaten; der Loader verwendet den Environment-Block des **Zielprozesses**. Jeder Prozess besitzt einen Environment-Block, und ein untergeordneter Prozess erbt normalerweise eine Kopie der Umgebung seines übergeordneten Prozesses. Folglich kann ein lange laufender Service einen älteren Wert beibehalten, und ein Service, der mit einer benutzerdefinierten Umgebung gestartet wurde, kann sich von dem in deiner Shell angezeigten Wert unterscheiden. Betrachte eine beobachtete Procmon-Prüfung des exakten Verzeichnisses durch die Ziel-PID als maßgebliche Information; starte nach einer Änderung des `PATH` in einer Lab-Umgebung den relevanten Prozessbaum neu oder führe einen Neustart durch, bevor du schlussfolgerst, dass der Lookup nicht stattfindet.<sup>[[5]](#references)</sup>

Das Problem in diesen Fällen besteht darin, dass diese Prozesse wahrscheinlich bereits laufen. Um DLLs zu identifizieren, deren Laden Services versuchen und nicht schaffen, starte Procmon so früh wie möglich (bevor die Prozesse gestartet werden), und führe dann Folgendes aus:

> [!WARNING]
> Das Hinzufügen eines benutzerschreibbaren Verzeichnisses zum Machine-`PATH` **erzeugt die verwundbare Bedingung**. Führe dies nur in einer isolierten Forschungs-VM durch, um herauszufinden, welche privilegierten Prozesse den `PATH` erreichen; überwache auf einem untersuchten Host den bereits vorhandenen schreibbaren Eintrag, ohne die Systemkonfiguration zu ändern.<sup>[[1]](#references)</sup>

- **Erstelle** den Ordner `C:\privesc_hijacking` und füge den Pfad `C:\privesc_hijacking` zur **System Path env variable** hinzu. Dies kannst du **manuell** oder mit **PS** tun:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Starte **`procmon`** und gehe zu **`Options`** --> **`Enable boot logging`** und drücke **`OK`** im Hinweis.
- Danach **rebooten**. Wenn der Computer neu gestartet wurde, beginnt **`procmon`** so schnell wie möglich mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** **gestartet** wurde, führe **`procmon`** erneut aus. Das Programm teilt dir mit, dass es ausgeführt wurde, und **fragt dich, ob du** die Ereignisse in einer Datei **speichern möchtest**. Bestätige mit **Ja** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **generiert** wurde, schließe das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu, um alle DLLs zu finden, die ein **Prozess aus dem beschreibbaren System Path-Ordner zu laden versucht hat**:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging ist nur für Services erforderlich, die zu früh starten**, um sie andernfalls zu beobachten. Wenn du den Ziel-Service/das Zielprogramm **bei Bedarf auslösen kannst** (beispielsweise durch Interaktion mit seiner COM-Schnittstelle, einen Neustart des Services oder den erneuten Start einer geplanten Aufgabe), ist es normalerweise schneller, eine normale Procmon-Aufzeichnung mit Filtern wie **`Path contains .dll`**, **`Result is NAME NOT FOUND`** und **`Path begins with <writable_machine_path>`** zu erstellen.

### Übersehene DLLs

Bei der Ausführung in einer kostenlosen **virtuellen (VMware-)Windows-11-Maschine** erhielt ich diese Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Ignoriere in diesem Fall die `.exe`-Ergebnisse. Die fehlenden DLL-Probes stammten von:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Das folgende Beispiel verwendet die in diesem Artikel beschriebene Technik zum [**Abusing von `WptsExtensions.dll` zur Privilege Escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Weitere Kandidaten, die eine Triage wert sind

`WptsExtensions.dll` ist ein gutes Beispiel, aber nicht die einzige wiederkehrende **Phantom DLL**, die in privilegierten Services auftaucht. Moderne Hunting-Regeln und öffentliche Hijack-Kataloge verfolgen weiterhin Namen wie:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassischer **SYSTEM**-Kandidat auf Client-Systemen. Geeignet, wenn sich das beschreibbare Verzeichnis im **Machine PATH** befindet und der Service die DLL beim Start abfragt. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Auf **Server-Editionen** interessant, weil der Service als **SYSTEM** ausgeführt und in einigen Builds von einem normalen Benutzer **bei Bedarf ausgelöst werden kann**, wodurch dieser Kandidat besser ist als Fälle, die nur nach einem Reboot funktionieren. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Liefert normalerweise zuerst **`NT AUTHORITY\LOCAL SERVICE`**. Das reicht oft dennoch aus, weil das Token über **`SeImpersonatePrivilege`** verfügt und du es daher mit [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) verketten kannst. |

Betrachte diese Namen als **Triage-Hinweise**, nicht als garantierte Treffer: Sie sind **von SKU und Build abhängig**, und Microsoft kann das Verhalten zwischen Releases ändern. Die wichtige Erkenntnis ist, nach **fehlenden DLLs in privilegierten Services zu suchen, die den Machine PATH durchlaufen**, insbesondere wenn der Service **ohne Reboot erneut ausgelöst werden kann**.

### Einen Kandidaten vor dem Weaponizing validieren

Ein `NAME NOT FOUND`-Ereignis allein reicht nicht aus. Überprüfe vor dem Platzieren eines Payloads die vollständige Kette:<sup>[[1]](#references)[[4]](#references)</sup>

1. Das Ereignis gehört zum erwarteten **PID, zur Command Line, zum Service-Konto und zum Integrity Level**, und der fehlende Pfad ist exakt das beschreibbare Machine-`PATH`-Verzeichnis.
2. Für denselben DLL-Basename liefert kein früheres Verzeichnis `SUCCESS`, und das Modul wird nicht durch die Liste geladener Module, KnownDLLs, Redirection oder ein SxS-Manifest bereitgestellt.
3. Die Abfrage wird wiederholt, wenn ein Benutzer mit niedrigen Privilegien den vorgesehenen Trigger ausführt. Eine nur beim Booten erfolgende Abfrage ist nutzbar, aber operativ deutlich schlechter als eine Abfrage bei Bedarf.
4. Die Payload-Architektur entspricht dem Prozess. Wenn die Anwendung später Exports auflöst, proxye die legitime DLL oder exportiere die erwarteten Symbole; siehe [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Verwende zuerst eine harmlose Canary-DLL, die PID, Identität und Zeitstempel aufzeichnet. Verlange in Procmon ein erfolgreiches **`Load Image`** aus dem platzierten Pfad, anstatt anzunehmen, dass eine vorherige Dateiabfrage die Ausführung verursacht hat.

### Exploitation

Um **Privileges zu eskalieren**, hijacke **`WptsExtensions.dll`**. Sobald **Pfad** und **Name** bekannt sind, generiere die bösartige DLL.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](README.md#creating-and-compiling-dlls). Du könntest Payloads wie die folgenden ausführen: eine Rev-Shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen ...

> [!WARNING]
> Beachte, dass **nicht alle Services** als **`NT AUTHORITY\SYSTEM`** ausgeführt werden. Einige laufen als **`NT AUTHORITY\LOCAL SERVICE`**, das **weniger Privilegien** besitzt. Der Missbrauch eines dieser Services ermöglicht es dir daher möglicherweise nicht, einen neuen Benutzer zu erstellen.\
> Dieses Konto verfügt jedoch über das Benutzerrecht **`SeImpersonatePrivilege`**, sodass du die [**Potato Suite zur Privilege Escalation verwenden kannst**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Reverse Shell die bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Der **Task Scheduler**-Service läuft normalerweise als **`NT AUTHORITY\SYSTEM`**, aber überprüfe die tatsächliche Bereitstellung und leite die Ausführungsidentität nicht allein aus dem Namen des Services ab:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Nachdem du die **bösartige DLL erstellt** hast (_in meinem Fall habe ich eine x64-Reverse-Shell verwendet und eine Shell zurückbekommen, aber Defender hat sie beendet, weil sie von msfvenom stammte_), speichere sie unter dem Namen **WptsExtensions.dll** im beschreibbaren Systempfad und **starte** den Computer neu (oder starte den Dienst neu bzw. führe die erforderlichen Schritte aus, damit der betroffene Dienst/das betroffene Programm erneut ausgeführt wird).

Wenn der Dienst neu gestartet wird, sollte die **DLL geladen und ausgeführt werden** (du kannst den **Procmon**-Trick erneut verwenden, um zu überprüfen, ob die **Bibliothek wie erwartet geladen wurde**).

> [!NOTE]
> Plane die Bereinigung vor dem Triggern. Ein Dienst kann die DLL weiterhin gemappt halten und die Datei sperren, bis er beendet wird; zum Beenden von Task Scheduler sind für `WptsExtensions.dll` erhöhte Rechte erforderlich. Nachdem du den vorgesehenen Kontext erhalten hast, beende das Ziel sicher, entferne die Payload und stelle jede nur für das Labor vorgenommene `PATH`-Änderung wieder her.<sup>[[1]](#references)</sup>

### Behebung / Erkennung

Entferne schwache Schreibberechtigungen aus jedem Verzeichnis im Machine-`PATH` und entferne veraltete Einträge. Entwickler sollten vertrauenswürdige Bibliotheken über den vollständigen Pfad laden oder die Auflösung mit `SetDefaultDllDirectories` / `LoadLibraryEx`-Suchflags einschränken. Defender können Änderungen am Machine-`PATH` mit privilegierten Prozessen korrelieren, die DLLs aus nicht systembezogenen, von Benutzern beschreibbaren Verzeichnissen laden.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows-DLL-Hijacking (hoffentlich) geklärt](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Verdächtige DLL für Persistenz oder Privilege Escalation geladen](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL-Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Suchreihenfolge für Dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Umgebungsvariablen](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
