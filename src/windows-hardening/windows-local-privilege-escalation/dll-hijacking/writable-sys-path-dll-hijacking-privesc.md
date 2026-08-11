# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Wenn du **in ein Verzeichnis im systemweiten `PATH` schreiben** kannst (nicht nur in deinen Benutzer-`PATH`), kannst du möglicherweise **deine Berechtigungen auf dem System erweitern**.

Dies kann durch **DLL hijacking** ausgenutzt werden, wenn ein privilegierterer Dienst oder Prozess versucht, eine DLL zu laden, die an den vorherigen Suchorten nicht vorhanden ist, und schließlich das beschreibbare systemweite `PATH`-Verzeichnis durchsucht.

Weitere Informationen zu **DLL hijacking** findest du unter:


{{#ref}}
./
{{#endref}}

## Privesc mit Dll Hijacking

### Eine fehlende DLL finden

Identifiziere zunächst **einen Prozess**, der mit **höheren Berechtigungen** ausgeführt wird und versucht, **eine DLL aus einem beschreibbaren systemweiten `PATH`-Verzeichnis zu laden**.

Beachte, dass diese Technik von einem **Machine/System PATH**-Eintrag abhängt, nicht nur von deinem **User PATH**. Daher lohnt es sich, vor dem Einsatz von Procmon die **Machine PATH**-Einträge aufzulisten und zu überprüfen, welche davon beschreibbar sind:<sup>[[1]](#references)</sup>
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
Das Problem in diesen Fällen ist, dass diese Prozesse wahrscheinlich bereits ausgeführt werden. Um DLLs zu identifizieren, die Dienste zu laden versuchen, dies jedoch nicht schaffen, starten Sie Procmon so früh wie möglich (bevor die Prozesse gestartet werden) und gehen Sie dann wie folgt vor:

- **Erstellen** Sie den Ordner `C:\privesc_hijacking` und fügen Sie den Pfad `C:\privesc_hijacking` zur **System Path env variable** hinzu. Dies können Sie **manuell** oder mit **PS** tun:
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
- Starte **`procmon`** und gehe zu **`Options`** --> **`Enable boot logging`** und drücke **`OK`** in der Eingabeaufforderung.
- Führe anschließend einen **Neustart** durch. Wenn der Computer neu gestartet wurde, beginnt **`procmon`** so schnell wie möglich mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** **gestartet** ist, führe **`procmon`** erneut aus. Das Programm teilt dir mit, dass es bereits ausgeführt wurde, und **fragt dich, ob du** die Ereignisse in einer Datei **speichern möchtest**. Antworte mit **Ja** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **erstellt** wurde, schließe das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu, um alle DLLs zu finden, die ein **Prozess aus dem beschreibbaren System-Pfad-Ordner zu laden versucht hat**:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging ist nur für Dienste erforderlich, die zu früh starten**, um sie anderweitig beobachten zu können. Wenn du den Zieldienst bzw. das Zielprogramm **bei Bedarf auslösen kannst** (beispielsweise durch Interaktion mit seiner COM-Schnittstelle, einen Neustart des Dienstes oder das erneute Starten einer geplanten Aufgabe), ist es normalerweise schneller, eine normale Procmon-Aufzeichnung mit Filtern wie **`Path contains .dll`**, **`Result is NAME NOT FOUND`** und **`Path begins with <writable_machine_path>`** zu verwenden.

### Übersehene Dlls

Bei der Ausführung auf einer kostenlosen **virtuellen (VMware-)Windows-11-Maschine** erhielt ich folgende Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Ignoriere in diesem Fall die `.exe`-Ergebnisse. Die fehlenden DLL-Suchen stammten von:

| Dienst                         | Dll                | CMD-Zeile                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Das folgende Beispiel verwendet die in diesem Artikel beschriebene Technik zum [**Abusing von `WptsExtensions.dll` zur Privilege Escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Weitere Kandidaten, die eine Triage wert sind

`WptsExtensions.dll` ist ein gutes Beispiel, aber nicht die einzige wiederkehrende **Phantom-DLL**, die in privilegierten Diensten auftaucht. Moderne Hunting-Regeln und öffentliche Hijacking-Kataloge führen weiterhin Namen wie die folgenden auf:<sup>[[2]](#references)</sup>

| Dienst / Szenario | Fehlende DLL | Hinweise |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassischer **SYSTEM**-Kandidat auf Client-Systemen. Gut geeignet, wenn sich das beschreibbare Verzeichnis im **Machine PATH** befindet und der Dienst beim Start nach der DLL sucht. |
| NetMan unter Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Auf **Server-Editionen** interessant, da der Dienst als **SYSTEM** ausgeführt wird und von einem normalen Benutzer bei einigen Builds **bei Bedarf ausgelöst werden kann**. Dadurch ist dieser Fall besser als Szenarien, die nur nach einem Neustart funktionieren. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Liefert normalerweise zunächst **`NT AUTHORITY\LOCAL SERVICE`**. Das reicht häufig dennoch aus, da das Token über **`SeImpersonatePrivilege`** verfügt und du es daher mit [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) verknüpfen kannst. |

Betrachte diese Namen als **Hinweise für die Triage**, nicht als garantierte Treffer: Sie sind **von SKU und Build abhängig**, und Microsoft kann das Verhalten zwischen Releases ändern. Die wichtigste Erkenntnis ist, nach **fehlenden DLLs in privilegierten Diensten zu suchen, die den Machine PATH durchlaufen**, insbesondere wenn der Dienst **ohne Neustart erneut ausgelöst werden kann**.

### Exploitation

Um **Privileges zu eskalieren**, hijacke **`WptsExtensions.dll`**. Sobald **Pfad** und **Name** bekannt sind, generiere die schädliche DLL.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](#creating-and-compiling-dlls). Du könntest Payloads wie die folgenden ausführen: eine Rev Shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen ...

> [!WARNING]
> Beachte, dass **nicht alle Dienste** als **`NT AUTHORITY\SYSTEM`** ausgeführt werden. Einige laufen als **`NT AUTHORITY\LOCAL SERVICE`**, das **weniger Privileges** besitzt. Daher kannst du durch den Missbrauch eines dieser Dienste möglicherweise keinen neuen Benutzer erstellen.\
> Dieses Konto verfügt jedoch über das Benutzerrecht **`SeImpersonatePrivilege`**, sodass du die [**Potato-Suite zur Privilege Escalation verwenden kannst**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Reverse Shell die bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Zum Zeitpunkt der Erstellung dieses Textes wird der **Task-Scheduler**-Dienst mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem du die schädliche **DLL generiert** hast (_in meinem Fall habe ich eine x64-Rev-Shell verwendet und eine Shell zurückerhalten, aber Defender hat sie beendet, weil sie von msfvenom stammte_), speichere sie unter dem Namen **WptsExtensions.dll** im beschreibbaren System-Pfad und **starte** den Computer neu (oder starte den Dienst neu bzw. führe die erforderliche Aktion aus, damit der betroffene Dienst bzw. das Programm erneut ausgeführt wird).

Wenn der Dienst neu gestartet wird, sollte die **DLL geladen und ausgeführt werden** (du kannst den **`procmon`**-Trick **wiederverwenden**, um zu überprüfen, ob die **Bibliothek wie erwartet geladen wurde**).

## References

- [1] [Windows DLL Hijacking (hoffentlich) geklärt](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
