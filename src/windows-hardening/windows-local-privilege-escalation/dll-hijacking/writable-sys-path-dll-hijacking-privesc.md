# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung

Wenn du **in ein Verzeichnis im systemweiten `PATH` schreiben** kannst (nicht nur in deinen Benutzer-`PATH`), kannst du möglicherweise **deine Privilegien auf dem System erhöhen**.

Dies kann durch **DLL hijacking** ausgenutzt werden, wenn ein privilegierterer Dienst oder Prozess versucht, eine DLL zu laden, die an den vorherigen Suchorten nicht vorhanden ist, und schließlich das beschreibbare systemweite `PATH`-Verzeichnis durchsucht.

Weitere Informationen zu **DLL hijacking** findest du unter:


{{#ref}}
./
{{#endref}}

## Privesc mit DLL Hijacking

### Fehlende DLL finden

Identifiziere zunächst **einen Prozess**, der mit **höheren Privilegien** ausgeführt wird und versucht, **eine DLL aus einem beschreibbaren systemweiten `PATH`-Verzeichnis zu laden**.

Beachte, dass diese Technik von einem **Machine/System PATH**-Eintrag abhängt, nicht nur von deinem **User PATH**. Daher lohnt es sich, vor dem Einsatz von Procmon die Einträge im **Machine PATH** aufzulisten und zu prüfen, welche davon beschreibbar sind:<sup>[[1]](#references)</sup>
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
Das Problem in diesen Fällen besteht darin, dass diese Prozesse wahrscheinlich bereits ausgeführt werden. Um DLLs zu identifizieren, die Dienste zu laden versuchen, aber nicht laden können, starte Procmon so früh wie möglich (bevor die Prozesse gestartet werden) und:

- **Erstelle** den Ordner `C:\privesc_hijacking` und füge den Pfad `C:\privesc_hijacking` zur **System Path env variable** hinzu. Du kannst dies **manuell** oder mit **PS** tun:
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
- Starte **`procmon`** und gehe zu **`Options`** --> **`Enable boot logging`**, anschließend klicke im Hinweis auf **`OK`**.
- Danach **starte den Computer neu**. Sobald der Computer neu gestartet wurde, beginnt **`procmon`** umgehend mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** **gestartet** ist, führe **`procmon`** erneut aus. Das Programm teilt dir mit, dass es bereits ausgeführt wurde, und **fragt dich, ob du die Ereignisse** in einer Datei **speichern möchtest**. Wähle **Ja** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **erstellt** wurde, schließe das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge die folgenden **Filter** hinzu, um alle DLLs zu finden, die ein **Prozess aus dem beschreibbaren Systempfad-Ordner zu laden versucht hat**:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging ist nur für Dienste erforderlich, die zu früh starten**, um sie ansonsten beobachten zu können. Wenn du den Zieldienst bzw. das Zielprogramm **bei Bedarf auslösen kannst** (zum Beispiel durch Interaktion mit dessen COM-Schnittstelle, einen Neustart des Dienstes oder das erneute Starten einer geplanten Aufgabe), ist es normalerweise schneller, eine normale Procmon-Aufzeichnung mit Filtern wie **`Path contains .dll`**, **`Result is NAME NOT FOUND`** und **`Path begins with <writable_machine_path>`** zu verwenden.

### Verpasste DLLs

Bei der Ausführung auf einer kostenlosen **virtuellen (VMware-)Windows-11-Maschine** erhielt ich folgende Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Ignoriere in diesem Fall die `.exe`-Ergebnisse. Die fehlenden DLL-Probes stammten von:

| Dienst                         | Dll                | CMD line                                                             |
| ----------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Das folgende Beispiel verwendet die in diesem Artikel beschriebene Technik zum [**Missbrauch von `WptsExtensions.dll` zur Privilege Escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Weitere interessante Kandidaten für die Triage

`WptsExtensions.dll` ist ein gutes Beispiel, aber nicht die einzige wiederkehrende **phantom DLL**, die in privilegierten Diensten auftaucht. Moderne Hunting-Regeln und öffentliche Hijack-Kataloge verfolgen weiterhin Namen wie:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassischer **SYSTEM**-Kandidat auf Client-Systemen. Gut geeignet, wenn sich das beschreibbare Verzeichnis im **Machine PATH** befindet und der Dienst die DLL beim Start abfragt. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessant auf **Server-Editionen**, da der Dienst als **SYSTEM** ausgeführt und in manchen Builds von einem **normalen Benutzer bei Bedarf ausgelöst werden kann**, wodurch dieser Kandidat besser ist als Fälle, die nur nach einem Neustart funktionieren. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Liefert normalerweise zunächst **`NT AUTHORITY\LOCAL SERVICE`**. Das reicht oft trotzdem aus, da das Token über **`SeImpersonatePrivilege`** verfügt. Daher kannst du es mit [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) verketten. |

Betrachte diese Namen als **Hinweise für die Triage**, nicht als garantierte Treffer: Sie sind **von SKU und Build abhängig**, und Microsoft kann das Verhalten zwischen Releases ändern. Die wichtigste Erkenntnis ist, nach **fehlenden DLLs in privilegierten Diensten zu suchen, die den Machine PATH durchlaufen**, insbesondere wenn der Dienst **ohne Neustart erneut ausgelöst werden kann**.

### Exploitation

Um die **Privileges zu erhöhen**, hijacke **`WptsExtensions.dll`**. Sobald **Pfad** und **Name** bekannt sind, generiere die bösartige DLL.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](#creating-and-compiling-dlls). Du könntest Payloads ausführen wie: eine rev shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen ...

> [!WARNING]
> Beachte, dass **nicht alle Dienste** als **`NT AUTHORITY\SYSTEM`** ausgeführt werden. Einige laufen als **`NT AUTHORITY\LOCAL SERVICE`**, das **weniger Privileges** besitzt. Der Missbrauch eines dieser Dienste ermöglicht es dir daher möglicherweise nicht, einen neuen Benutzer zu erstellen.\
> Dieses Konto verfügt jedoch über das Benutzerrecht **`SeImpersonatePrivilege`**, sodass du die [**Potato-Suite zur Privilege Escalation verwenden kannst**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Reverse Shell die bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Zum Zeitpunkt der Erstellung dieses Textes wird der **Task Scheduler**-Dienst mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem du die **bösartige DLL generiert** hast (_in meinem Fall habe ich eine x64 rev shell verwendet und eine Shell erhalten, aber Defender hat sie beendet, weil sie aus msfvenom stammte_), speichere sie unter dem Namen **WptsExtensions.dll** im beschreibbaren Systempfad und **starte** den Computer neu (oder starte den Dienst neu bzw. führe alle erforderlichen Schritte aus, um den betroffenen Dienst bzw. das betroffene Programm erneut auszuführen).

Wenn der Dienst neu gestartet wird, sollte die **DLL geladen und ausgeführt werden** (du kannst den **`procmon`**-Trick **wiederverwenden**, um zu überprüfen, ob die **Bibliothek wie erwartet geladen wurde**).

## References

- [1] [Windows DLL Hijacking (hoffentlich) erklärt](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Verdächtige DLL, die zur Persistenz oder Privilege Escalation geladen wurde](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
