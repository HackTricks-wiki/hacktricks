# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Wenn du festgestellt hast, dass du **in einen System Path-Ordner schreiben** kannst (beachte, dass dies nicht funktioniert, wenn du in einen User Path-Ordner schreiben kannst), ist es möglicherweise möglich, **die Berechtigungen im System zu erweitern**.

Dazu kannst du einen **Dll Hijacking** ausnutzen, bei dem du eine **von einem Service oder Prozess geladene Bibliothek hijackst**, der über **mehr Berechtigungen** verfügt als du. Da dieser Service eine Dll lädt, die wahrscheinlich im gesamten System nicht einmal existiert, wird er versuchen, sie aus dem System Path zu laden, in den du schreiben kannst.

Weitere Informationen darüber, **was ein Dll Hijack ist**, findest du hier:


{{#ref}}
./
{{#endref}}

## Privesc with Dll Hijacking

### Finding a missing Dll

Als Erstes musst du einen **Prozess identifizieren**, der mit **mehr Berechtigungen** als du ausgeführt wird und versucht, eine **Dll aus dem System Path zu laden**, in den du schreiben kannst.

Denke daran, dass diese Technik von einem **Machine/System PATH**-Eintrag abhängt, nicht nur von deinem **User PATH**. Daher lohnt es sich, vor dem Einsatz von Procmon die **Machine PATH**-Einträge zu enumerieren und zu prüfen, welche davon beschreibbar sind:<sup>[[1]](#references)</sup>
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
Das Problem in diesen Fällen ist, dass diese Prozesse wahrscheinlich bereits laufen. Um herauszufinden, welche DLLs den Services fehlen, musst du Procmon so schnell wie möglich starten (bevor die Prozesse geladen werden). Um die fehlenden `.dlls` zu finden, gehe wie folgt vor:

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
- Starte **`procmon`** und gehe zu **`Options`** --> **`Enable boot logging`**, anschließend drücke **`OK`** in der Eingabeaufforderung.
- Danach **reboot**. Wenn der Computer neu gestartet wird, beginnt **`procmon`** schnellstmöglich mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** **gestartet** ist, führe **`procmon`** erneut aus. Es teilt dir mit, dass es bereits ausgeführt wurde, und **fragt dich, ob du die Ereignisse** in einer Datei **speichern möchtest**. Wähle **yes** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **generiert** wurde, schließe das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu. Dadurch findest du alle DLLs, die ein **Prozess** aus dem beschreibbaren System-PATH-Ordner zu laden versucht hat:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** ist nur für Services erforderlich, die **zu früh starten**, um sie anderweitig beobachten zu können. Wenn du den Ziel-Service/das Zielprogramm **bei Bedarf auslösen kannst** (beispielsweise durch Interaktion mit seiner COM-Schnittstelle, einen Neustart des Services oder das erneute Starten einer geplanten Aufgabe), ist es normalerweise schneller, eine normale Procmon-Aufzeichnung mit Filtern wie **`Path contains .dll`**, **`Result is NAME NOT FOUND`** und **`Path begins with <writable_machine_path>`** zu verwenden.

### Übersehene DLLs

Bei der Ausführung in einer kostenlosen **virtuellen (VMware-)Windows-11-Maschine** erhielt ich diese Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die EXE-Dateien nutzlos, also ignoriere sie. Die übersehenen DLLs stammten aus:

| Service                         | DLL                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nachdem ich dies gefunden hatte, stieß ich auf diesen interessanten Blogbeitrag, der ebenfalls erklärt, wie man [**WptsExtensions.dll für privesc missbraucht**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Genau das **werden wir jetzt tun**.<sup>[[3]](#references)</sup>

### Weitere Kandidaten, die eine Analyse wert sind

`WptsExtensions.dll` ist ein gutes Beispiel, aber nicht die einzige wiederkehrende **phantom DLL**, die in privilegierten Services auftaucht. Moderne Hunting-Regeln und öffentliche Hijack-Kataloge führen weiterhin Namen wie diese auf:<sup>[[2]](#references)</sup>

| Service / Szenario | Fehlende DLL | Hinweise |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassischer **SYSTEM**-Kandidat auf Client-Systemen. Geeignet, wenn sich das beschreibbare Verzeichnis im **Machine PATH** befindet und der Service die DLL während des Starts abfragt. |
| NetMan unter Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interessant bei **Server-Editionen**, da der Service als **SYSTEM** ausgeführt wird und in einigen Builds **bei Bedarf von einem normalen Benutzer ausgelöst werden kann**. Dadurch ist dieser Fall besser als Szenarien, die nur nach einem Reboot funktionieren. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Liefert normalerweise zunächst **`NT AUTHORITY\LOCAL SERVICE`**. Das reicht häufig trotzdem aus, da das Token über **`SeImpersonatePrivilege`** verfügt und du es daher mit [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) verketten kannst. |

Betrachte diese Namen als **Hinweise für die Triage**, nicht als garantierte Erfolge: Sie sind **von SKU und Build abhängig**, und Microsoft kann das Verhalten zwischen Releases ändern. Die wichtigste Erkenntnis ist, nach **fehlenden DLLs in privilegierten Services zu suchen, die den Machine PATH durchsuchen**, insbesondere wenn der Service **ohne Reboot erneut ausgelöst werden kann**.

### Exploitation

Um also **Privilegien zu eskalieren**, werden wir die Bibliothek **WptsExtensions.dll** hijacken. Da wir den **Pfad** und den **Namen** kennen, müssen wir nur noch die **malicious DLL erstellen**.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](#creating-and-compiling-dlls). Du könntest Payloads wie die folgenden ausführen: eine Rev-Shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen ...

> [!WARNING]
> Beachte, dass **nicht alle Services** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden. Einige laufen auch mit **`NT AUTHORITY\LOCAL SERVICE`**, das über **weniger Privilegien** verfügt. Daher **kannst du keinen neuen Benutzer erstellen**, um dessen Berechtigungen zu missbrauchen.\
> Dieser Benutzer verfügt jedoch über das Privileg **`seImpersonate`**, sodass du die[ **Potato Suite zur Privilegieneskalation verwenden kannst**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Rev-Shell also eine bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Zum Zeitpunkt der Erstellung dieses Textes wird der **Task Scheduler**-Service mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem du die **malicious DLL erstellt** hast (_in meinem Fall habe ich eine x64-Rev-Shell verwendet und eine Shell zurückerhalten, aber Defender hat sie beendet, weil sie aus msfvenom stammte_), speichere sie mit dem Namen **WptsExtensions.dll** im beschreibbaren System-PATH und **starte** den Computer **neu** (oder starte den Service neu beziehungsweise tue alles Notwendige, um den betroffenen Service/das betroffene Programm erneut auszuführen).

Wenn der Service neu gestartet wird, sollte die **DLL geladen und ausgeführt werden** (du kannst den **procmon**-Trick wiederverwenden, um zu prüfen, ob die **Bibliothek wie erwartet geladen wurde**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
