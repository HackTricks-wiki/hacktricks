# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Wenn du festgestellt hast, dass du in einen **System Path**-Ordner schreiben kannst (beachte, dass das nicht funktioniert, wenn du in einen **User Path**-Ordner schreiben kannst), ist es möglich, dass du **Privileges im System eskalieren** kannst.

Dazu kannst du ein **Dll Hijacking** ausnutzen, bei dem du eine **geladene library hijackst**, die von einem Service oder Prozess mit **mehr Privileges** als deinen geladen wird, und weil dieser Service eine Dll lädt, die wahrscheinlich nicht einmal im gesamten System existiert, wird er versuchen, sie aus dem System Path zu laden, in den du schreiben kannst.

Für mehr Infos darüber, **was Dll Hijacking ist**, siehe:


{{#ref}}
./
{{#endref}}

## Privesc mit Dll Hijacking

### Eine fehlende Dll finden

Das Erste, was du brauchst, ist, **einen Prozess zu identifizieren**, der mit **mehr Privileges** als du läuft und versucht, eine **Dll aus dem System Path zu laden**, in den du schreiben kannst.

Denk daran, dass diese Technik von einem **Machine/System PATH**-Eintrag abhängt, nicht nur von deinem **User PATH**. Deshalb lohnt es sich, bevor du Zeit mit Procmon verbringst, die **Machine PATH**-Einträge aufzulisten und zu prüfen, welche davon beschreibbar sind:
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
Das Problem in diesen Fällen ist, dass diese Prozesse wahrscheinlich bereits laufen. Um herauszufinden, welche Dlls den Services fehlen, musst du procmon so früh wie möglich starten (bevor Prozesse geladen werden). Um fehlende .dlls zu finden, gehe wie folgt vor:

- **Create** den Ordner `C:\privesc_hijacking` und füge den Pfad `C:\privesc_hijacking` zur **System Path env variable** hinzu. Du kannst dies **manually** oder mit **PS** tun:
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
- Dann **neu starten**. Wenn der Computer neu gestartet wird, beginnt **`procmon`** sofort, Ereignisse **aufzuzeichnen**.
- Sobald **Windows** **gestartet** ist, **führe `procmon` erneut aus**. Es teilt dir mit, dass es bereits läuft, und wird **fragen, ob du die Ereignisse** in einer Datei **speichern** möchtest. Antworte mit **yes** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **generiert** wurde, **schließe** das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu und du wirst alle Dlls finden, die ein **Prozess versucht hat zu laden** aus dem beschreibbaren System Path-Ordner:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging ist nur für Services erforderlich, die zu früh starten**, um sie sonst beobachten zu können. Wenn du den Ziel-Service/das Ziel-Programm **bei Bedarf auslösen** kannst (zum Beispiel durch Interaktion mit seiner COM-Schnittstelle, Neustart des Services oder erneutes Starten einer Scheduled Task), ist es normalerweise schneller, einen normalen Procmon-Capture mit Filtern wie **`Path contains .dll`**, **`Result is NAME NOT FOUND`** und **`Path begins with <writable_machine_path>`** beizubehalten.

### Missed Dlls

Wenn ich das in einer kostenlosen **virtuellen (vmware) Windows 11 machine** ausführe, erhalte ich diese Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die .exe nutzlos, also ignoriere sie. Die fehlenden DLLs waren von:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nachdem ich das gefunden hatte, stieß ich auf diesen interessanten Blog-Post, der auch erklärt, wie man [**WptsExtensions.dll für privesc missbrauchen**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll) kann. Genau das **werden wir jetzt tun**.

### Other candidates worth triaging

`WptsExtensions.dll` ist ein gutes Beispiel, aber es ist nicht die einzige wiederkehrende **phantom DLL**, die in privilegierten Services auftaucht. Moderne Hunting-Regeln und öffentliche Hijack-Kataloge verfolgen weiterhin Namen wie diese:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Klassischer **SYSTEM**-Kandidat auf Client-Systemen. Gut, wenn das beschreibbare Verzeichnis im **Machine PATH** liegt und der Service die DLL beim Start überprüft. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Auf **Server-Editionen** interessant, weil der Service als **SYSTEM** läuft und in einigen Builds von einem normalen Benutzer **bei Bedarf ausgelöst werden kann**, was besser ist als reine Neustart-Fälle. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Führt normalerweise zuerst zu **`NT AUTHORITY\LOCAL SERVICE`**. Das reicht oft trotzdem, weil das Token **`SeImpersonatePrivilege`** hat, sodass du es mit [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md) kombinieren kannst. |

Betrachte diese Namen als **Triage-Hinweise**, nicht als garantierte Treffer: Sie sind **SKU/build-abhängig**, und Microsoft kann das Verhalten zwischen Releases ändern. Die wichtige Erkenntnis ist, nach **fehlenden DLLs in privilegierten Services zu suchen, die den Machine PATH durchsuchen**, besonders wenn der Service **ohne Neustart erneut ausgelöst werden kann**.

### Exploitation

Um also die **privileges zu erhöhen**, werden wir die Library **WptsExtensions.dll** hijacken. Mit dem **Pfad** und dem **Namen** müssen wir nur noch die **malicious dll** erzeugen.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](#creating-and-compiling-dlls). Du könntest Payloads ausführen wie: eine rev shell erhalten, einen Benutzer hinzufügen, einen beacon ausführen...

> [!WARNING]
> Beachte, dass **nicht alle Services** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden, einige laufen auch mit **`NT AUTHORITY\LOCAL SERVICE`**, was **weniger privileges** hat, und du **kannst keinen neuen Benutzer erstellen**, um seine Berechtigungen zu missbrauchen.\
> Allerdings hat dieser Benutzer das **`seImpersonate`**-Privilege, sodass du die [**potato suite zur privilege escalation verwenden**](../roguepotato-and-printspoofer.md) kannst. In diesem Fall ist also eine rev shell die bessere Option als zu versuchen, einen Benutzer zu erstellen.

Zum Zeitpunkt des Schreibens läuft der **Task Scheduler**-Service mit **Nt AUTHORITY\SYSTEM**.

Nachdem die **malicious Dll** erzeugt wurde (_in meinem Fall habe ich eine x64 rev shell verwendet und eine Shell zurückbekommen, aber Defender hat sie gekillt, weil sie von msfvenom stammte_), speichere sie im beschreibbaren System Path unter dem Namen **WptsExtensions.dll** und **starte** den Computer **neu** (oder starte den Service neu oder tue, was auch immer nötig ist, um den betroffenen Service/das betroffene Programm erneut auszuführen).

Wenn der Service neu gestartet wird, sollte die **dll geladen und ausgeführt** werden (du kannst den **procmon**-Trick erneut verwenden, um zu prüfen, ob die **Library wie erwartet geladen wurde**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
