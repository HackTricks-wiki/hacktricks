# Beschreibbarer Systempfad + Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Wenn du feststellst, dass du **in einen Systempfad-Ordner schreiben** kannst (beachte, dass das nicht funktioniert, wenn du in einen User Path-Ordner schreiben kannst), ist es möglich, dass du die Privilegien im System **erhöhen** kannst.

Um das zu erreichen, kannst du ein **Dll Hijacking** ausnutzen, bei dem du eine Bibliothek, die von einem Dienst oder Prozess mit **höheren Privilegien** als du geladen wird, **hijackst**. Da dieser Dienst eine Dll lädt, die wahrscheinlich im gesamten System gar nicht existiert, wird er versuchen, sie aus dem Systempfad zu laden, in den du schreiben kannst.

Für mehr Informationen darüber, **was Dll Hijacking ist**, siehe:

{{#ref}}
./
{{#endref}}

## Privesc mit Dll Hijacking

### Eine fehlende Dll finden

Das Erste, was du brauchst, ist ein Prozess zu **identifizieren**, der mit **höheren Privilegien** als du läuft und versucht, eine **Dll aus dem Systempfad** zu laden, in den du schreiben kannst.

Das Problem in diesen Fällen ist, dass diese Prozesse vermutlich bereits laufen. Um herauszufinden, welche Dlls fehlen, musst du procmon so früh wie möglich starten (bevor die Prozesse geladen werden). Um fehlende .dlls zu finden, mache folgendes:

- **Erstelle** den Ordner `C:\privesc_hijacking` und füge den Pfad `C:\privesc_hijacking` zur **Systempfad-Umgebungsvariable** hinzu. Du kannst das **manuell** oder mit **PS**:
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
- Starte **`procmon`** und gehe zu **`Options`** --> **`Enable boot logging`** und bestätige im Prompt mit **`OK`**.
- Starte dann den Rechner **neu**. Wenn der Computer neu gestartet ist, beginnt **`procmon`** so schnell wie möglich mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** gestartet ist, führe **`procmon`** erneut aus; es wird dir mitteilen, dass es bereits läuft und dich **fragen, ob du die Ereignisse speichern** möchtest. Sage **yes** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **generiert** wurde, **schließe** das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu und du findest alle Dlls, die einige **Prozesse zu laden versucht haben** aus dem beschreibbaren Systempfad-Ordner:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Fehlende Dlls

Als ich das in einer kostenlosen virtuellen (vmware) Windows 11-Maschine ausgeführt habe, erhielt ich folgende Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die .exe nutzlos, also ignoriere sie; die fehlenden DLLs stammten von:

| Dienst                          | Dll                | CMD-Zeile                                                            |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

After finding this, I found this interesting blog post that also explains how to [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Which is what we **are going to do now**.

### Exploitation

Also, um Privilegien zu eskalieren, werden wir die Bibliothek **WptsExtensions.dll** hijacken. Wenn wir den Pfad und den Namen haben, müssen wir nur noch die bösartige DLL generieren.

You can [**try to use any of these examples**](#creating-and-compiling-dlls). Du könntest Payloads ausführen wie: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Beachte, dass **nicht alle Dienste** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden; einige laufen auch mit **`NT AUTHORITY\LOCAL SERVICE`**, welches **weniger Rechte** hat und mit dessen Rechten du **nicht in der Lage sein wirst, einen neuen Benutzer zu erstellen**.\
> Allerdings hat dieser Benutzer das **`seImpersonate`**-Privileg, sodass du die[ **potato suite to escalate privileges**](../roguepotato-and-printspoofer.md) verwenden kannst. In diesem Fall ist eine rev shell eine bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Im Moment, als dieses Dokument verfasst wurde, läuft der **Task Scheduler**-Dienst mit **NT AUTHORITY\SYSTEM**.

Nachdem du die bösartige Dll generiert hast (in meinem Fall habe ich eine x64 rev shell verwendet und bekam eine Shell zurück, aber Defender hat sie beendet, weil sie von msfvenom stammte), speichere sie im beschreibbaren Systempfad unter dem Namen **WptsExtensions.dll** und starte den Computer neu (oder starte den Dienst neu oder tue, was nötig ist, damit der betroffene Dienst/das Programm erneut ausgeführt wird).

Wenn der Dienst neu gestartet ist, sollte die **dll geladen und ausgeführt** werden (du kannst den **procmon**-Trick wiederverwenden, um zu überprüfen, ob die Bibliothek wie erwartet geladen wurde).

{{#include ../../../banners/hacktricks-training.md}}
