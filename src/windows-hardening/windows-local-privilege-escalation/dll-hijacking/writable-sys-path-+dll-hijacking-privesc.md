# Schreibbarer Systempfad + Dll-Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Einführung

Wenn Sie festgestellt haben, dass Sie **in einen Systempfad-Ordner schreiben können** (beachten Sie, dass dies nicht funktioniert, wenn Sie in einen Benutzerpfad-Ordner schreiben können), ist es möglich, dass Sie **Berechtigungen im System eskalieren** können.

Um dies zu tun, können Sie ein **Dll-Hijacking** ausnutzen, bei dem Sie eine **Bibliothek übernehmen**, die von einem Dienst oder Prozess mit **höheren Berechtigungen** als Ihren geladen wird. Da dieser Dienst eine Dll lädt, die wahrscheinlich nicht einmal im gesamten System existiert, wird er versuchen, sie aus dem Systempfad zu laden, in den Sie schreiben können.

Für weitere Informationen darüber, **was Dll-Hijacking ist**, siehe:

{{#ref}}
./
{{#endref}}

## Privesc mit Dll-Hijacking

### Finden einer fehlenden Dll

Das erste, was Sie benötigen, ist, einen **Prozess zu identifizieren**, der mit **höheren Berechtigungen** als Sie läuft und versucht, eine **Dll aus dem Systempfad** zu laden, in den Sie schreiben können.

Das Problem in diesen Fällen ist, dass diese Prozesse wahrscheinlich bereits laufen. Um herauszufinden, welche Dlls den Diensten fehlen, müssen Sie procmon so schnell wie möglich starten (bevor die Prozesse geladen werden). Um fehlende .dlls zu finden, tun Sie Folgendes:

- **Erstellen** Sie den Ordner `C:\privesc_hijacking` und fügen Sie den Pfad `C:\privesc_hijacking` zur **Systempfad-Umgebungsvariable** hinzu. Sie können dies **manuell** oder mit **PS** tun:
```powershell
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
- Starte **`procmon`** und gehe zu **`Optionen`** --> **`Boot-Logging aktivieren`** und drücke **`OK`** im Prompt.
- Dann **neustarten**. Wenn der Computer neu gestartet wird, beginnt **`procmon`** sofort mit der **Aufzeichnung** von Ereignissen.
- Sobald **Windows** **gestartet ist, führe `procmon`** erneut aus, es wird dir sagen, dass es bereits läuft und wird **fragen, ob du die Ereignisse in einer Datei speichern möchtest**. Sage **ja** und **speichere die Ereignisse in einer Datei**.
- **Nachdem** die **Datei** **generiert** wurde, **schließe** das geöffnete **`procmon`**-Fenster und **öffne die Ereignisdatei**.
- Füge diese **Filter** hinzu und du wirst alle Dlls finden, die einige **Prozesse versucht haben zu laden** aus dem beschreibbaren Systempfad-Ordner:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

### Verpasste Dlls

Als ich dies auf einer kostenlosen **virtuellen (vmware) Windows 11-Maschine** ausführte, erhielt ich diese Ergebnisse:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die .exe nutzlos, also ignoriere sie, die verpassten DLLs stammen von:

| Dienst                           | Dll                | CMD-Zeile                                                            |
| -------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Aufgabenplanung (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnosetool-Dienst (DPS)       | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                              | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nachdem ich dies gefunden hatte, stieß ich auf diesen interessanten Blogbeitrag, der auch erklärt, wie man [**WptsExtensions.dll für privesc missbrauchen kann**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Das ist es, was wir **jetzt tun werden**.

### Ausnutzung

Um die **Berechtigungen zu eskalieren**, werden wir die Bibliothek **WptsExtensions.dll** hijacken. Mit dem **Pfad** und dem **Namen** müssen wir nur die **bösartige dll generieren**.

Du kannst [**versuchen, eines dieser Beispiele zu verwenden**](./#creating-and-compiling-dlls). Du könntest Payloads ausführen wie: eine rev shell erhalten, einen Benutzer hinzufügen, ein Beacon ausführen...

> [!WARNING]
> Beachte, dass **nicht alle Dienste** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden, einige werden auch mit **`NT AUTHORITY\LOCAL SERVICE`** ausgeführt, was **weniger Berechtigungen** hat und du **kannst keinen neuen Benutzer erstellen**, um seine Berechtigungen auszunutzen.\
> Dieser Benutzer hat jedoch das **`seImpersonate`**-Privileg, sodass du die [**potato suite zur Eskalation von Berechtigungen verwenden kannst**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine rev shell also eine bessere Option, als zu versuchen, einen Benutzer zu erstellen.

Zum Zeitpunkt des Schreibens wird der **Aufgabenplanungs**-Dienst mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem ich die bösartige Dll **generiert** habe (_in meinem Fall verwendete ich eine x64 rev shell und ich erhielt eine Shell zurück, aber Defender tötete sie, weil sie von msfvenom stammte_), speichere sie im beschreibbaren Systempfad unter dem Namen **WptsExtensions.dll** und **starte** den Computer neu (oder starte den Dienst neu oder tue, was nötig ist, um den betroffenen Dienst/das Programm erneut auszuführen).

Wenn der Dienst neu gestartet wird, sollte die **dll geladen und ausgeführt** werden (du kannst den **procmon**-Trick **wiederverwenden**, um zu überprüfen, ob die **Bibliothek wie erwartet geladen wurde**).

{{#include ../../../banners/hacktricks-training.md}}
